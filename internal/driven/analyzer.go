package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	"github.com/PuerkitoBio/goquery"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

var urlRegexes = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+`),
	regexp.MustCompile(`/api/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*`),
	regexp.MustCompile(`/v[0-9]+/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*`),
}

// GenkitSecurityAnalyzer анализатор с использованием Genkit
type GenkitSecurityAnalyzer struct {
	model          string
	llmProvider    llm.Provider // Опциональный провайдер (если используется generic)
	WsHub          *websocket.WebsocketManager
	genkitApp      *genkit.Genkit
	mutex          sync.RWMutex
	reports        []models.VulnerabilityReport
	secretPatterns []*regexp.Regexp
	analysisFlow   *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]

	siteContexts map[string]*models.SiteContext
	contextMutex sync.RWMutex
}

// newGenkitSecurityAnalyzer создаёт анализатор с Gemini (без кастомного провайдера)
func newGenkitSecurityAnalyzer(genkitApp *genkit.Genkit, model string, wsHub *websocket.WebsocketManager) (
	*GenkitSecurityAnalyzer, error,
) {
	return newSecurityAnalyzerWithProvider(genkitApp, model, nil, wsHub)
}

// newSecurityAnalyzerWithProvider создаёт анализатор с опциональным кастомным LLM провайдером
// Если provider == nil, используется Gemini через Genkit
func newSecurityAnalyzerWithProvider(
	genkitApp *genkit.Genkit,
	model string,
	provider llm.Provider,
	wsHub *websocket.WebsocketManager,
) (*GenkitSecurityAnalyzer, error) {
	analyzer := &GenkitSecurityAnalyzer{
		model:          model,
		llmProvider:    provider,
		WsHub:          wsHub,
		genkitApp:      genkitApp,
		reports:        make([]models.VulnerabilityReport, 0),
		secretPatterns: createSecretRegexPatterns(),
		siteContexts:   make(map[string]*models.SiteContext),
	}

	// Определяем flow для анализа безопасности
	analyzer.analysisFlow = genkit.DefineFlow(
		genkitApp, "securityAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			return analyzer.performSecurityAnalysis(ctx, req)
		},
	)

	return analyzer, nil
}

// performSecurityAnalysis выполняет анализ безопасности с помощью Genkit или провайдера
func (analyzer *GenkitSecurityAnalyzer) performSecurityAnalysis(
	ctx context.Context, req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	var result *models.SecurityAnalysisResponse
	var err error

	// Если установлен кастомный провайдер, используем его
	if analyzer.llmProvider != nil {
		result, err = analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to generate security analysis: %w", err)
		}
	} else {
		// Иначе используем Genkit (Gemini)
		prompt := analyzer.buildSecurityAnalysisPrompt(req)

		result, _, err = genkit.GenerateData[models.SecurityAnalysisResponse](
			ctx, analyzer.genkitApp,
			ai.WithPrompt(prompt),
		)

		if err != nil {
			return nil, fmt.Errorf("failed to generate security analysis: %w", err)
		}
	}

	// Устанавливаем timestamp и URL
	result.Timestamp = time.Now()

	// Нормализуем risk_level к lowercase (на случай если LLM вернул "Low" вместо "low")
	result.RiskLevel = strings.ToLower(strings.TrimSpace(result.RiskLevel))

	// Валидируем risk_level
	validRiskLevels := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validRiskLevels[result.RiskLevel] {
		log.Printf("⚠️ Невалидный risk_level '%s', устанавливаем 'low'", result.RiskLevel)
		result.RiskLevel = "low"
	}

	// Дополняем результат извлеченными секретами
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.APIKeys...)
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.Secrets...)

	return result, nil
}

// AnalyzeHTTPTraffic анализирует HTTP трафик с помощью Genkit flows
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context, req *http.Request, resp *http.Response, reqBody, respBody, contentType string,
) (*models.VulnerabilityReport, error) {
	startTime := time.Now()

	siteContext := analyzer.getOrCreateSiteContext(req.URL.Host)

	// Извлекаем данные из контента
	extractedData := analyzer.extractDataFromContent(reqBody, respBody, contentType)
	preparedRequestBody := analyzer.prepareContentForLLM(reqBody, req.Header.Get("Content-Type"))
	preparedResponseBody := analyzer.prepareContentForLLM(respBody, contentType)

	// Подготавливаем запрос для анализа
	analysisReq := &models.SecurityAnalysisRequest{
		URL:           req.URL.String(),
		Method:        req.Method,
		Headers:       convertHeaders(req.Header),
		RequestBody:   preparedRequestBody,
		ResponseBody:  preparedResponseBody,
		ContentType:   contentType,
		ExtractedData: *extractedData,
		SiteContext:   siteContext,
	}

	// Выполняем анализ через Genkit flow
	result, err := analyzer.analysisFlow.Run(ctx, analysisReq)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	analyzer.updateSiteContext(req.URL.Host, req.URL.String(), result)

	// Создаем полный отчет
	report := &models.VulnerabilityReport{
		ID:             generateReportID(),
		Timestamp:      time.Now(),
		AnalysisResult: *result,
		ProcessingTime: time.Since(startTime),
	}

	// Сохраняем отчет
	analyzer.mutex.Lock()
	analyzer.reports = append(analyzer.reports, *report)
	analyzer.mutex.Unlock()

	// Логируем критические находки
	if result.HasVulnerability && (result.RiskLevel == "high" || result.RiskLevel == "critical") {
		log.Printf(
			"🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - Risk: %s",
			req.URL.String(), result.RiskLevel,
		)
		log.Printf("💡 AI Комментарий: %s", result.AIComment)

		// Логируем чеклист для ручной проверки
		if len(result.SecurityChecklist) > 0 {
			log.Printf("📋 Варианты проверки уязвимости (%d):", len(result.SecurityChecklist))
			for i, check := range result.SecurityChecklist {
				log.Printf("   ┣━ Тест %d: %s", i+1, check.Action)
				log.Printf("   ┃  Что проверить: %s", check.Description)
				log.Printf("   ┗━ Ожидается: %s", check.Expected)
				if i < len(result.SecurityChecklist)-1 {
					log.Println("   ┃")
				}
			}
		}

	}

	dto := models.ReportDTO{
		Report: *report,
		RequestResponse: models.RequestResponseInfo{
			URL:         req.URL.String(),
			Method:      req.Method,
			StatusCode:  resp.StatusCode,
			ReqHeaders:  convertHeaders(req.Header),
			RespHeaders: convertHeaders(resp.Header),
			ReqBody:     truncateString(reqBody, 500),
			RespBody:    truncateString(respBody, 500),
		},
	}

	analyzer.WsHub.Broadcast(dto)

	return report, nil
}

func (analyzer *GenkitSecurityAnalyzer) getOrCreateSiteContext(host string) *models.SiteContext {
	analyzer.contextMutex.Lock()
	defer analyzer.contextMutex.Unlock()

	if context, exists := analyzer.siteContexts[host]; exists {
		return context
	}

	newContext := models.NewSiteContext(host)
	analyzer.siteContexts[host] = newContext
	return newContext
}

func (analyzer *GenkitSecurityAnalyzer) prepareContentForLLM(content, contentType string) string {
	if len(content) == 0 {
		return "empty"
	}

	// Для HTML извлекаем только текст без тегов и разметки, чтобы модель поняла суть страницы
	if strings.Contains(contentType, "html") {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
		if err == nil {
			// Удаляем скрипты и стили, чтобы они не загромождали контекст
			doc.Find("script, style").Remove()
			// Возвращаем только текст из body
			textContent := doc.Find("body").Text()
			// Заменяем множественные пробелы и переносы строк на один пробел
			re := regexp.MustCompile(`\s+`)
			textContent = re.ReplaceAllString(textContent, " ")
			return truncateString("HTML Text Content: "+textContent, 2000) // Ограничиваем до 2000 символов
		}
	}

	// Для JavaScript и JSON просто обрезаем, т.к. их структура важна
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		return truncateString(content, 2000) // Ограничиваем до 2000 символов
	}

	// Для всего остального (например, text/plain) тоже обрезаем
	return truncateString(content, 1000)
}

// updateSiteContext обновляет контекст на основе ответа от LLM
func (analyzer *GenkitSecurityAnalyzer) updateSiteContext(
	host string, url string,
	llmResponse *models.SecurityAnalysisResponse,
) {
	analyzer.contextMutex.Lock()
	defer analyzer.contextMutex.Unlock()

	context, exists := analyzer.siteContexts[host]
	if !exists {
		return // Должен уже существовать
	}

	// Обновляем роли
	if llmResponse.IdentifiedUserRole != "" {
		context.UserRoles[llmResponse.IdentifiedUserRole] = true
	}

	// ИЗМЕНЕНО: Обновляем объекты данных, итерируясь по срезу
	if len(llmResponse.IdentifiedDataObjects) > 0 {
		for _, dataObject := range llmResponse.IdentifiedDataObjects {
			name := dataObject.Name
			fields := dataObject.Fields
			if name == "" || len(fields) == 0 {
				continue
			}

			// Логика слияния полей остается той же
			existingFields := make(map[string]bool)
			for _, field := range context.DataObjects[name] {
				existingFields[field] = true
			}
			for _, newField := range fields {
				if !existingFields[newField] {
					context.DataObjects[name] = append(context.DataObjects[name], newField)
				}
			}
		}
	}

	// Обновляем эндпоинты
	context.DiscoveredEndpoints[url] = true
	context.LastUpdated = time.Now()
}

// extractDataFromContent извлекает данные из HTTP контента
func (analyzer *GenkitSecurityAnalyzer) extractDataFromContent(reqBody, respBody, contentType string) *models.ExtractedData {
	extractedData := &models.ExtractedData{
		URLs:          make([]string, 0),
		APIKeys:       make([]models.ExtractedSecret, 0),
		Secrets:       make([]models.ExtractedSecret, 0),
		JSFunctions:   make([]models.JSFunction, 0),
		FormActions:   make([]string, 0),
		Comments:      make([]string, 0),
		ExternalHosts: make([]string, 0),
	}

	contents := []string{reqBody, respBody}
	locations := []string{"request", "response"}

	for i, content := range contents {
		if content == "" {
			continue
		}

		location := locations[i]

		// Извлекаем секреты
		secrets := analyzer.extractSecretsFromContent(content, location)
		extractedData.APIKeys = append(extractedData.APIKeys, secrets...)

		// Анализируем JavaScript контент
		if strings.Contains(contentType, "javascript") ||
			strings.Contains(content, "function") ||
			strings.Contains(content, "const ") ||
			strings.Contains(content, "var ") {

			jsFunctions := analyzer.extractJavaScriptFunctions(content)
			extractedData.JSFunctions = append(extractedData.JSFunctions, jsFunctions...)

			urls := analyzer.extractURLsFromJS(content)
			extractedData.URLs = append(extractedData.URLs, urls...)
		}

		// Анализируем HTML контент
		if strings.Contains(contentType, "html") ||
			strings.Contains(content, "<html") ||
			strings.Contains(content, "<!DOCTYPE") {

			htmlData := analyzer.extractHTMLData(content)
			extractedData.FormActions = append(extractedData.FormActions, htmlData.FormActions...)
			extractedData.Comments = append(extractedData.Comments, htmlData.Comments...)
			extractedData.URLs = append(extractedData.URLs, htmlData.URLs...)
		}
	}

	return extractedData
}

// extractSecretsFromContent извлекает секреты с помощью regex
func (analyzer *GenkitSecurityAnalyzer) extractSecretsFromContent(content, location string) []models.ExtractedSecret {
	secrets := make([]models.ExtractedSecret, 0)

	for _, pattern := range analyzer.secretPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				secretType := identifySecretType(match[0])
				secretValue := strings.Trim(match[2], `"'`)

				if len(secretValue) < 8 {
					continue
				}

				secrets = append(
					secrets, models.ExtractedSecret{
						Type:       secretType,
						Value:      truncateSecret(secretValue),
						Context:    truncateString(match[0], 100),
						Confidence: calculateSecretConfidence(secretType, secretValue),
						Location:   location,
					},
				)
			}
		}
	}

	return secrets
}

// extractJavaScriptFunctions извлекает JavaScript функции
func (analyzer *GenkitSecurityAnalyzer) extractJavaScriptFunctions(content string) []models.JSFunction {
	functions := make([]models.JSFunction, 0)

	funcRegex := regexp.MustCompile(`function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)`)
	matches := funcRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			funcName := match[1]
			params := strings.Split(strings.TrimSpace(match[2]), ",")

			// Очищаем параметры
			for i, param := range params {
				params[i] = strings.TrimSpace(param)
			}

			suspicious, reason := isSuspiciousFunction(funcName, content)

			functions = append(
				functions, models.JSFunction{
					Name:       funcName,
					Parameters: params,
					Context:    truncateString(match[0], 200),
					Suspicious: suspicious,
					Reason:     reason,
				},
			)
		}
	}

	return functions
}

// extractURLsFromJS извлекает URL'ы из JavaScript
func (analyzer *GenkitSecurityAnalyzer) extractURLsFromJS(content string) []string {
	urls := make([]string, 0)

	for _, regex := range urlRegexes {
		matches := regex.FindAllString(content, -1)
		urls = append(urls, matches...)
	}

	return removeDuplicates(urls)
}

// extractHTMLData извлекает данные из HTML с помощью goquery
func (analyzer *GenkitSecurityAnalyzer) extractHTMLData(content string) *models.HTMLData {
	data := &models.HTMLData{
		FormActions: make([]string, 0),
		Comments:    make([]string, 0),
		URLs:        make([]string, 0),
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return data
	}

	// Извлекаем form actions
	doc.Find("form[action]").Each(
		func(i int, s *goquery.Selection) {
			if action, exists := s.Attr("action"); exists && action != "#" {
				data.FormActions = append(data.FormActions, action)
			}
		},
	)

	// Извлекаем все ссылки
	doc.Find("a[href], script[src], img[src], iframe[src]").Each(
		func(i int, s *goquery.Selection) {
			if href, exists := s.Attr("href"); exists && href != "#" {
				data.URLs = append(data.URLs, href)
			}
			if src, exists := s.Attr("src"); exists {
				data.URLs = append(data.URLs, src)
			}
		},
	)

	// Извлекаем комментарии
	commentRegex := regexp.MustCompile(`<!--(.*?)-->`)
	comments := commentRegex.FindAllStringSubmatch(content, -1)
	for _, match := range comments {
		if len(match) >= 2 {
			comment := strings.TrimSpace(match[1])
			if len(comment) > 5 && !strings.HasPrefix(comment, "<!") {
				data.Comments = append(data.Comments, truncateString(comment, 200))
			}
		}
	}

	return data
}

// GetReports возвращает все отчеты
func (analyzer *GenkitSecurityAnalyzer) GetReports() []models.VulnerabilityReport {
	analyzer.mutex.RLock()
	defer analyzer.mutex.RUnlock()

	reports := make([]models.VulnerabilityReport, len(analyzer.reports))
	copy(reports, analyzer.reports)
	return reports
}

// GetHighRiskReports возвращает только высокорисковые отчеты
func (analyzer *GenkitSecurityAnalyzer) GetHighRiskReports() []models.VulnerabilityReport {
	analyzer.mutex.RLock()
	defer analyzer.mutex.RUnlock()

	highRiskReports := make([]models.VulnerabilityReport, 0)
	for _, report := range analyzer.reports {
		if report.AnalysisResult.HasVulnerability &&
			(report.AnalysisResult.RiskLevel == "high" || report.AnalysisResult.RiskLevel == "critical") {
			highRiskReports = append(highRiskReports, report)
		}
	}
	return highRiskReports
}

// GetSummaryStats возвращает статистику анализа
func (analyzer *GenkitSecurityAnalyzer) GetSummaryStats() map[string]interface{} {
	analyzer.mutex.RLock()
	defer analyzer.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_reports":       len(analyzer.reports),
		"vulnerable_requests": 0,
		"critical_risks":      0,
		"high_risks":          0,
		"medium_risks":        0,
		"low_risks":           0,
		"secrets_found":       0,
		"avg_confidence":      0.0,
		"vulnerability_types": make(map[string]int),
	}

	totalConfidence := 0.0
	totalSecrets := 0

	for _, report := range analyzer.reports {
		if report.AnalysisResult.HasVulnerability {
			stats["vulnerable_requests"] = stats["vulnerable_requests"].(int) + 1

			switch report.AnalysisResult.RiskLevel {
			case "critical":
				stats["critical_risks"] = stats["critical_risks"].(int) + 1
			case "high":
				stats["high_risks"] = stats["high_risks"].(int) + 1
			case "medium":
				stats["medium_risks"] = stats["medium_risks"].(int) + 1
			case "low":
				stats["low_risks"] = stats["low_risks"].(int) + 1
			}

			for _, vulnType := range report.AnalysisResult.VulnerabilityTypes {
				count := stats["vulnerability_types"].(map[string]int)[vulnType]
				stats["vulnerability_types"].(map[string]int)[vulnType] = count + 1
			}
		}

		totalConfidence += report.AnalysisResult.ConfidenceScore
		totalSecrets += len(report.AnalysisResult.ExtractedSecrets)
	}

	stats["secrets_found"] = totalSecrets
	if len(analyzer.reports) > 0 {
		stats["avg_confidence"] = totalConfidence / float64(len(analyzer.reports))
	}

	return stats
}
