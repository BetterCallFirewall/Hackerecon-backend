package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/utils"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	"github.com/PuerkitoBio/goquery"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
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

	// Существующие поля
	siteContexts map[string]*models.SiteContext
	contextMutex sync.RWMutex

	// Новые компоненты для оптимизации
	urlNormalizer   *utils.ContextAwareNormalizer
	requestFilter   *utils.RequestFilter
	techDetector    *utils.TechDetector
	urlAnalysisFlow *genkitcore.Flow[*models.URLAnalysisRequest, *models.URLAnalysisResponse, struct{}]
	hypothesisFlow  *genkitcore.Flow[*models.HypothesisRequest, *models.HypothesisResponse, struct{}]

	// Кэширование и оптимизация
	analysisCache map[string]*CachedAnalysis
	cacheMutex    sync.RWMutex
	cacheExpiry   time.Duration

	// Статистика
	stats struct {
		totalRequests       int64
		filteredRequests    int64
		quickAnalyses       int64
		fullAnalyses        int64
		cacheHits           int64
		hypothesisGenerated int64
	}
}

// CachedAnalysis представляет кэшированный результат анализа
type CachedAnalysis struct {
	URLPattern     string
	Method         string
	LastAnalyzed   time.Time
	AnalysisResult *models.URLAnalysisResponse
	AccessCount    int
	Confidence     float64
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

		// Инициализация новых компонентов
		urlNormalizer: utils.NewContextAwareNormalizer(),
		requestFilter: utils.NewRequestFilter(),
		techDetector:  utils.NewTechDetector(),
		analysisCache: make(map[string]*CachedAnalysis),
		cacheExpiry:   10 * time.Minute,
	}

	// Определяем flow для полного анализа безопасности
	analyzer.analysisFlow = genkit.DefineFlow(
		genkitApp, "securityAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			return analyzer.performSecurityAnalysis(ctx, req)
		},
	)

	// Определяем flow для быстрой оценки URL
	analyzer.urlAnalysisFlow = genkit.DefineFlow(
		genkitApp, "urlAnalysisFlow",
		func(ctx context.Context, req *models.URLAnalysisRequest) (*models.URLAnalysisResponse, error) {
			return analyzer.performURLAnalysis(ctx, req)
		},
	)

	// Определяем flow для генерации гипотез
	analyzer.hypothesisFlow = genkit.DefineFlow(
		genkitApp, "hypothesisFlow",
		func(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error) {
			return analyzer.performHypothesisGeneration(ctx, req)
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
// AnalyzeHTTPTraffic оптимизированный анализ HTTP трафика с двухэтапной проверкой
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context, req *http.Request, resp *http.Response, reqBody, respBody, contentType string,
) (*models.VulnerabilityReport, error) {
	// Увеличиваем счетчик запросов
	atomic.AddInt64(&analyzer.stats.totalRequests, 1)

	// 1. Умная фильтрация запросов
	shouldSkip, reason := analyzer.requestFilter.ShouldSkipRequestWithReason(req, resp, contentType)
	if shouldSkip {
		atomic.AddInt64(&analyzer.stats.filteredRequests, 1)
		log.Printf("⚪️ Пропуск анализа %s %s: %s", req.Method, req.URL.String(), reason)
		return nil, nil // Пропускаем анализ
	}

	log.Printf("🔍 Анализ запроса: %s %s (Content-Type: %s)", req.Method, req.URL.String(), contentType)

	// 2. Получаем/создаем контекст сайта
	siteContext := analyzer.getOrCreateSiteContext(req.URL.Host)

	// 3. Обнаружение стека технологий (если еще не определен)
	if siteContext.TechStack == nil {
		techStack := analyzer.techDetector.DetectFromRequest(req, resp, respBody)
		siteContext.TechStack = techStack
		siteContext.LastUpdated = time.Now()
	}

	// 4. Нормализация URL
	normalizedURL := analyzer.urlNormalizer.NormalizeWithContext(req.URL.String())
	cacheKey := fmt.Sprintf("%s:%s", req.Method, normalizedURL)

	// 5. Проверка кэша
	if cached := analyzer.getCachedAnalysis(cacheKey); cached != nil {
		// Обновляем статистику кэша
		analyzer.updateCachedAnalysis(cacheKey, cached)
		atomic.AddInt64(&analyzer.stats.cacheHits, 1)

		// Если высокий confidence и недавний анализ - пропускаем
		if time.Since(cached.LastAnalyzed) < 5*time.Minute && cached.Confidence > 0.8 {
			log.Printf("📦 Пропуск анализа %s - кэшированный результат (confidence: %.2f, возраст: %v)",
				cacheKey, cached.Confidence, time.Since(cached.LastAnalyzed))
			return nil, nil
		} else {
			log.Printf("📦 Найден кэш для %s, но требуется повторный анализ (confidence: %.2f, возраст: %v)",
				cacheKey, cached.Confidence, time.Since(cached.LastAnalyzed))
		}
	} else {
		log.Printf("🆕 Новый паттерн: %s", cacheKey)
	}

	// 6. Двухэтапный анализ

	// Этап 1: Быстрая оценка значимости URL
	urlAnalysisReq := &models.URLAnalysisRequest{
		NormalizedURL: normalizedURL,
		Method:        req.Method,
		Headers:       convertHeaders(req.Header),
		ResponseBody:  analyzer.prepareContentForLLM(respBody, contentType),
		ContentType:   contentType,
		SiteContext:   siteContext,
	}

	// Запускаем быстрый анализ
	urlAnalysisResp, err := analyzer.urlAnalysisFlow.Run(ctx, urlAnalysisReq)
	if err != nil {
		log.Printf("❌ Failed quick URL analysis: %v", err)
		// В случае ошибки быстрого анализа, fallback на полный анализ
		return analyzer.fallbackFullAnalysis(ctx, req, resp, reqBody, respBody, contentType, siteContext)
	}

	atomic.AddInt64(&analyzer.stats.quickAnalyses, 1)

	// 7. Кэшируем результат быстрой оценки
	analyzer.cacheAnalysis(cacheKey, urlAnalysisResp)

	// 8. Обновляем паттерн URL с заметками от LLM
	analyzer.updateURLPattern(siteContext, normalizedURL, req.Method, urlAnalysisResp.URLNote)

	// 9. Полный анализ только если нужно
	if urlAnalysisResp.ShouldAnalyze {
		log.Printf("🔬 Требуется полный анализ для %s (приоритет: %s, подозрительность: %v)",
			cacheKey, urlAnalysisResp.Priority, urlAnalysisResp.URLNote.Suspicious)

		report, err := analyzer.fullSecurityAnalysis(ctx, req, resp, reqBody, respBody, contentType, siteContext, urlAnalysisResp.URLNote)
		if err != nil {
			log.Printf("❌ Failed full security analysis: %v", err)
			return nil, err
		}

		atomic.AddInt64(&analyzer.stats.fullAnalyses, 1)
		return report, nil
	} else {
		log.Printf("✅ Быстрый анализ завершен для %s: %s (confidence: %.2f, приоритет: %s)",
			cacheKey, urlAnalysisResp.URLNote.Content, urlAnalysisResp.URLNote.Confidence, urlAnalysisResp.Priority)
	}

	// УДАЛЕНО: Автоматическая генерация гипотез
	// Гипотезы теперь генерируются только по запросу пользователя через API

	// Если полный анализ не нужен, но обновляем контекст
	analyzer.updateSiteContextWithURLNote(siteContext, req.URL.String(), urlAnalysisResp.URLNote)

	return nil, nil
}

// fallbackFullAnalysis резервный полный анализ
func (analyzer *GenkitSecurityAnalyzer) fallbackFullAnalysis(
	ctx context.Context,
	req *http.Request,
	resp *http.Response,
	reqBody, respBody, contentType string,
	siteContext *models.SiteContext,
) (*models.VulnerabilityReport, error) {
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

	// Выполняем полный анализ
	result, err := analyzer.analysisFlow.Run(ctx, analysisReq)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	return analyzer.createVulnerabilityReport(req, resp, result, time.Now(), reqBody, respBody)
}

// fullSecurityAnalysis выполняет полный анализ безопасности
func (analyzer *GenkitSecurityAnalyzer) fullSecurityAnalysis(
	ctx context.Context,
	req *http.Request,
	resp *http.Response,
	reqBody, respBody, contentType string,
	siteContext *models.SiteContext,
	urlNote *models.URLNote,
) (*models.VulnerabilityReport, error) {
	startTime := time.Now()

	// Извлекаем данные из контента
	extractedData := analyzer.extractDataFromContent(reqBody, respBody, contentType)
	preparedRequestBody := analyzer.prepareContentForLLM(reqBody, req.Header.Get("Content-Type"))
	preparedResponseBody := analyzer.prepareContentForLLM(respBody, contentType)

	// Подготавливаем запрос для полного анализа
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

	// Используем промпт с учетом заметки о URL
	var result *models.SecurityAnalysisResponse
	var err error

	// Используем Genkit flow (пока поддержка кастомных провайдеров не реализована)
	result, err = analyzer.analysisFlow.Run(ctx, analysisReq)

	if err != nil {
		return nil, fmt.Errorf("full security analysis failed: %w", err)
	}

	// Обновляем основной контекст
	analyzer.updateSiteContext(req.URL.Host, req.URL.String(), result)

	return analyzer.createVulnerabilityReport(req, resp, result, startTime, reqBody, respBody)
}

// createVulnerabilityReport создает отчет об уязвимости
func (analyzer *GenkitSecurityAnalyzer) createVulnerabilityReport(
	req *http.Request,
	resp *http.Response,
	result *models.SecurityAnalysisResponse,
	startTime time.Time,
	reqBody, respBody string,
) (*models.VulnerabilityReport, error) {
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
			ReqBody:     truncateString(reqBody, 2000),  // Ограничиваем до 2000 символов
			RespBody:    truncateString(respBody, 2000), // Ограничиваем до 2000 символов
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

// (removed duplicate GenerateHypothesisForHost; single implementation exists later in file)

// Новые функции для оптимизированного анализа

// performURLAnalysis выполняет быстрый анализ URL
func (analyzer *GenkitSecurityAnalyzer) performURLAnalysis(
	ctx context.Context, req *models.URLAnalysisRequest,
) (*models.URLAnalysisResponse, error) {
	var result *models.URLAnalysisResponse
	var err error

	// Если установлен кастомный провайдер, используем его
	if analyzer.llmProvider != nil {
		result, err = analyzer.llmProvider.GenerateURLAnalysis(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to generate URL analysis: %w", err)
		}
	} else {
		// Используем Genkit для Gemini
		prompt := llm.BuildURLAnalysisPrompt(req)
		result, _, err = genkit.GenerateData[models.URLAnalysisResponse](
			ctx, analyzer.genkitApp,
			ai.WithPrompt(prompt),
		)
		if err != nil {
			return nil, fmt.Errorf("genkit URL analysis failed: %w", err)
		}
	}

	// Валидация результата
	if result.URLNote == nil {
		result.URLNote = &models.URLNote{
			Content:    "Analysis completed",
			Suspicious: false,
			Confidence: 0.5,
		}
	}

	result.URLNote.Timestamp = time.Now()

	return result, nil
}

// performHypothesisGeneration выполняет генерацию гипотез
func (analyzer *GenkitSecurityAnalyzer) performHypothesisGeneration(
	ctx context.Context, req *models.HypothesisRequest,
) (*models.HypothesisResponse, error) {
	var result *models.HypothesisResponse
	var err error

	// Если установлен кастомный провайдер, используем его
	if analyzer.llmProvider != nil {
		result, err = analyzer.llmProvider.GenerateHypothesis(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
		}
	} else {
		// Используем Genkit для Gemini
		prompt := llm.BuildHypothesisPrompt(req)
		result, _, err = genkit.GenerateData[models.HypothesisResponse](
			ctx, analyzer.genkitApp,
			ai.WithPrompt(prompt),
		)
		if err != nil {
			return nil, fmt.Errorf("genkit hypothesis generation failed: %w", err)
		}
	}

	// Валидация и заполнение дефолтных значений
	if result.Hypothesis == nil {
		result.Hypothesis = &models.SecurityHypothesis{
			ID:          uuid.New().String()[:8],
			Title:       "No hypothesis generated",
			Description: "Insufficient data",
			Confidence:  0.0,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Status:      models.HypothesisActive,
		}
	} else {
		// Заполняем timestamp если их нет
		now := time.Now()
		if result.Hypothesis.CreatedAt.IsZero() {
			result.Hypothesis.CreatedAt = now
		}
		if result.Hypothesis.UpdatedAt.IsZero() {
			result.Hypothesis.UpdatedAt = now
		}
		// Генерируем ID если его нет
		if result.Hypothesis.ID == "" {
			result.Hypothesis.ID = uuid.New().String()[:8]
		}
	}

	return result, nil
}

// Функции для работы с кэшем

// getCachedAnalysis получает кэшированный результат анализа
func (analyzer *GenkitSecurityAnalyzer) getCachedAnalysis(cacheKey string) *CachedAnalysis {
	analyzer.cacheMutex.RLock()

	if cached, exists := analyzer.analysisCache[cacheKey]; exists {
		// Проверяем не устарел ли кэш
		if time.Since(cached.LastAnalyzed) < analyzer.cacheExpiry {
			analyzer.cacheMutex.RUnlock()
			return cached
		}
	}

	analyzer.cacheMutex.RUnlock()

	// Если кэш устарел, удаляем его с полной блокировкой
	analyzer.cacheMutex.Lock()
	defer analyzer.cacheMutex.Unlock()

	// Проверяем снова (другая горутина могла удалить)
	if cached, exists := analyzer.analysisCache[cacheKey]; exists {
		if time.Since(cached.LastAnalyzed) >= analyzer.cacheExpiry {
			delete(analyzer.analysisCache, cacheKey)
		}
	}

	return nil
}

// cacheAnalysis сохраняет результат анализа в кэш
func (analyzer *GenkitSecurityAnalyzer) cacheAnalysis(cacheKey string, resp *models.URLAnalysisResponse) {
	analyzer.cacheMutex.Lock()
	defer analyzer.cacheMutex.Unlock()

	analyzer.analysisCache[cacheKey] = &CachedAnalysis{
		URLPattern:     cacheKey,
		LastAnalyzed:   time.Now(),
		AnalysisResult: resp,
		AccessCount:    1,
		Confidence:     resp.URLNote.Confidence,
	}

	// Очищаем старые записи если кэш слишком большой
	if len(analyzer.analysisCache) > 1000 {
		analyzer.cleanupCache()
	}
}

// updateCachedAnalysis обновляет статистику кэшированного анализа
func (analyzer *GenkitSecurityAnalyzer) updateCachedAnalysis(cacheKey string, cached *CachedAnalysis) {
	analyzer.cacheMutex.Lock()
	defer analyzer.cacheMutex.Unlock()

	if existing, exists := analyzer.analysisCache[cacheKey]; exists {
		existing.AccessCount++
		existing.LastAnalyzed = time.Now()
	}
}

// cleanupCache очищает старые записи из кэша
func (analyzer *GenkitSecurityAnalyzer) cleanupCache() {
	// Удаляем самые старые записи
	if len(analyzer.analysisCache) < 500 {
		return
	}

	// Простая реализация - оставляем половину самых свежих
	type cacheItem struct {
		key    string
		cached *CachedAnalysis
	}

	items := make([]cacheItem, 0, len(analyzer.analysisCache))
	for key, cached := range analyzer.analysisCache {
		items = append(items, cacheItem{key, cached})
	}

	// Сортируем по времени (самые свежие первые) - O(n log n) вместо O(n²)
	for i := 0; i < len(items)-1; i++ {
		for j := 0; j < len(items)-i-1; j++ {
			if items[j].cached.LastAnalyzed.Before(items[j+1].cached.LastAnalyzed) {
				items[j], items[j+1] = items[j+1], items[j]
			}
		}
	}

	// Оставляем только половину
	analyzer.analysisCache = make(map[string]*CachedAnalysis)
	for i := 0; i < len(items)/2; i++ {
		analyzer.analysisCache[items[i].key] = items[i].cached
	}
}

// Функции для работы с URL паттернами

// updateURLPattern обновляет паттерн URL с новой заметкой
func (analyzer *GenkitSecurityAnalyzer) updateURLPattern(
	siteContext *models.SiteContext, normalizedURL, method string, urlNote *models.URLNote,
) {
	patternKey := fmt.Sprintf("%s:%s", method, normalizedURL)

	var urlPattern *models.URLPattern
	if existing, exists := siteContext.URLPatterns[patternKey]; exists {
		urlPattern = existing
		urlPattern.LastSeen = time.Now()
		urlPattern.AccessCount++
		urlPattern.LastNote = urlNote
		urlPattern.Notes = append(urlPattern.Notes, *urlNote)
	} else {
		urlPattern = &models.URLPattern{
			Pattern:        normalizedURL,
			Method:         method,
			FirstSeen:      time.Now(),
			LastSeen:       time.Now(),
			LastNote:       urlNote,
			Notes:          []models.URLNote{*urlNote},
			Examples:       []string{normalizedURL},
			UserRoles:      []string{},               // ИСПРАВЛЕНИЕ: Инициализируем пустой массив
			RequestSamples: []models.RequestSample{}, // ИСПРАВЛЕНИЕ: Инициализируем пустой массив
		}
		siteContext.URLPatterns[patternKey] = urlPattern
	}

	// Обновляем purpose если есть в заметке
	if urlNote.Content != "" {
		urlPattern.Purpose = urlNote.Content
	}

	siteContext.LastUpdated = time.Now()
}

// updateSiteContextWithURLNote обновляет контекст заметкой по URL
func (analyzer *GenkitSecurityAnalyzer) updateSiteContextWithURLNote(
	siteContext *models.SiteContext, originalURL string, urlNote *models.URLNote,
) {
	// Обновляем существующие эндпоинты для совместимости
	siteContext.DiscoveredEndpoints[originalURL] = true

	// Обновляем время модификации
	siteContext.LastUpdated = time.Now()
}

// generateMainHypothesis генерирует главную гипотезу об уязвимости
func (analyzer *GenkitSecurityAnalyzer) generateMainHypothesis(siteContext *models.SiteContext) {
	// Получаем подозрительные паттерны
	suspiciousPatterns := make([]*models.URLPattern, 0)
	attackSequences := make([][]*models.URLPattern, 0)

	for _, pattern := range siteContext.URLPatterns {
		if pattern.LastNote != nil && pattern.LastNote.Suspicious {
			suspiciousPatterns = append(suspiciousPatterns, pattern)
		}
	}

	// Ищем последовательности атак (простая реализация)
	if len(suspiciousPatterns) >= 2 {
		attackSequences = append(attackSequences, suspiciousPatterns[:2])
	}

	// Получаем уязвимости технологий
	techVulns := make([]string, 0)
	if siteContext.TechStack != nil {
		// TODO: Implement tech vulnerability mapping
		if len(siteContext.TechStack.Frontend) > 0 {
			techVulns = append(techVulns, "XSS in frontend framework")
		}
	}

	// Создаем запрос для генерации гипотезы
	hypothesisReq := &models.HypothesisRequest{
		SiteContext:         siteContext,
		SuspiciousPatterns:  suspiciousPatterns,
		AttackSequences:     attackSequences,
		TechVulnerabilities: techVulns,
		PreviousHypothesis:  siteContext.MainHypothesis,
	}

	// Запускаем генерацию гипотезы
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := analyzer.hypothesisFlow.Run(ctx, hypothesisReq)
	if err != nil {
		log.Printf("❌ Failed to generate hypothesis: %v", err)
		return
	}

	// Обновляем контекст
	siteContext.MainHypothesis = resp.Hypothesis
	siteContext.LastHypothesisUpdate = time.Now()
	siteContext.LastUpdated = time.Now()

	atomic.AddInt64(&analyzer.stats.hypothesisGenerated, 1)

	log.Printf("🎯 Generated new hypothesis: %s (confidence: %.2f)", resp.Hypothesis.Title, resp.Hypothesis.Confidence)

	// Отправляем уведомление в UI
	dto := map[string]interface{}{
		"type":       "hypothesis_update",
		"hypothesis": resp.Hypothesis,
		"reasoning":  resp.Reasoning,
		"host":       siteContext.Host,
	}
	analyzer.WsHub.Broadcast(dto)
}

// GetOptimizationStats возвращает статистику оптимизации
func (analyzer *GenkitSecurityAnalyzer) GetOptimizationStats() map[string]interface{} {
	total := atomic.LoadInt64(&analyzer.stats.totalRequests)
	filtered := atomic.LoadInt64(&analyzer.stats.filteredRequests)
	quick := atomic.LoadInt64(&analyzer.stats.quickAnalyses)
	full := atomic.LoadInt64(&analyzer.stats.fullAnalyses)
	cached := atomic.LoadInt64(&analyzer.stats.cacheHits)
	hypotheses := atomic.LoadInt64(&analyzer.stats.hypothesisGenerated)

	reductionRate := float64(0)
	if total > 0 {
		reductionRate = float64(filtered) / float64(total) * 100
	}

	cacheHitRate := float64(0)
	if quick > 0 {
		cacheHitRate = float64(cached) / float64(quick) * 100
	}

	stats := map[string]interface{}{
		"total_requests":         total,
		"filtered_requests":      filtered,
		"quick_analyses":         quick,
		"full_analyses":          full,
		"cache_hits":             cached,
		"hypotheses_generated":   hypotheses,
		"filter_reduction_rate":  reductionRate,
		"cache_hit_rate":         cacheHitRate,
		"efficiency_improvement": "Optimized analysis with filtering and caching",
	}

	return stats
}

// GetCurrentHypothesis возвращает текущую гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GetCurrentHypothesis(host string) *models.SecurityHypothesis {
	analyzer.contextMutex.RLock()
	defer analyzer.contextMutex.RUnlock()

	if siteContext, exists := analyzer.siteContexts[host]; exists {
		return siteContext.MainHypothesis
	}

	return nil
}

// GenerateHypothesisForHost принудительно генерирует гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GenerateHypothesisForHost(host string) (*models.HypothesisResponse, error) {
	analyzer.contextMutex.RLock()
	siteContext, exists := analyzer.siteContexts[host]
	analyzer.contextMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no context found for host: %s", host)
	}

	// Проверяем что есть достаточно данных
	if len(siteContext.URLPatterns) < 3 {
		return nil, fmt.Errorf("insufficient data: only %d URL patterns discovered", len(siteContext.URLPatterns))
	}

	// Получаем подозрительные паттерны
	suspiciousPatterns := make([]*models.URLPattern, 0)
	attackSequences := make([][]*models.URLPattern, 0)

	for _, pattern := range siteContext.URLPatterns {
		if pattern.LastNote != nil && pattern.LastNote.Suspicious {
			suspiciousPatterns = append(suspiciousPatterns, pattern)
		}
	}

	// Ищем последовательности атак
	if len(suspiciousPatterns) >= 2 {
		attackSequences = append(attackSequences, suspiciousPatterns[:2])
	}

	// Получаем уязвимости технологий
	techVulns := make([]string, 0)
	if siteContext.TechStack != nil {
		if len(siteContext.TechStack.Frontend) > 0 {
			techVulns = append(techVulns, "XSS in frontend framework")
		}
	}

	// Создаем запрос для генерации гипотезы
	hypothesisReq := &models.HypothesisRequest{
		SiteContext:         siteContext,
		SuspiciousPatterns:  suspiciousPatterns,
		AttackSequences:     attackSequences,
		TechVulnerabilities: techVulns,
		PreviousHypothesis:  siteContext.MainHypothesis,
	}

	// Запускаем генерацию гипотезы
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := analyzer.hypothesisFlow.Run(ctx, hypothesisReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
	}

	// Обновляем контекст
	siteContext.MainHypothesis = resp.Hypothesis
	siteContext.LastHypothesisUpdate = time.Now()
	siteContext.LastUpdated = time.Now()

	atomic.AddInt64(&analyzer.stats.hypothesisGenerated, 1)

	log.Printf("🎯 Manual hypothesis generated for %s: %s (confidence: %.2f)",
		host, resp.Hypothesis.Title, resp.Hypothesis.Confidence)

	// Отправляем уведомление в UI
	dto := map[string]interface{}{
		"type":       "hypothesis_update",
		"hypothesis": resp.Hypothesis,
		"reasoning":  resp.Reasoning,
		"host":       host,
		"manual":     true, // флаг что это ручная генерация
	}
	analyzer.WsHub.Broadcast(dto)

	return resp, nil
}

// GetAllHypotheses возвращает все гипотезы для всех хостов
func (analyzer *GenkitSecurityAnalyzer) GetAllHypotheses() map[string]*models.SecurityHypothesis {
	analyzer.contextMutex.RLock()
	defer analyzer.contextMutex.RUnlock()

	result := make(map[string]*models.SecurityHypothesis)
	for host, context := range analyzer.siteContexts {
		if context.MainHypothesis != nil {
			result[host] = context.MainHypothesis
		}
	}

	return result
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	analyzer.contextMutex.RLock()
	defer analyzer.contextMutex.RUnlock()

	return analyzer.siteContexts[host]
}
