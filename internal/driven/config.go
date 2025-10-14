package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/PuerkitoBio/goquery"
)

// SecurityAnalysisRequest входные данные для анализа безопасности
type SecurityAnalysisRequest struct {
	URL             string            `json:"url" jsonschema:"description=Target URL for analysis"`
	Method          string            `json:"method" jsonschema:"description=HTTP method (GET, POST, etc.)"`
	Headers         map[string]string `json:"headers" jsonschema:"description=HTTP headers"`
	RequestBody     string            `json:"request_body,omitempty" jsonschema:"description=Request body content"`
	ResponseBody    string            `json:"response_body,omitempty" jsonschema:"description=Response body content"`
	ContentType     string            `json:"content_type" jsonschema:"description=Response content type"`
	ExtractedData   ExtractedData     `json:"extracted_data" jsonschema:"description=Pre-extracted data from content"`
}

// ExtractedData данные, извлеченные из контента перед анализом
type ExtractedData struct {
	URLs           []string          `json:"urls" jsonschema:"description=Extracted URLs"`
	APIKeys        []ExtractedSecret `json:"api_keys" jsonschema:"description=Found API keys"`
	Secrets        []ExtractedSecret `json:"secrets" jsonschema:"description=Other secrets found"`
	JSFunctions    []JSFunction      `json:"js_functions" jsonschema:"description=JavaScript functions found"`
	FormActions    []string          `json:"form_actions" jsonschema:"description=Form action URLs"`
	Comments       []string          `json:"comments" jsonschema:"description=HTML/JS comments"`
	ExternalHosts  []string          `json:"external_hosts" jsonschema:"description=External domains referenced"`
}

// ExtractedSecret найденный секрет или чувствительные данные
type ExtractedSecret struct {
	Type       string  `json:"type" jsonschema:"description=Type of secret (API key, token, etc.)"`
	Value      string  `json:"value" jsonschema:"description=Secret value (truncated for security)"`
	Context    string  `json:"context" jsonschema:"description=Context where secret was found"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0)"`
	Location   string  `json:"location" jsonschema:"description=Where the secret was found (request/response)"`
}

// JSFunction JavaScript функция
type JSFunction struct {
	Name        string   `json:"name" jsonschema:"description=Function name"`
	Parameters  []string `json:"parameters" jsonschema:"description=Function parameters"`
	Context     string   `json:"context" jsonschema:"description=Function context/code snippet"`
	Suspicious  bool     `json:"suspicious" jsonschema:"description=Whether function is potentially suspicious"`
	Reason      string   `json:"reason,omitempty" jsonschema:"description=Reason why function is suspicious"`
}

// SecurityAnalysisResponse структурированный ответ от LLM
type SecurityAnalysisResponse struct {
	URL                string                    `json:"url" jsonschema:"description=Analyzed URL"`
	HasVulnerability   bool                     `json:"has_vulnerability" jsonschema:"description=True if vulnerability found"`
	RiskLevel          string                   `json:"risk_level" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Risk level assessment"`
	AIComment          string                   `json:"ai_comment" jsonschema:"description=AI analysis comment and explanation"`
	SecurityChecklist  []SecurityCheckItem      `json:"security_checklist" jsonschema:"description=Minimal security checklist for manual verification"`
	VulnerabilityTypes []string                 `json:"vulnerability_types" jsonschema:"description=List of detected vulnerability types"`
	ConfidenceScore    float64                  `json:"confidence_score" jsonschema:"description=Confidence in analysis (0.0-1.0)"`
	Recommendations    []string                 `json:"recommendations" jsonschema:"description=Actionable security recommendations"`
	ExtractedSecrets   []ExtractedSecret        `json:"extracted_secrets" jsonschema:"description=Found secrets and sensitive data"`
	Timestamp          time.Time                `json:"timestamp" jsonschema:"description=Analysis timestamp"`
}

// SecurityCheckItem элемент чеклиста для ручной проверки
type SecurityCheckItem struct {
	CheckName     string `json:"check_name" jsonschema:"description=Name of the security check"`
	Description   string `json:"description" jsonschema:"description=What to check manually"`
	Priority      string `json:"priority" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Check priority"`
	Instructions  string `json:"instructions" jsonschema:"description=Step-by-step instructions for manual verification"`
	ExpectedResult string `json:"expected_result" jsonschema:"description=What the secure result should look like"`
}

// SecurityProxyWithGenkit расширенный прокси с интеграцией Genkit
type SecurityProxyWithGenkit struct {
	port         string
	burpHost     string
	burpPort     string
	analyzer     *GenkitSecurityAnalyzer
	server       *http.Server
	useUpstream  bool
}

// GenkitSecurityAnalyzer анализатор с использованием Genkit
type GenkitSecurityAnalyzer struct {
	genkitApp         *genkit.Genkit
	mutex             sync.RWMutex
	reports           []VulnerabilityReport
	secretPatterns    []*regexp.Regexp
	analysisFlow      genkit.Flow[SecurityAnalysisRequest, SecurityAnalysisResponse]
	batchAnalysisFlow genkit.Flow[[]SecurityAnalysisRequest, []SecurityAnalysisResponse]
}

// VulnerabilityReport полный отчет о уязвимости
type VulnerabilityReport struct {
	ID                 string                   `json:"id" jsonschema:"description=Unique report ID"`
	Timestamp          time.Time                `json:"timestamp" jsonschema:"description=Report timestamp"`
	SourceProxy        string                   `json:"source_proxy" jsonschema:"description=Source proxy (Go/Burp)"`
	AnalysisResult     SecurityAnalysisResponse `json:"analysis_result" jsonschema:"description=LLM analysis result"`
	ProcessingTime     time.Duration            `json:"processing_time" jsonschema:"description=Time taken for analysis"`
	ModelUsed          string                   `json:"model_used" jsonschema:"description=AI model used for analysis"`
	ValidationStatus   string                   `json:"validation_status" jsonschema:"description=Manual validation status"`
}

// NewSecurityProxyWithGenkit создает новый прокси с Genkit интеграцией
func NewSecurityProxyWithGenkit(port, burpHost, burpPort, geminiAPIKey string) (*SecurityProxyWithGenkit, error) {
	ctx := context.Background()

	// Инициализируем Genkit с плагинами
	genkitApp := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{
			APIKey: geminiAPIKey,
		}),
		genkit.WithDefaultModel("googleai/gemini-2.5-flash"),
	)

	analyzer, err := NewGenkitSecurityAnalyzer(genkitApp)
	if err != nil {
		return nil, fmt.Errorf("failed to create analyzer: %w", err)
	}

	return &SecurityProxyWithGenkit{
		port:        port,
		burpHost:    burpHost,
		burpPort:    burpPort,
		analyzer:    analyzer,
		useUpstream: burpHost != "" && burpPort != "",
	}, nil
}

// NewGenkitSecurityAnalyzer создает новый анализатор с Genkit flows
func NewGenkitSecurityAnalyzer(genkitApp *genkit.Genkit) (*GenkitSecurityAnalyzer, error) {
	analyzer := &GenkitSecurityAnalyzer{
		genkitApp: genkitApp,
		reports:   make([]VulnerabilityReport, 0),
		secretPatterns: createSecretRegexPatterns(),
	}

	// Определяем основной flow для анализа безопасности
	analyzer.analysisFlow = genkit.DefineFlow(genkitApp, "securityAnalysisFlow",
		func(ctx context.Context, req *SecurityAnalysisRequest) (*SecurityAnalysisResponse, error) {
			return analyzer.performSecurityAnalysis(ctx, req)
		})

	// Определяем batch flow для массового анализа
	analyzer.batchAnalysisFlow = genkit.DefineFlow(genkitApp, "batchSecurityAnalysisFlow",
		func(ctx context.Context, requests *[]SecurityAnalysisRequest) (*[]SecurityAnalysisResponse, error) {
			return analyzer.performBatchAnalysis(ctx, requests)
		})

	return analyzer, nil
}

// performSecurityAnalysis выполняет анализ безопасности с помощью Genkit
func (analyzer *GenkitSecurityAnalyzer) performSecurityAnalysis(ctx context.Context, req *SecurityAnalysisRequest) (*SecurityAnalysisResponse, error) {
	// Создаем детальный промпт для анализа
	prompt := analyzer.buildSecurityAnalysisPrompt(req)

	// Используем Genkit для генерации структурированного ответа
	result, _, err := genkit.GenerateData[SecurityAnalysisResponse](ctx, analyzer.genkitApp,
		ai.WithPrompt(prompt),
		ai.WithConfig(&ai.GenerationCommonConfig{
			Temperature: 0.1, // Низкая температура для консистентности
		}),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to generate security analysis: %w", err)
	}

	// Устанавливаем timestamp и URL
	result.Timestamp = time.Now()
	result.URL = req.URL

	// Дополняем результат извлеченными секретами
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.APIKeys...)
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.Secrets...)

	return result, nil
}

// buildSecurityAnalysisPrompt создает детальный промпт для анализа
func (analyzer *GenkitSecurityAnalyzer) buildSecurityAnalysisPrompt(req *SecurityAnalysisRequest) string {
	extractedDataJson, _ := json.Marshal(req.ExtractedData)

	return fmt.Sprintf(`
Проведи углубленный анализ безопасности HTTP запроса и ответа. Ты - эксперт по кибербезопасности.

АНАЛИЗИРУЕМЫЕ ДАННЫЕ:
URL: %s
Метод: %s
Заголовки: %v
Тело запроса: %s
Тело ответа: %s
Content-Type: %s
Извлеченные данные: %s

ЗАДАЧИ АНАЛИЗА:

1. ОЦЕНКА УЯЗВИМОСТЕЙ:
   - Проверь на SQL инъекции в параметрах и формах
   - Найди XSS уязвимости в пользовательском вводе
   - Обнаружь CSRF проблемы (отсутствие токенов)
   - Проверь Path Traversal возможности
   - Найди Command Injection векторы
   - Оцени безопасность заголовков (CSP, HSTS, X-Frame-Options)
   - Проанализируй утечки информации

2. АНАЛИЗ ИЗВЛЕЧЕННЫХ ДАННЫХ:
   - Оцени критичность найденных API ключей и секретов
   - Проверь подозрительные JavaScript функции
   - Проанализируй безопасность найденных URL'ов
   - Проверь комментарии на утечки информации

3. СОЗДАНИЕ ЧЕКЛИСТА:
   - Создай минимальный чеклист из 3-5 критически важных проверок
   - Каждый пункт должен содержать четкие инструкции для ручной проверки
   - Укажи ожидаемый результат безопасной конфигурации

4. ОЦЕНКА РИСКОВ:
   - Определи общий уровень риска (low/medium/high/critical)
   - Укажи типы найденных уязвимостей
   - Оцени уверенность в анализе (0.0-1.0)
   - Предложи конкретные рекомендации по устранению

ВАЖНО:
- Будь точным и конкретным в рекомендациях
- Если уязвимости не найдены, укажи has_vulnerability: false
- Создавай практичные чеклисты, которые можно использовать мануально
- Учитывай контекст приложения при анализе

Ответь строго в JSON формате согласно предоставленной схеме.
`,
		req.URL,
		req.Method,
		req.Headers,
		truncateString(req.RequestBody, 500),
		truncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson))
}

// performBatchAnalysis выполняет массовый анализ запросов
func (analyzer *GenkitSecurityAnalyzer) performBatchAnalysis(ctx context.Context, requests *[]SecurityAnalysisRequest) (*[]SecurityAnalysisResponse, error) {
	results := make([]SecurityAnalysisResponse, 0, len(*requests))

	// Анализируем каждый запрос (можно распараллелить)
	for _, req := range *requests {
		result, err := analyzer.performSecurityAnalysis(ctx, &req)
		if err != nil {
			log.Printf("Error analyzing request %s: %v", req.URL, err)
			continue
		}
		results = append(results, *result)
	}

	return &results, nil
}

// AnalyzeHTTPTraffic анализирует HTTP трафик с помощью Genkit flows
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(ctx context.Context, url, method string, headers map[string]string, reqBody, respBody, contentType string) (*VulnerabilityReport, error) {
	startTime := time.Now()

	// Извлекаем данные из контента
	extractedData := analyzer.extractDataFromContent(reqBody, respBody, contentType)

	// Подготавливаем запрос для анализа
	analysisReq := &SecurityAnalysisRequest{
		URL:           url,
		Method:        method,
		Headers:       headers,
		RequestBody:   reqBody,
		ResponseBody:  respBody,
		ContentType:   contentType,
		ExtractedData: *extractedData,
	}

	// Выполняем анализ через Genkit flow
	result, err := analyzer.analysisFlow.Run(ctx, analysisReq)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	// Создаем полный отчет
	report := &VulnerabilityReport{
		ID:               generateReportID(),
		Timestamp:        time.Now(),
		SourceProxy:      "Go-Genkit",
		AnalysisResult:   *result,
		ProcessingTime:   time.Since(startTime),
		ModelUsed:        "gemini-1.5-flash",
		ValidationStatus: "pending",
	}

	// Сохраняем отчет
	analyzer.mutex.Lock()
	analyzer.reports = append(analyzer.reports, *report)
	analyzer.mutex.Unlock()

	// Логируем критические находки
	if result.HasVulnerability && (result.RiskLevel == "high" || result.RiskLevel == "critical") {
		log.Printf("🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - Risk: %s, Confidence: %.2f",
			url, result.RiskLevel, result.ConfidenceScore)
		log.Printf("💡 AI Комментарий: %s", result.AIComment)

		for i, check := range result.SecurityChecklist {
			log.Printf("✅ Чек %d: %s (Приоритет: %s)", i+1, check.CheckName, check.Priority)
		}
	}

	return report, nil
}

// extractDataFromContent извлекает данные из HTTP контента
func (analyzer *GenkitSecurityAnalyzer) extractDataFromContent(reqBody, respBody, contentType string) *ExtractedData {
	extractedData := &ExtractedData{
		URLs:          make([]string, 0),
		APIKeys:       make([]ExtractedSecret, 0),
		Secrets:       make([]ExtractedSecret, 0),
		JSFunctions:   make([]JSFunction, 0),
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
func (analyzer *GenkitSecurityAnalyzer) extractSecretsFromContent(content, location string) []ExtractedSecret {
	secrets := make([]ExtractedSecret, 0)

	for _, pattern := range analyzer.secretPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				secretType := identifySecretType(match[0])
				secretValue := strings.Trim(match[2], `"'`)

				if len(secretValue) < 8 {
					continue
				}

				secrets = append(secrets, ExtractedSecret{
					Type:       secretType,
					Value:      truncateSecret(secretValue),
					Context:    truncateString(match[0], 100),
					Confidence: calculateSecretConfidence(secretType, secretValue),
					Location:   location,
				})
			}
		}
	}

	return secrets
}

// extractJavaScriptFunctions извлекает JavaScript функции
func (analyzer *GenkitSecurityAnalyzer) extractJavaScriptFunctions(content string) []JSFunction {
	functions := make([]JSFunction, 0)

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

			functions = append(functions, JSFunction{
				Name:       funcName,
				Parameters: params,
				Context:    truncateString(match[0], 200),
				Suspicious: suspicious,
				Reason:     reason,
			})
		}
	}

	return functions
}

// extractURLsFromJS извлекает URL'ы из JavaScript
func (analyzer *GenkitSecurityAnalyzer) extractURLsFromJS(content string) []string {
	urls := make([]string, 0)

	urlRegexes := []*regexp.Regexp{
		regexp.MustCompile(`https?://[a-zA-Z0-9\-\._~:/?#[\]@!$&'()*+,;=%]+`),
		regexp.MustCompile(`/api/[a-zA-Z0-9\-\._~:/?#[\]@!$&'()*+,;=%]*`),
		regexp.MustCompile(`/v[0-9]+/[a-zA-Z0-9\-\._~:/?#[\]@!$&'()*+,;=%]*`),
	}

	for _, regex := range urlRegexes {
		matches := regex.FindAllString(content, -1)
		urls = append(urls, matches...)
	}

	return removeDuplicates(urls)
}

// HTMLData структура для данных из HTML
type HTMLData struct {
	FormActions []string
	Comments    []string
	URLs        []string
}

// extractHTMLData извлекает данные из HTML с помощью goquery
func (analyzer *GenkitSecurityAnalyzer) extractHTMLData(content string) *HTMLData {
	data := &HTMLData{
		FormActions: make([]string, 0),
		Comments:    make([]string, 0),
		URLs:        make([]string, 0),
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return data
	}

	// Извлекаем form actions
	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		if action, exists := s.Attr("action"); exists && action != "#" {
			data.FormActions = append(data.FormActions, action)
		}
	})

	// Извлекаем все ссылки
	doc.Find("a[href], script[src], img[src], iframe[src]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && href != "#" {
			data.URLs = append(data.URLs, href)
		}
		if src, exists := s.Attr("src"); exists {
			data.URLs = append(data.URLs, src)
		}
	})

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
func (analyzer *GenkitSecurityAnalyzer) GetReports() []VulnerabilityReport {
	analyzer.mutex.RLock()
	defer analyzer.mutex.RUnlock()

	reports := make([]VulnerabilityReport, len(analyzer.reports))
	copy(reports, analyzer.reports)
	return reports
}

// GetHighRiskReports возвращает только высокорисковые отчеты
func (analyzer *GenkitSecurityAnalyzer) GetHighRiskReports() []VulnerabilityReport {
	analyzer.mutex.RLock()
	defer analyzer.mutex.RUnlock()

	highRiskReports := make([]VulnerabilityReport, 0)
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
		"total_reports":        len(analyzer.reports),
		"vulnerable_requests":  0,
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

// Утилитарные функции

func createSecretRegexPatterns() []*regexp.Regexp {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)(access[_\-\s]*token[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{20,}['"]|[a-zA-Z0-9]{20,})`),
		regexp.MustCompile(`(?i)(secret[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
	}
	return patterns
}

func identifySecretType(match string) string {
	lowerMatch := strings.ToLower(match)

	typeMap := map[string]string{
		"api":      "API Key",
		"token":    "Access Token",
		"secret":   "Secret Key",
		"akia":     "AWS Access Key",
		"aiza":     "Google API Key",
		"ghp_":     "GitHub Token",
		"sk_live":  "Stripe Secret Key",
		"eyj":      "JWT Token",
	}

	for pattern, secretType := range typeMap {
		if strings.Contains(lowerMatch, pattern) {
			return secretType
		}
	}

	return "Unknown Secret"
}

func calculateSecretConfidence(secretType, value string) float64 {
	confidence := 0.5

	if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "AIza") {
		confidence = 0.95
	} else if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "sk_live_") {
		confidence = 0.95
	} else if len(value) > 32 && (strings.Contains(secretType, "API") || strings.Contains(secretType, "Secret")) {
		confidence = 0.8
	} else if len(value) > 16 {
		confidence = 0.7
	}

	return confidence
}

func isSuspiciousFunction(funcName, context string) (bool, string) {
	suspiciousFunctions := map[string]string{
		"eval":           "Выполнение произвольного кода",
		"settimeout":     "Потенциальное выполнение кода",
		"setinterval":    "Потенциальное выполнение кода",
		"function":       "Динамическое создание функций",
		"innerhtml":      "Возможность XSS",
		"outerhtml":      "Возможность XSS",
	}

	lowerName := strings.ToLower(funcName)
	if reason, exists := suspiciousFunctions[lowerName]; exists {
		return true, reason
	}

	// Проверяем контекст
	suspiciousPatterns := []string{"crypto", "encrypt", "decrypt", "hash", "password", "token", "secret"}
	lowerContext := strings.ToLower(context)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerContext, pattern) {
			return true, fmt.Sprintf("Содержит подозрительный паттерн: %s", pattern)
		}
	}

	return false, ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func truncateSecret(secret string) string {
	if len(secret) <= 10 {
		return secret
	}
	return secret[:6] + "***" + secret[len(secret)-4:]
}

func generateReportID() string {
	return fmt.Sprintf("VR-%d", time.Now().UnixNano())
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

// HTTP прокси функции (упрощенная версия для демонстрации)
func (ps *SecurityProxyWithGenkit) Start() error {
	ps.server = &http.Server{
		Addr: ":" + ps.port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				ps.handleTunneling(w, r)
			} else {
				ps.handleHTTP(w, r)
			}
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("🚀 Security Proxy запущен на порту %s", ps.port)
	if ps.useUpstream {
		log.Printf("📡 Upstream Burp Suite: %s:%s", ps.burpHost, ps.burpPort)
	}
	log.Printf("🤖 Genkit AI анализ: Включен (Gemini)")

	return ps.server.ListenAndServe()
}

func (ps *SecurityProxyWithGenkit) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// Читаем тело запроса
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Отправляем запрос (через Burp или напрямую)
	client := ps.createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, _ := io.ReadAll(resp.Body)

	// Анализируем в отдельной горутине
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		headers := make(map[string]string)
		for k, v := range req.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		_, err := ps.analyzer.AnalyzeHTTPTraffic(ctx, req.URL.String(), req.Method, headers,
			string(body), string(respBody), resp.Header.Get("Content-Type"))
		if err != nil {
			log.Printf("❌ Ошибка анализа %s: %v", req.URL.String(), err)
		}
	}()

	// Возвращаем ответ
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (ps *SecurityProxyWithGenkit) createHTTPClient() *http.Client {
	if !ps.useUpstream {
		return http.DefaultClient
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%s", ps.burpHost, ps.burpPort))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func (ps *SecurityProxyWithGenkit) handleTunneling(w http.ResponseWriter, r *http.Request) {
	// Простая реализация HTTPS туннелирования
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking не поддерживается", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go ps.transfer(destConn, clientConn)
	go ps.transfer(clientConn, destConn)
}

func (ps *SecurityProxyWithGenkit) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// main функция
func main() {
	geminiAPIKey := os.Getenv("GEMINI_API_KEY")
	if geminiAPIKey == "" {
		log.Fatal("❌ Необходимо установить переменную окружения GEMINI_API_KEY")
	}

	burpHost := os.Getenv("BURP_HOST")
	burpPort := os.Getenv("BURP_PORT")

	// Создаем прокси с Genkit интеграцией
	proxy, err := NewSecurityProxyWithGenkit(proxyPort, burpHost, burpPort, geminiAPIKey)
	if err != nil {
		log.Fatalf("❌ Ошибка создания прокси: %v", err)
	}


	log.Println("🔒 Security Proxy с Genkit AI запущен")
	log.Println("🌐 Веб-панель: http://localhost:8081")
	log.Printf("🔧 Настройте браузер на прокси: localhost:%s", proxyPort)

	log.Fatal(proxy.Start())
}

func getGenkitDashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Security Proxy с Genkit AI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333; min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 { color: white; font-size: 3rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header p { color: rgba(255,255,255,0.9); font-size: 1.2rem; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { 
            background: rgba(255,255,255,0.95); padding: 1.5rem; border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); backdrop-filter: blur(10px);
            text-align: center; transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 2.5rem; font-weight: bold; margin-bottom: 0.5rem; }
        .stat-label { color: #666; text-transform: uppercase; font-size: 0.9rem; letter-spacing: 1px; }

        .critical { color: #e74c3c; } .high { color: #e67e22; }
        .medium { color: #f39c12; } .low { color: #27ae60; }
        .info { color: #3498db; } .success { color: #2ecc71; }

        .reports-section { 
            background: rgba(255,255,255,0.95); border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); backdrop-filter: blur(10px);
            overflow: hidden; margin-bottom: 2rem;
        }
        .section-header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 1.5rem; font-size: 1.3rem; font-weight: 600;
        }

        .report-item { padding: 1.5rem; border-bottom: 1px solid #e9ecef; }
        .report-item:hover { background: #f8f9fa; }
        .report-item:last-child { border-bottom: none; }

        .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .report-url { font-weight: 600; color: #2c3e50; flex: 1; }
        .risk-badge { 
            padding: 0.5rem 1rem; border-radius: 25px; font-size: 0.8rem;
            font-weight: 600; text-transform: uppercase; margin-left: 1rem;
        }
        .risk-critical { background: #e74c3c; color: white; }
        .risk-high { background: #e67e22; color: white; }
        .risk-medium { background: #f39c12; color: white; }
        .risk-low { background: #27ae60; color: white; }

        .ai-comment { 
            background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;
            border-left: 4px solid #3498db; font-style: italic;
        }

        .checklist { margin: 1rem 0; }
        .checklist-item { 
            background: white; padding: 1rem; margin: 0.5rem 0; border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .checklist-title { font-weight: 600; color: #2c3e50; margin-bottom: 0.5rem; }
        .checklist-desc { color: #666; font-size: 0.9rem; }

        .secrets-found { 
            background: #fff3cd; border: 1px solid #ffeaa7; padding: 1rem;
            border-radius: 8px; margin: 1rem 0;
        }
        .secret-item { 
            background: #ffe8e8; padding: 0.5rem; margin: 0.3rem 0;
            border-radius: 4px; font-family: monospace; font-size: 0.8rem;
        }

        .refresh-btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 1rem 2rem; border-radius: 25px;
            cursor: pointer; font-size: 1rem; transition: transform 0.2s ease;
        }
        .refresh-btn:hover { transform: scale(1.05); }

        .loading { text-align: center; padding: 3rem; color: #666; }
        .no-data { text-align: center; padding: 3rem; color: #999; }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header h1 { font-size: 2rem; }
            .stats-grid { grid-template-columns: 1fr; }
            .report-header { flex-direction: column; align-items: flex-start; }
            .risk-badge { margin: 0.5rem 0 0 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Proxy Dashboard</h1>
            <p>Анализ уязвимостей веб-трафика с помощью Genkit AI</p>
        </div>

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-number info" id="totalReports">0</div>
                <div class="stat-label">Всего анализов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical" id="vulnerableRequests">0</div>
                <div class="stat-label">С уязвимостями</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical" id="criticalRisks">0</div>
                <div class="stat-label">Критические</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high" id="highRisks">0</div>
                <div class="stat-label">Высокий риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium" id="mediumRisks">0</div>
                <div class="stat-label">Средний риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number success" id="secretsFound">0</div>
                <div class="stat-label">Секретов найдено</div>
            </div>
            <div class="stat-card">
                <div class="stat-number info" id="avgConfidence">0.0</div>
                <div class="stat-label">Средняя уверенность</div>
            </div>
        </div>

        <div class="reports-section">
            <div class="section-header">
                🤖 Отчеты анализа уязвимостей с AI комментариями
                <button class="refresh-btn" onclick="loadData()" style="float: right;">🔄 Обновить</button>
            </div>
            <div id="reportsContainer">
                <div class="loading">Загрузка отчетов...</div>
            </div>
        </div>
    </div>

    <script>
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                document.getElementById('totalReports').textContent = data.total_reports || 0;
                document.getElementById('vulnerableRequests').textContent = data.vulnerable_requests || 0;
                document.getElementById('criticalRisks').textContent = data.critical_risks || 0;
                document.getElementById('highRisks').textContent = data.high_risks || 0;
                document.getElementById('mediumRisks').textContent = data.medium_risks || 0;
                document.getElementById('secretsFound').textContent = data.secrets_found || 0;
                document.getElementById('avgConfidence').textContent = (data.avg_confidence || 0).toFixed(2);
            } catch (error) {
                console.error('Ошибка загрузки статистики:', error);
            }
        }

        async function loadReports() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();

                const container = document.getElementById('reportsContainer');

                if (!reports || reports.length === 0) {
                    container.innerHTML = '<div class="no-data">📭 Пока нет отчетов для отображения</div>';
                    return;
                }

                let html = '';
                reports.slice(-10).reverse().forEach(report => {
                    const result = report.analysis_result;
                    const riskClass = getRiskClass(result.risk_level);
                    const riskLabel = getRiskLabel(result.risk_level);
                    const timestamp = new Date(report.timestamp).toLocaleString('ru-RU');

                    html += \`
	<div class="report-item">
	<div class="report-header">
	<span class="report-url">\${result.url}</span>
	<span class="risk-badge risk-\${riskClass}">\${riskLabel}</span>
	</div>

	<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0;">
	<div><strong>Время:</strong> \${timestamp}</div>
	<div><strong>Модель:</strong> \${report.model_used}</div>
	<div><strong>Время анализа:</strong> \${(report.processing_time / 1000000).toFixed(0)}ms</div>
	<div><strong>Уверенность:</strong> \${(result.confidence_score * 100).toFixed(1)}%</div>
	</div>

	\${result.has_vulnerability ? \`
                                <div class="ai-comment">
                                    <strong>🤖 AI Анализ:</strong> \${result.ai_comment}
                                </div>

                                \${result.security_checklist && result.security_checklist.length > 0 ? \`
	<div class="checklist">
	<strong>✅ Чеклист для ручной проверки:</strong>
	\${result.security_checklist.map(check => \`
                                            <div class="checklist-item">
                                                <div class="checklist-title">\${check.check_name} (\${check.priority})</div>
                                                <div class="checklist-desc">\${check.description}</div>
                                                <div class="checklist-desc"><em>Инструкция:</em> \${check.instructions}</div>
                                            </div>
                                        \`).join('')}
	</div>
	\` : ''}

                                \${result.extracted_secrets && result.extracted_secrets.length > 0 ? \`
	<div class="secrets-found">
	<strong>🔐 Найдены секреты:</strong>
	\${result.extracted_secrets.map(secret => \`
                                            <div class="secret-item">
                                                <strong>\${secret.type}</strong>: \${secret.value} 
                                                <em>(уверенность: \${(secret.confidence * 100).toFixed(0)}%)</em>
                                            </div>
                                        \`).join('')}
	</div>
	\` : ''}

                                \${result.vulnerability_types && result.vulnerability_types.length > 0 ? \`
	<div><strong>🚨 Типы уязвимостей:</strong> \${result.vulnerability_types.join(', ')}</div>
	\` : ''}

                                \${result.recommendations && result.recommendations.length > 0 ? \`
	<div style="margin-top: 1rem;"><strong>💡 Рекомендации:</strong>
	<ul>\${result.recommendations.map(rec => \`<li>\${rec}</li>\`).join('')}</ul>
	</div>
	\` : ''}
                            \` : \`
                                <div style="color: #27ae60; font-weight: 600;">✅ Уязвимости не обнаружены</div>
                                <div class="ai-comment"><strong>🤖 AI Анализ:</strong> \${result.ai_comment}</div>
                            \`}
	</div>
	\`;
                });

                container.innerHTML = html;
            } catch (error) {
                console.error('Ошибка загрузки отчетов:', error);
                document.getElementById('reportsContainer').innerHTML = 
                    '<div class="no-data">❌ Ошибка загрузки данных</div>';
            }
        }

        function getRiskClass(level) {
            const riskMap = { 'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low' };
            return riskMap[level] || 'low';
        }

        function getRiskLabel(level) {
            const labelMap = { 'critical': 'Критический', 'high': 'Высокий', 'medium': 'Средний', 'low': 'Низкий' };
            return labelMap[level] || 'Неизвестный';
        }

        function loadData() {
            loadStats();
            loadReports();
        }

        // Автоматическое обновление каждые 10 секунд
        setInterval(loadData, 10000);

        // Первоначальная загрузка
        loadData();
    </script>
</body>
</html>`
}