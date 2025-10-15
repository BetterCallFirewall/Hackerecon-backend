package driven

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

var urlRegexes = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+`),
	regexp.MustCompile(`/api/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*`),
	regexp.MustCompile(`/v[0-9]+/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*`),
}

type BurpIntegration struct {
	host        string
	port        string
	enabled     bool
	client      *http.Client
	healthCheck bool
}

// NewBurpIntegration создает новую интеграцию с Burp
func NewBurpIntegration(host, port string) *BurpIntegration {
	if host == "" || port == "" {
		return &BurpIntegration{enabled: false}
	}

	integration := &BurpIntegration{
		host:    host,
		port:    port,
		enabled: true,
	}

	// Создаем HTTP клиент для работы с Burp
	integration.setupClient()

	// Проверяем доступность Burp
	integration.healthCheck = integration.checkBurpHealth()

	return integration
}

// setupClient настраивает HTTP клиент для Burp
func (bi *BurpIntegration) setupClient() {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", bi.host, bi.port))
	if err != nil {
		log.Printf("❌ Ошибка парсинга Burp URL: %v", err)
		bi.enabled = false
		return
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Для работы с Burp CA
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 0,
		}).DialContext,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	bi.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// checkBurpHealth проверяет доступность Burp Suite
func (bi *BurpIntegration) checkBurpHealth() bool {
	if !bi.enabled {
		return false
	}

	log.Printf("🔍 Проверка подключения к Burp Suite %s:%s...", bi.host, bi.port)

	conn, err := net.DialTimeout("tcp", bi.host+":"+bi.port, 5*time.Second)
	if err != nil {
		log.Printf("❌ Burp Suite недоступен: %v", err)
		log.Printf("💡 Убедитесь что Burp запущен и слушает на %s:%s", bi.host, bi.port)
		return false
	}
	conn.Close()

	// Дополнительная проверка через HTTP запрос
	testReq, _ := http.NewRequest("GET", "http://httpbin.org/get", nil)
	testReq.Header.Set("User-Agent", "SecurityProxy-HealthCheck")

	resp, err := bi.client.Do(testReq)
	if err != nil {
		log.Printf("⚠️ Burp доступен, но HTTP запросы не проходят: %v", err)
		return false
	}
	resp.Body.Close()

	log.Printf("✅ Burp Suite подключен успешно")
	return true
}

type broker interface {
	Publish(topic string, msg models.SecurityAnalysisResponse)
}

// IsHealthy возвращает состояние здоровья Burp интеграции
func (bi *BurpIntegration) IsHealthy() bool {
	return bi.enabled && bi.healthCheck
}

// GetClient возвращает HTTP клиент для запросов через Burp
func (bi *BurpIntegration) GetClient() *http.Client {
	if bi.IsHealthy() {
		return bi.client
	}
	return http.DefaultClient
}

type SecurityProxyWithGenkit struct {
	port            string
	Analyzer        *GenkitSecurityAnalyzer
	server          *http.Server
	burpIntegration *BurpIntegration
	fallbackMode    bool
}

// GenkitSecurityAnalyzer анализатор с использованием Genkit
type GenkitSecurityAnalyzer struct {
	model             string
	genkitApp         *genkit.Genkit
	mutex             sync.RWMutex
	broker            broker
	reports           []models.VulnerabilityReport
	secretPatterns    []*regexp.Regexp
	analysisFlow      *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]
	batchAnalysisFlow *genkitcore.Flow[*[]models.SecurityAnalysisRequest, *[]models.SecurityAnalysisResponse, struct{}]
}

func NewSecurityProxyWithGenkit(cfg config.LLMConfig, broker broker) (*SecurityProxyWithGenkit, error) {
	ctx := context.Background()

	// Инициализируем Genkit с плагинами
	genkitApp := genkit.Init(
		ctx,
		genkit.WithPlugins(
			&googlegenai.GoogleAI{
				APIKey: cfg.ApiKey,
			},
		),
		genkit.WithDefaultModel(cfg.Model),
	)

	analyzer, err := newGenkitSecurityAnalyzer(genkitApp, cfg.Model, broker)
	if err != nil {
		return nil, fmt.Errorf("failed to create Analyzer: %w", err)
	}

	burpIntegration := NewBurpIntegration(cfg.BurpHost, cfg.BurpPort)

	return &SecurityProxyWithGenkit{
		port:            cfg.Port,
		burpIntegration: burpIntegration,
		Analyzer:        analyzer,
		fallbackMode:    !burpIntegration.IsHealthy(),
	}, nil
}

func newGenkitSecurityAnalyzer(genkitApp *genkit.Genkit, model string, broker broker) (*GenkitSecurityAnalyzer, error) {
	analyzer := &GenkitSecurityAnalyzer{
		model:          model,
		genkitApp:      genkitApp,
		broker:         broker,
		reports:        make([]models.VulnerabilityReport, 0),
		secretPatterns: createSecretRegexPatterns(),
	}
	// Определяем основной flow для анализа безопасности
	analyzer.analysisFlow = genkit.DefineFlow(
		genkitApp, "securityAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			return analyzer.performSecurityAnalysis(ctx, req)
		},
	)

	// Определяем batch flow для массового анализа
	analyzer.batchAnalysisFlow = genkit.DefineFlow(
		genkitApp, "batchSecurityAnalysisFlow",
		func(ctx context.Context, requests *[]models.SecurityAnalysisRequest) (
			*[]models.SecurityAnalysisResponse, error,
		) {
			return analyzer.performBatchAnalysis(ctx, requests)
		},
	)

	return analyzer, nil
}

// AnalyzeHTTPTraffic анализирует HTTP трафик с помощью Genkit flows
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context, url, method string, headers map[string]string, reqBody, respBody, contentType string,
) (*models.VulnerabilityReport, error) {
	startTime := time.Now()

	// Извлекаем данные из контента
	extractedData := analyzer.extractDataFromContent(reqBody, respBody, contentType)

	// Подготавливаем запрос для анализа
	analysisReq := &models.SecurityAnalysisRequest{
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
	report := &models.VulnerabilityReport{
		ID:               generateReportID(),
		Timestamp:        time.Now(),
		SourceProxy:      "Go-Genkit",
		AnalysisResult:   *result,
		ProcessingTime:   time.Since(startTime),
		ModelUsed:        analyzer.model,
		ValidationStatus: "pending",
	}

	// Сохраняем отчет
	analyzer.mutex.Lock()
	analyzer.reports = append(analyzer.reports, *report)
	analyzer.mutex.Unlock()
	// пишем отчет в брокера
	analyzer.broker.Publish(models.LLMTopic, report.AnalysisResult)

	// Логируем критические находки
	if result.HasVulnerability && (result.RiskLevel == "high" || result.RiskLevel == "critical") {
		log.Printf(
			"🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - Risk: %s, Confidence: %.2f",
			url, result.RiskLevel, result.ConfidenceScore,
		)
		log.Printf("💡 AI Комментарий: %s", result.AIComment)

		for i, check := range result.SecurityChecklist {
			log.Printf("✅ Чек %d: %s (Приоритет: %s)", i+1, check.CheckName, check.Priority)
		}
	}

	return report, nil
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

// performSecurityAnalysis выполняет анализ безопасности с помощью Genkit
func (analyzer *GenkitSecurityAnalyzer) performSecurityAnalysis(
	ctx context.Context, req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	// Создаем детальный промпт для анализа
	prompt := analyzer.buildSecurityAnalysisPrompt(req)

	// Используем Genkit для генерации структурированного ответа
	result, _, err := genkit.GenerateData[models.SecurityAnalysisResponse](
		ctx, analyzer.genkitApp,
		ai.WithPrompt(prompt),
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

// performBatchAnalysis выполняет массовый анализ запросов
func (analyzer *GenkitSecurityAnalyzer) performBatchAnalysis(
	ctx context.Context, requests *[]models.SecurityAnalysisRequest,
) (*[]models.SecurityAnalysisResponse, error) {
	results := make([]models.SecurityAnalysisResponse, 0, len(*requests))

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

// Улучшенная обработка HTTPS туннелирования
func (ps *SecurityProxyWithGenkit) handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔒 HTTPS CONNECT: %s", r.Host)

	var destConn net.Conn
	var err error
	var routeInfo string

	if ps.burpIntegration.IsHealthy() && !ps.fallbackMode {
		// Подключение через Burp Suite
		routeInfo = fmt.Sprintf(
			"через Burp Suite (%s:%s)",
			ps.burpIntegration.host, ps.burpIntegration.port,
		)

		destConn, err = net.DialTimeout(
			"tcp",
			ps.burpIntegration.host+":"+ps.burpIntegration.port, 10*time.Second,
		)
		if err != nil {
			log.Printf("❌ Ошибка подключения к Burp: %v", err)
			// Переключаемся в fallback режим
			ps.fallbackMode = true
		} else {
			// Отправляем CONNECT запрос к Burp
			fmt.Fprintf(
				destConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
				r.Host, r.Host,
			)

			// Читаем ответ от Burp
			resp, err := http.ReadResponse(bufio.NewReader(destConn), r)
			if err != nil || resp.StatusCode != 200 {
				log.Printf(
					"❌ Burp CONNECT failed: status=%d, error=%v",
					func() int {
						if resp != nil {
							return resp.StatusCode
						} else {
							return 0
						}
					}(), err,
				)
				destConn.Close()
				ps.fallbackMode = true
				destConn = nil
			}
		}
	}

	// Fallback: прямое подключение
	if destConn == nil || ps.fallbackMode {
		routeInfo = "напрямую (Burp недоступен или в fallback режиме)"
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	log.Printf("🔗 HTTPS туннель установлен: %s → %s", r.Host, routeInfo)

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking не поддерживается", http.StatusInternalServerError)
		destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	go ps.transfer(destConn, clientConn)
	go ps.transfer(clientConn, destConn)
}

func (ps *SecurityProxyWithGenkit) createHTTPClient() *http.Client {
	if !ps.burpIntegration.enabled {
		return http.DefaultClient
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%s", ps.burpIntegration.host, ps.burpIntegration.port))
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// Исправленная обработка HTTP запросов
func (ps *SecurityProxyWithGenkit) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// Читаем тело запроса для анализа
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения тела запроса: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Создаем новый запрос для отправки (это ключевое исправление)
	outReq := createProxyRequest(req, body)

	// Выбираем клиента в зависимости от доступности Burp
	var client *http.Client
	var routeInfo string

	if ps.burpIntegration.IsHealthy() {
		client = ps.burpIntegration.GetClient()
		routeInfo = fmt.Sprintf(
			"через Burp Suite (%s:%s)",
			ps.burpIntegration.host, ps.burpIntegration.port,
		)
	} else {
		client = http.DefaultClient
		routeInfo = "напрямую (Burp недоступен)"
		if !ps.fallbackMode {
			log.Printf("⚠️ Переключение в fallback режим - Burp недоступен")
			ps.fallbackMode = true
		}
	}

	log.Printf("🌐 %s %s → %s", outReq.Method, outReq.URL.String(), routeInfo)

	// Отправляем исправленный запрос
	resp, err := client.Do(outReq)
	if err != nil {
		log.Printf("❌ Ошибка выполнения запроса: %v", err)

		// Если это ошибка Burp, пробуем напрямую
		if ps.burpIntegration.IsHealthy() && !ps.fallbackMode {
			log.Printf("🔄 Повторная попытка напрямую...")
			client = http.DefaultClient
			resp, err = client.Do(outReq)
			if err != nil {
				http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusServiceUnavailable)
				return
			}
			ps.fallbackMode = true
		} else {
			http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения ответа: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Анализируем в отдельной горутине
	go ps.analyzeTraffic(req, string(body), resp, string(respBody))

	// Возвращаем ответ клиенту
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// Новая функция для создания правильного прокси запроса
func createProxyRequest(inReq *http.Request, body []byte) *http.Request {
	// Создаем новый запрос с правильным URL
	outReq, err := http.NewRequest(inReq.Method, inReq.URL.String(), strings.NewReader(string(body)))
	if err != nil {
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return nil
	}

	outReq.RequestURI = ""

	// Копируем заголовки, исключая проблемные
	copyHeaders(outReq.Header, inReq.Header)

	// Устанавливаем правильный Host заголовок
	outReq.Host = inReq.Host

	// Копируем другие важные поля
	outReq.ContentLength = inReq.ContentLength
	outReq.TransferEncoding = inReq.TransferEncoding
	outReq.Close = inReq.Close

	return outReq
}

func copyHeaders(dst, src http.Header) {
	// Заголовки, которые нужно исключить или обработать особо
	excludeHeaders := map[string]bool{
		"Connection":          true,
		"Proxy-Connection":    true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Upgrade":             true,
	}

	for name, values := range src {
		if excludeHeaders[name] {
			continue
		}

		// Копируем остальные заголовки
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func (ps *SecurityProxyWithGenkit) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (ps *SecurityProxyWithGenkit) analyzeTraffic(
	req *http.Request, reqBody string, resp *http.Response, respBody string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	_, err := ps.Analyzer.AnalyzeHTTPTraffic(
		ctx, req.URL.String(), req.Method, headers,
		reqBody, respBody, resp.Header.Get("Content-Type"),
	)
	if err != nil {
		log.Printf("❌ Ошибка анализа %s: %v", req.URL.String(), err)
	}
}

// Периодическая проверка здоровья Burp
func (ps *SecurityProxyWithGenkit) startHealthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			if ps.fallbackMode && ps.burpIntegration.enabled {
				// Пробуем восстановить подключение к Burp
				if ps.burpIntegration.checkBurpHealth() {
					log.Printf("✅ Burp Suite восстановлен, выходим из fallback режима")
					ps.fallbackMode = false
					ps.burpIntegration.healthCheck = true
				}
			}
		}
	}()
}
