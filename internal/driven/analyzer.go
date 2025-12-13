package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/utils"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	"github.com/PuerkitoBio/goquery"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
)

// Пакет-уровневые паттерны для оптимизации hot path
// Компилируются один раз при запуске программы
var (
	// whitespaceRegex - паттерн для замены множественных пробелов на один
	whitespaceRegex = regexp.MustCompile(`\s+`)
)

// GenkitSecurityAnalyzer анализирует HTTP трафик на наличие уязвимостей безопасности
// используя LLM модели через кастомный провайдер. Поддерживает двухэтапный анализ с кэшированием
// и автоматическую генерацию гипотез об уязвимостях.
type GenkitSecurityAnalyzer struct {
	// Core components
	llmProvider llm.Provider
	WsHub       *websocket.WebsocketManager
	genkitApp   *genkit.Genkit

	// Analysis flow (возвращает SecurityAnalysisResponse или nil если анализ не нужен)
	unifiedAnalysisFlow *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]

	// Modular components
	contextManager *SiteContextManager
	dataExtractor  *DataExtractor
	hypothesisGen  *HypothesisGenerator
	requestFilter  *utils.RequestFilter
}

// NewGenkitSecurityAnalyzer создаёт анализатор с кастомным LLM провайдером
func NewGenkitSecurityAnalyzer(
	genkitApp *genkit.Genkit,
	provider llm.Provider,
	wsHub *websocket.WebsocketManager,
) (*GenkitSecurityAnalyzer, error) {
	analyzer := &GenkitSecurityAnalyzer{
		llmProvider: provider,
		WsHub:       wsHub,
		genkitApp:   genkitApp,

		// Инициализация компонентов
		contextManager: NewSiteContextManager(),
		requestFilter:  utils.NewRequestFilter(),
	}

	// Инициализация data extractor
	analyzer.dataExtractor = NewDataExtractor()

	// Определяем unified flow с orchestration двух LLM вызовов
	analyzer.unifiedAnalysisFlow = genkit.DefineFlow(
		genkitApp, "unifiedAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			// Step 1: Quick URL Analysis (traced)
			urlAnalysisReq := &models.URLAnalysisRequest{
				URL:          req.URL,
				Method:       req.Method,
				Headers:      req.Headers,
				ResponseBody: req.ResponseBody,
				ContentType:  req.ContentType,
				SiteContext:  req.SiteContext,
			}

			urlAnalysisResp, err := genkit.Run(ctx, "quick-url-analysis", func() (*models.URLAnalysisResponse, error) {
				return analyzer.llmProvider.GenerateURLAnalysis(ctx, urlAnalysisReq)
			})
			if err != nil {
				return nil, fmt.Errorf("quick URL analysis failed: %w", err)
			}

			// Step 2: Update URL pattern в контексте
			if req.SiteContext != nil {
				analyzer.updateURLPattern(req.SiteContext, req.URL, req.Method, urlAnalysisResp.URLNote)
			}

			// Step 3: Решаем, нужен ли полный анализ (решение принимает LLM)
			if !urlAnalysisResp.ShouldAnalyze {
				// Быстрый анализ достаточен - возвращаем nil
				return nil, nil
			}

			// Step 5: Extract data для полного анализа (traced)
			extractedData, err := genkit.Run(ctx, "extract-data", func() (*models.ExtractedData, error) {
				if analyzer.shouldExtractData(req.ContentType, req.ResponseBody) {
					return analyzer.dataExtractor.ExtractFromContent(
						req.RequestBody,
						req.ResponseBody,
						req.ContentType,
					), nil
				}
				return &models.ExtractedData{
					FormActions: []string{},
					Comments:    []string{},
				}, nil
			})
			if err != nil {
				return nil, err
			}

			// Step 6: Full Security Analysis (traced)
			req.ExtractedData = *extractedData

			return genkit.Run(ctx, "full-security-analysis", func() (*models.SecurityAnalysisResponse, error) {
				return analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
			})
		},
	)

	// Определяем flow для генерации гипотез с orchestration
	hypothesisFlow := genkit.DefineFlow(
		genkitApp, "hypothesisFlow",
		func(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error) {
			// LLM hypothesis generation с трейсингом
			result, err := genkit.Run(ctx, "llm-hypothesis-generation", func() (*models.HypothesisResponse, error) {
				return analyzer.llmProvider.GenerateHypothesis(ctx, req)
			})
			if err != nil {
				return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
			}

			return result, nil
		},
	)

	// Инициализация генератора гипотез
	analyzer.hypothesisGen = NewHypothesisGenerator(
		hypothesisFlow,
		wsHub,
		analyzer.contextManager,
	)

	return analyzer, nil
}

// AnalyzeHTTPTraffic анализирует HTTP трафик с unified flow
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context, req *http.Request, resp *http.Response, reqBody, respBody, contentType string,
) error {
	// 1. Умная фильтрация запросов
	shouldSkip, reason := analyzer.requestFilter.ShouldSkipRequestWithReason(req, resp, contentType)
	if shouldSkip {
		log.Printf("⚪️ Пропуск анализа %s %s: %s", req.Method, req.URL.String(), reason)
		return nil // Пропускаем анализ
	}

	log.Printf("🔍 Анализ запроса: %s %s (Content-Type: %s)", req.Method, req.URL.String(), contentType)

	// 2. Получаем/создаем контекст сайта (LLM будет использовать его для принятия решений)
	siteContext := analyzer.getOrCreateSiteContext(req.URL.Host)

	// 3. Unified анализ через один orchestration flow
	//    Quick Analysis всегда выполняется - LLM сам решает нужен ли Full Analysis
	//    на основе контекста сайта и подозрительных паттернов

	analysisReq := &models.SecurityAnalysisRequest{
		URL:          req.URL.String(),
		Method:       req.Method,
		Headers:      convertHeaders(req.Header),
		RequestBody:  analyzer.prepareContentForLLM(reqBody, req.Header.Get("Content-Type")),
		ResponseBody: analyzer.prepareContentForLLM(respBody, contentType),
		ContentType:  contentType,
		SiteContext:  siteContext,
	}

	// Запускаем unified flow (Quick → Full если LLM решит)
	securityAnalysis, err := analyzer.unifiedAnalysisFlow.Run(ctx, analysisReq)
	if err != nil {
		log.Printf("❌ Unified analysis failed: %v", err)
		return err
	}

	// 4. Отправляем результат в WebSocket
	analyzer.broadcastAnalysisResult(req, resp, securityAnalysis, reqBody, respBody)

	// 5. Логируем результат
	if securityAnalysis != nil && securityAnalysis.HasVulnerability {
		log.Printf("🔬 Полный анализ завершен для %s %s (риск: %s)",
			req.Method, req.URL.String(), securityAnalysis.RiskLevel)
	} else {
		log.Printf("✅ Анализ завершен для %s %s", req.Method, req.URL.String())
	}

	return nil
}

// broadcastAnalysisResult отправляет результат анализа в WebSocket
func (analyzer *GenkitSecurityAnalyzer) broadcastAnalysisResult(
	req *http.Request,
	resp *http.Response,
	result *models.SecurityAnalysisResponse,
	reqBody, respBody string,
) {
	// Логируем критические находки
	if result.HasVulnerability && (result.RiskLevel == "high" || result.RiskLevel == "critical") {
		log.Printf("🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - Risk: %s", req.URL.String(), result.RiskLevel)
		log.Printf("💡 AI Комментарий: %s", result.AIComment)
	}

	// Отправляем результат в WebSocket
	analyzer.WsHub.Broadcast(
		models.ReportDTO{
			Report: models.VulnerabilityReport{
				ID:             uuid.New().String(),
				AnalysisResult: *result,
			},
			RequestResponse: models.RequestResponseInfo{
				URL:         req.URL.String(),
				Method:      req.Method,
				StatusCode:  resp.StatusCode,
				ReqHeaders:  convertHeaders(req.Header),
				RespHeaders: convertHeaders(resp.Header),
				ReqBody:     llm.TruncateString(reqBody, maxContentSizeForLLM),
				RespBody:    llm.TruncateString(respBody, maxContentSizeForLLM),
			},
		},
	)
}

// getOrCreateSiteContext получает или создает контекст для хоста.
func (analyzer *GenkitSecurityAnalyzer) getOrCreateSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.GetOrCreate(host)
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
			textContent = whitespaceRegex.ReplaceAllString(textContent, " ")
			return llm.TruncateString("HTML Text Content: "+textContent, 2000) // Ограничиваем до 2000 символов
		}
	}

	// Для JavaScript и JSON просто обрезаем, т.к. их структура важна
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		return llm.TruncateString(content, 2000) // Ограничиваем до 2000 символов
	}

	// Для всего остального (например, text/plain) тоже обрезаем
	return llm.TruncateString(content, 3500)
}

// shouldExtractData проверяет, нужно ли извлекать данные (только для HTML/JS)
func (analyzer *GenkitSecurityAnalyzer) shouldExtractData(contentType, body string) bool {
	// Извлекаем только для HTML и JavaScript
	isHTML := strings.Contains(contentType, "html") || strings.Contains(body, "<html") || strings.Contains(
		body, "<!DOCTYPE",
	)
	isJS := strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json")

	return isHTML || isJS
}

// Функции для работы с URL паттернами

// updateURLPattern обновляет паттерн URL с новой заметкой
func (analyzer *GenkitSecurityAnalyzer) updateURLPattern(
	siteContext *models.SiteContext, url, method string, urlNote *models.URLNote,
) {
	analyzer.contextManager.UpdateURLPattern(siteContext, url, method, urlNote)
}

// GenerateHypothesisForHost принудительно генерирует гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GenerateHypothesisForHost(host string) (*models.HypothesisResponse, error) {
	return analyzer.hypothesisGen.GenerateForHost(host)
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.Get(host)
}
