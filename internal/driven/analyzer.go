package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/utils"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	"github.com/PuerkitoBio/goquery"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
)

// GenkitSecurityAnalyzer анализирует HTTP трафик на наличие уязвимостей безопасности
// используя LLM модели через кастомный провайдер. Поддерживает двухэтапный анализ с кэшированием
// и автоматическую генерацию гипотез об уязвимостях.
type GenkitSecurityAnalyzer struct {
	// Core components
	llmProvider llm.Provider
	WsHub       *websocket.WebsocketManager
	genkitApp   *genkit.Genkit

	// Analysis flows
	analysisFlow    *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]
	urlAnalysisFlow *genkitcore.Flow[*models.URLAnalysisRequest, *models.URLAnalysisResponse, struct{}]

	// Modular components
	cache          *AnalysisCache
	contextManager *SiteContextManager
	dataExtractor  *DataExtractor
	hypothesisGen  *HypothesisGenerator
	urlNormalizer  *utils.ContextAwareNormalizer
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
		urlNormalizer:  utils.NewContextAwareNormalizer(),
		requestFilter:  utils.NewRequestFilter(),
		cache:          NewAnalysisCache(),
	}

	// Инициализация data extractor с паттернами секретов
	secretPatterns := createSecretRegexPatterns()
	analyzer.dataExtractor = NewDataExtractor(secretPatterns)

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
	hypothesisFlow := genkit.DefineFlow(
		genkitApp, "hypothesisFlow",
		func(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error) {
			return analyzer.performHypothesisGeneration(ctx, req)
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

// performSecurityAnalysis выполняет анализ безопасности с помощью провайдера
func (analyzer *GenkitSecurityAnalyzer) performSecurityAnalysis(
	ctx context.Context, req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	result, err := analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate security analysis: %w", err)
	}

	// Финализируем результат
	analyzer.finalizeAnalysisResult(result, req)

	return result, nil
}

// finalizeAnalysisResult финализирует результат анализа безопасности
func (analyzer *GenkitSecurityAnalyzer) finalizeAnalysisResult(
	result *models.SecurityAnalysisResponse,
	req *models.SecurityAnalysisRequest,
) {
	result.Timestamp = time.Now()
	analyzer.normalizeAndValidateRiskLevel(result)
	analyzer.appendExtractedSecrets(result, req)
}

// normalizeAndValidateRiskLevel нормализует и валидирует уровень риска
func (analyzer *GenkitSecurityAnalyzer) normalizeAndValidateRiskLevel(result *models.SecurityAnalysisResponse) {
	result.RiskLevel = strings.ToLower(strings.TrimSpace(result.RiskLevel))

	validRiskLevels := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}

	if !validRiskLevels[result.RiskLevel] {
		log.Printf("⚠️ Невалидный risk_level '%s', устанавливаем 'low'", result.RiskLevel)
		result.RiskLevel = "low"
	}
}

// appendExtractedSecrets добавляет извлеченные секреты к результату
func (analyzer *GenkitSecurityAnalyzer) appendExtractedSecrets(
	result *models.SecurityAnalysisResponse,
	req *models.SecurityAnalysisRequest,
) {
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.APIKeys...)
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.Secrets...)
}

// AnalyzeHTTPTraffic оптимизированный анализ HTTP трафика с двухэтапной проверкой
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

	// 2. Получаем/создаем контекст сайта
	siteContext := analyzer.getOrCreateSiteContext(req.URL.Host)

	// 3. Нормализация URL
	normalizedURL := analyzer.urlNormalizer.NormalizeWithContext(req.URL.String())
	cacheKey := fmt.Sprintf("%s:%s", req.Method, normalizedURL)

	// 5. Проверка кэша
	if shouldSkipBasedOnCache := analyzer.checkCacheAndDecide(cacheKey); shouldSkipBasedOnCache {
		return nil
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
		return err
	}

	// 7. Кэшируем результат быстрой оценки
	analyzer.cacheAnalysis(cacheKey, urlAnalysisResp)

	// 8. Обновляем паттерн URL с заметками от LLM (если контекст существует)
	if siteContext != nil {
		analyzer.updateURLPattern(siteContext, normalizedURL, req.Method, urlAnalysisResp.URLNote)
	}

	// 9. Полный анализ только если нужно
	if urlAnalysisResp.ShouldAnalyze {
		log.Printf(
			"🔬 Требуется полный анализ для %s (приоритет: %s, подозрительность: %v)",
			cacheKey, urlAnalysisResp.Priority, urlAnalysisResp.URLNote.Suspicious,
		)

		err := analyzer.fullSecurityAnalysis(
			ctx, req, resp, reqBody, respBody, contentType, siteContext, urlAnalysisResp.URLNote,
		)
		if err != nil {
			log.Printf("❌ Failed full security analysis: %v", err)
			return err
		}

		return nil
	}

	log.Printf(
		"✅ Быстрый анализ завершен для %s: %s (confidence: %.2f, приоритет: %s)",
		cacheKey, urlAnalysisResp.URLNote.Content, urlAnalysisResp.URLNote.Confidence, urlAnalysisResp.Priority,
	)

	return nil
}

// fullSecurityAnalysis выполняет полный анализ безопасности
func (analyzer *GenkitSecurityAnalyzer) fullSecurityAnalysis(
	ctx context.Context,
	req *http.Request,
	resp *http.Response,
	reqBody, respBody, contentType string,
	siteContext *models.SiteContext,
	urlNote *models.URLNote,
) error {
	// Ленивое извлечение данных - только для HTML/JS контента
	var extractedData *models.ExtractedData
	if analyzer.shouldExtractData(contentType, respBody) {
		extractedData = analyzer.extractDataFromContent(reqBody, respBody, contentType)
	} else {
		// Пустые данные для non-HTML/JS контента
		extractedData = &models.ExtractedData{
			URLs:          []string{},
			APIKeys:       []models.ExtractedSecret{},
			Secrets:       []models.ExtractedSecret{},
			JSFunctions:   []models.JSFunction{},
			FormActions:   []string{},
			Comments:      []string{},
			ExternalHosts: []string{},
		}
	}

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

	// Выполняем анализ через flow
	result, err := analyzer.analysisFlow.Run(ctx, analysisReq)
	if err != nil {
		return fmt.Errorf("full security analysis failed: %w", err)
	}

	// Отправляем результат в WebSocket
	analyzer.broadcastAnalysisResult(req, resp, result, reqBody, respBody)

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
				Timestamp:      time.Now(),
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
			re := regexp.MustCompile(`\s+`)
			textContent = re.ReplaceAllString(textContent, " ")
			return llm.TruncateString("HTML Text Content: "+textContent, 2000) // Ограничиваем до 2000 символов
		}
	}

	// Для JavaScript и JSON просто обрезаем, т.к. их структура важна
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		return llm.TruncateString(content, 2000) // Ограничиваем до 2000 символов
	}

	// Для всего остального (например, text/plain) тоже обрезаем
	return llm.TruncateString(content, 1000)
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

// extractDataFromContent извлекает данные из HTTP контента
func (analyzer *GenkitSecurityAnalyzer) extractDataFromContent(reqBody, respBody, contentType string) *models.ExtractedData {
	return analyzer.dataExtractor.ExtractFromContent(reqBody, respBody, contentType)
}

// Новые функции для оптимизированного анализа

// performURLAnalysis выполняет быстрый анализ URL
func (analyzer *GenkitSecurityAnalyzer) performURLAnalysis(
	ctx context.Context, req *models.URLAnalysisRequest,
) (*models.URLAnalysisResponse, error) {
	result, err := analyzer.llmProvider.GenerateURLAnalysis(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate URL analysis: %w", err)
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
	result, err := analyzer.llmProvider.GenerateHypothesis(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
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

// checkCacheAndDecide проверяет кэш и решает, нужно ли пропустить анализ
func (analyzer *GenkitSecurityAnalyzer) checkCacheAndDecide(cacheKey string) bool {
	return analyzer.cache.CheckAndDecide(cacheKey)
}

// cacheAnalysis сохраняет результат анализа в кэш
func (analyzer *GenkitSecurityAnalyzer) cacheAnalysis(cacheKey string, resp *models.URLAnalysisResponse) {
	analyzer.cache.Set(cacheKey, resp)
}

// Функции для работы с URL паттернами

// updateURLPattern обновляет паттерн URL с новой заметкой
func (analyzer *GenkitSecurityAnalyzer) updateURLPattern(
	siteContext *models.SiteContext, normalizedURL, method string, urlNote *models.URLNote,
) {
	analyzer.contextManager.UpdateURLPattern(siteContext, normalizedURL, method, urlNote)
}

// GetCurrentHypothesis возвращает текущую гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GetCurrentHypothesis(host string) *models.SecurityHypothesis {
	return analyzer.hypothesisGen.GetCurrent(host)
}

// GenerateHypothesisForHost принудительно генерирует гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GenerateHypothesisForHost(host string) (*models.HypothesisResponse, error) {
	return analyzer.hypothesisGen.GenerateForHost(host)
}

// GetAllHypotheses возвращает все гипотезы для всех хостов
func (analyzer *GenkitSecurityAnalyzer) GetAllHypotheses() map[string]*models.SecurityHypothesis {
	return analyzer.hypothesisGen.GetAll()
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.Get(host)
}
