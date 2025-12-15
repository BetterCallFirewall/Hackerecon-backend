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
	"github.com/BetterCallFirewall/Hackerecon/internal/verification"
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

	// Verification flow
	verificationFlow *genkitcore.Flow[*models.VerificationRequest, *models.VerificationResponse, struct{}]

	// Modular components
	contextManager *SiteContextManager
	dataExtractor  *DataExtractor
	hypothesisGen  *HypothesisGenerator
	requestFilter  *utils.RequestFilter

	// Verification client
	verificationClient *verification.VerificationClient
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

			urlAnalysisResp, err := genkit.Run(
				ctx, "quick-url-analysis", func() (*models.URLAnalysisResponse, error) {
					return analyzer.llmProvider.GenerateURLAnalysis(ctx, urlAnalysisReq)
				},
			)
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
			extractedData, err := genkit.Run(
				ctx, "extract-data", func() (models.ExtractedData, error) {
					if analyzer.shouldExtractData(req.ContentType, req.ResponseBody) {
						return analyzer.dataExtractor.ExtractFromContent(
							req.RequestBody,
							req.ResponseBody,
							req.ContentType,
						), nil
					}
					return models.ExtractedData{
						FormActions: []string{},
						Comments:    []string{},
					}, nil
				},
			)
			if err != nil {
				return nil, err
			}

			// Step 6: Full Security Analysis (traced)
			req.ExtractedData = extractedData

			return genkit.Run(
				ctx, "full-security-analysis", func() (*models.SecurityAnalysisResponse, error) {
					return analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
				},
			)
		},
	)

	// Определяем flow для генерации гипотез с orchestration
	hypothesisFlow := genkit.DefineFlow(
		genkitApp, "hypothesisFlow",
		func(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error) {
			// LLM hypothesis generation с трейсингом
			result, err := genkit.Run(
				ctx, "llm-hypothesis-generation", func() (*models.HypothesisResponse, error) {
					return analyzer.llmProvider.GenerateHypothesis(ctx, req)
				},
			)
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

	// Initialize verification client
	analyzer.verificationClient = verification.NewVerificationClient(verification.VerificationClientConfig{
		Timeout:    30 * time.Second,
		MaxRetries: 2,
	})

	// Initialize verification flow
	analyzer.verificationFlow = genkit.DefineFlow(
		analyzer.genkitApp,
		"verificationFlow",
		func(ctx context.Context, req *models.VerificationRequest) (*models.VerificationResponse, error) {
			return analyzer.verifyHypothesis(ctx, req)
		},
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
		ExtractedData: models.ExtractedData{
			FormActions: []string{},
			Comments:    []string{},
		},
		SiteContext: siteContext,
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
		log.Printf(
			"🔬 Полный анализ завершен для %s %s (риск: %s)",
			req.Method, req.URL.String(), securityAnalysis.RiskLevel,
		)
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

	// Convert request info
	requestInfo := models.RequestResponseInfo{
		URL:         req.URL.String(),
		Method:      req.Method,
		StatusCode:  resp.StatusCode,
		ReqHeaders:  convertHeaders(req.Header),
		RespHeaders: convertHeaders(resp.Header),
		ReqBody:     llm.TruncateString(reqBody, maxContentSizeForLLM),
		RespBody:    llm.TruncateString(respBody, maxContentSizeForLLM),
	}

	// Broadcast initial result immediately (fast response)
	reportID := uuid.New().String()
	analyzer.WsHub.Broadcast(models.ReportDTO{
		Report: models.VulnerabilityReport{
			ID:             reportID,
			Timestamp:      time.Now(),
			AnalysisResult: *result,
		},
		RequestResponse:    requestInfo,
		VerificationStatus: "in_progress", // NEW: track verification progress
	})

	// Start background verification if there are checklist items
	if result.HasVulnerability && len(result.SecurityChecklist) > 0 {
		go analyzer.verifyChecklistInBackground(reportID, result, requestInfo)
	}
}

// verifyChecklistInBackground performs async verification of security checklist items
func (analyzer *GenkitSecurityAnalyzer) verifyChecklistInBackground(
	reportID string,
	result *models.SecurityAnalysisResponse,
	requestInfo models.RequestResponseInfo,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log.Printf("🔬 Starting background verification for %d checklist items", len(result.SecurityChecklist))

	// Verify each checklist item
	verificationResults := make([]*models.VerificationResponse, len(result.SecurityChecklist))

	for i, item := range result.SecurityChecklist {
		// Ensure hypothesis is set for verification
		if item.Hypothesis == "" {
			item.Hypothesis = item.Action + " - " + item.Description
		}

		// Create verification request
		verificationReq := &models.VerificationRequest{
			OriginalRequest: requestInfo,
			ChecklistItem:   item,
			MaxAttempts:     3,
		}

		// Execute verification flow
		verificationResult, err := genkit.Run(
			ctx, "verification", func() (*models.VerificationResponse, error) {
				return analyzer.verifyHypothesis(ctx, verificationReq)
			},
		)
		if err != nil {
			log.Printf("❌ Verification failed for item %d: %v", i, err)

			// Create fallback result
			verificationResult = &models.VerificationResponse{
				OriginalIndex:     i,
				Status:            "inconclusive",
				UpdatedConfidence: item.ConfidenceScore,
				Reasoning:         fmt.Sprintf("Verification failed: %v", err),
			}
		}

		verificationResult.OriginalIndex = i
		verificationResults[i] = verificationResult

		log.Printf("📋 Item %d verification completed: %s (confidence: %.2f)",
			i, verificationResult.Status, verificationResult.UpdatedConfidence)
	}

	// Update checklist with verification results
	updatedChecklist := analyzer.applyVerificationResults(result.SecurityChecklist, verificationResults)

	// Update result
	result.SecurityChecklist = updatedChecklist
	result.ConfidenceScore = analyzer.calculateOverallConfidence(verificationResults)

	log.Printf("✅ All verifications completed. Overall confidence: %.2f", result.ConfidenceScore)

	// Broadcast updated result
	analyzer.WsHub.Broadcast(models.ReportDTO{
		Report: models.VulnerabilityReport{
			ID:             reportID,
			Timestamp:      time.Now(),
			AnalysisResult: *result,
		},
		RequestResponse:     requestInfo,
		VerificationStatus:  "completed",
		VerificationResults: verificationResults, // NEW: include detailed verification results
	})
}

// applyVerificationResults updates checklist items with verification results
func (analyzer *GenkitSecurityAnalyzer) applyVerificationResults(
	original []models.SecurityCheckItem,
	results []*models.VerificationResponse,
) []models.SecurityCheckItem {

	updated := make([]models.SecurityCheckItem, len(original))

	for i, item := range original {
		if i < len(results) {
			result := results[i]

			// Create copy of original item
			updatedItem := item

			// Update with verification results
			updatedItem.VerificationStatus = result.Status
			updatedItem.ConfidenceScore = result.UpdatedConfidence
			updatedItem.VerificationReason = result.Reasoning
			updatedItem.RecommendedPOC = result.RecommendedPOC

			updated[i] = updatedItem
		} else {
			updated[i] = item
		}
	}

	return updated
}

// calculateOverallConfidence calculates overall confidence from verification results
func (analyzer *GenkitSecurityAnalyzer) calculateOverallConfidence(results []*models.VerificationResponse) float64 {
	if len(results) == 0 {
		return 0.5
	}

	total := 0.0
	for _, result := range results {
		total += result.UpdatedConfidence
	}

	return total / float64(len(results))
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

// verifyHypothesis верифицирует гипотезу об уязвимости с помощью LLM
func (analyzer *GenkitSecurityAnalyzer) verifyHypothesis(ctx context.Context, req *models.VerificationRequest) (*models.VerificationResponse, error) {
	log.Printf("🔬 Starting verification for hypothesis: %s", req.ChecklistItem.Hypothesis)

	// Шаг 1: LLM генерирует тестовые запросы на основе гипотезы
	prompt := analyzer.buildVerificationPrompt(req)

	llmResponse, err := analyzer.llmProvider.GenerateVerificationPlan(ctx, &models.VerificationPlanRequest{
		Hypothesis:       req.ChecklistItem.Hypothesis,
		OriginalRequest:  req.OriginalRequest,
		MaxAttempts:      req.MaxAttempts,
		TargetURL:        req.OriginalRequest.URL,
		AdditionalInfo:   prompt,
	})

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: req.ChecklistItem.Confidence,
			Reasoning:         fmt.Sprintf("Failed to generate verification plan: %v", err),
			TestAttempts:      []models.TestAttempt{},
		}, nil
	}

	// Шаг 2: Выполняем сгенерированные тестовые запросы
	var testAttempts []models.TestAttempt
	var successfulTests []models.TestAttempt

	for _, testReq := range llmResponse.TestRequests {
		// Конвертируем в формат verification client
		verificationReq := verification.TestRequest{
			URL:     testReq.URL,
			Method:  testReq.Method,
			Headers: testReq.Headers,
			Body:    testReq.Body,
		}

		// Выполняем запрос
		testResp, err := analyzer.verificationClient.MakeRequest(ctx, verificationReq)

		testAttempt := models.TestAttempt{
			RequestURL:    testReq.URL,
			RequestMethod: testReq.Method,
			Headers:       make(map[string]string),
		}

		if err != nil {
			testAttempt.Error = err.Error()
			testAttempt.StatusCode = 0
			log.Printf("❌ Test request failed: %s - %v", testReq.URL, err)
		} else {
			testAttempt.StatusCode = testResp.StatusCode
			testAttempt.ResponseSize = testResp.ResponseSize
			testAttempt.ResponseBody = testResp.ResponseBody
			testAttempt.Headers = testResp.Headers
			testAttempt.Duration = testResp.Duration.String()
			successfulTests = append(successfulTests, testAttempt)
			log.Printf("✅ Test request completed: %s - Status: %d", testReq.URL, testResp.StatusCode)
		}

		testAttempts = append(testAttempts, testAttempt)
	}

	// Шаг 3: LLM анализирует результаты и определяет статус верификации
	analysisResponse, err := analyzer.llmProvider.AnalyzeVerificationResults(ctx, &models.VerificationAnalysisRequest{
		Hypothesis:        req.ChecklistItem.Hypothesis,
		OriginalConfidence: req.ChecklistItem.Confidence,
		TestResults:       successfulTests,
		OriginalRequest:   req.OriginalRequest,
	})

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: req.ChecklistItem.Confidence,
			Reasoning:         fmt.Sprintf("Failed to analyze verification results: %v", err),
			TestAttempts:      testAttempts,
		}, nil
	}

	log.Printf("🎯 Verification completed for hypothesis: %s - Status: %s",
		req.ChecklistItem.Hypothesis, analysisResponse.Status)

	return &models.VerificationResponse{
		OriginalIndex:     req.ChecklistItem.OriginalIndex,
		Status:            analysisResponse.Status,
		UpdatedConfidence: analysisResponse.UpdatedConfidence,
		Reasoning:         analysisResponse.Reasoning,
		TestAttempts:      testAttempts,
		RecommendedPOC:    analysisResponse.RecommendedPOC,
	}, nil
}

// buildVerificationPrompt создает промпт для LLM с контекстом верификации
func (analyzer *GenkitSecurityAnalyzer) buildVerificationPrompt(req *models.VerificationRequest) string {
	return fmt.Sprintf(`You are a security verification assistant. Your task is to verify a security hypothesis by generating and analyzing test requests.

HYPOTHESIS TO VERIFY: %s
CONFIDENCE LEVEL: %.2f
TARGET: %s

ORIGINAL REQUEST DETAILS:
- Method: %s
- URL: %s
- Status Code: %d
- Response Size: %d bytes

VERIFICATION REQUIREMENTS:
1. Generate %d test requests to verify this hypothesis
2. Each request should target the specific vulnerability type suggested
3. Focus on non-destructive testing that demonstrates the vulnerability
4. Include variations in parameters, payloads, or endpoints as appropriate
5. Consider both positive (vulnerable) and negative (secure) test cases

Generate targeted test requests that can definitively prove or disprove this security hypothesis.`,
		req.ChecklistItem.Hypothesis,
		req.ChecklistItem.Confidence,
		req.OriginalRequest.URL,
		req.OriginalRequest.Method,
		req.OriginalRequest.URL,
		req.OriginalRequest.StatusCode,
		len(req.OriginalRequest.RespBody),
		req.MaxAttempts)
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.Get(host)
}
