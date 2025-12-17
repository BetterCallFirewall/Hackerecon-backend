package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
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

	// URL Analysis cache (90% LLM reduction)
	urlCache *URLAnalysisCache

	// Enhanced SiteContext tracking
	formExtractor   *utils.FormExtractor
	crudMapper      *utils.CRUDMapper
	temporalTracker *utils.TemporalTracker
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
		contextManager:  NewSiteContextManager(),
		requestFilter:   utils.NewRequestFilter(),
		urlCache:        NewURLAnalysisCache(1000), // Кэш на 1000 URL паттернов
		formExtractor:   utils.NewFormExtractor(),
		crudMapper:      utils.NewCRUDMapper(),
		temporalTracker: utils.NewTemporalTracker(),
	}

	// Инициализация data extractor
	analyzer.dataExtractor = NewDataExtractor()

	// Определяем unified flow с orchestration двух LLM вызовов
	analyzer.unifiedAnalysisFlow = genkit.DefineFlow(
		genkitApp, "unifiedAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			// Step 1: Quick URL Analysis (traced)
			// Сначала проверяем кэш
			urlPattern := normalizeURLPattern(req.URL)
			cacheKey := fmt.Sprintf("%s:%s", req.Method, urlPattern)

			var urlAnalysisResp *models.URLAnalysisResponse
			if cached, ok := analyzer.urlCache.Get(cacheKey); ok {
				// Cache hit! Пропускаем LLM вызов
				log.Printf("✅ Cache HIT: %s %s", req.Method, urlPattern)
				urlAnalysisResp = cached
			} else {
				// Cache miss - делаем LLM запрос
				log.Printf("❌ Cache MISS: %s %s", req.Method, urlPattern)

				// Используем только 500 символов для быстрой проверки
				urlAnalysisReq := &models.URLAnalysisRequest{
					URL:          req.URL,
					Method:       req.Method,
					Headers:      req.Headers,
					ResponseBody: llm.TruncateString(req.ResponseBody, 500), // Только 500 символов!
					ContentType:  req.ContentType,
					SiteContext:  req.SiteContext,
				}

				var err error
				urlAnalysisResp, err = genkit.Run(
					ctx, "quick-url-analysis", func() (*models.URLAnalysisResponse, error) {
						return analyzer.llmProvider.GenerateURLAnalysis(ctx, urlAnalysisReq)
					},
				)
				if err != nil {
					return nil, fmt.Errorf("quick URL analysis failed: %w", err)
				}

				// Сохраняем в кэш
				analyzer.urlCache.Set(cacheKey, urlAnalysisResp)
			}

			// Step 2: Update URL pattern в контексте (всегда создаем заметки)
			if req.SiteContext != nil {
				analyzer.updateURLPattern(req.SiteContext, req.URL, req.Method, urlAnalysisResp)
			}

			// Step 3: Решаем, нужен ли полный анализ (только для high interest)
			// Для medium и low - возвращаем краткий результат
			if urlAnalysisResp.InterestLevel != "high" {
				// Быстрый анализ достаточен для low/medium - возвращаем краткий результат
				// WebSocket будет обновлен только с observations из Quick Analysis
				return &models.SecurityAnalysisResponse{
					Summary:         "Endpoint с " + urlAnalysisResp.InterestLevel + " приоритетом",
					Findings:        []models.Finding{}, // Нет findings для low/medium
					ContextForLater: models.ContextForLater{},
				}, nil
			}

			// Step 4: Теперь готовим полный контент для Full Analysis (только для high)
			req.RequestBody = analyzer.prepareContentForLLM(req.RequestBody, req.Headers["Content-Type"])
			req.ResponseBody = analyzer.prepareContentForLLM(req.ResponseBody, req.ContentType)

			// Step 5: Extract data только если нужно
			if analyzer.shouldExtractData(req.ContentType, req.ResponseBody) {
				extractedData, err := genkit.Run(
					ctx, "extract-data", func() (models.ExtractedData, error) {
						return analyzer.dataExtractor.ExtractFromContent(
							req.RequestBody,
							req.ResponseBody,
							req.ContentType,
						), nil
					},
				)
				if err != nil {
					return nil, err
				}
				req.ExtractedData = extractedData
			} else {
				// Пустые данные без overhead genkit.Run
				req.ExtractedData = models.ExtractedData{
					FormActions: []string{},
					Comments:    []string{},
				}
			}

			// Step 6: Full Security Analysis (traced)
			securityResp, err := genkit.Run(
				ctx, "full-security-analysis", func() (*models.SecurityAnalysisResponse, error) {
					return analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
				},
			)
			if err != nil {
				return nil, fmt.Errorf("security analysis failed: %w", err)
			}

			// Step 7: Ограничиваем findings до 5 и сортируем по приоритету
			if securityResp != nil && len(securityResp.Findings) > 5 {
				// Сортируем по impact/effort
				sort.Slice(
					securityResp.Findings, func(i, j int) bool {
						return priorityScore(securityResp.Findings[i]) > priorityScore(securityResp.Findings[j])
					},
				)
				securityResp.Findings = securityResp.Findings[:5]
			}

			return securityResp, nil
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
	analyzer.verificationClient = verification.NewVerificationClient(
		verification.VerificationClientConfig{
			Timeout:    30 * time.Second,
			MaxRetries: 2,
		},
	)

	// Initialize verification flow
	analyzer.verificationFlow = genkit.DefineFlow(
		analyzer.genkitApp,
		"verificationFlow",
		func(ctx context.Context, req *models.VerificationRequest) (*models.VerificationResponse, error) {
			// Generate hypothesis from checklist item
			hypothesis := req.ChecklistItem.Action + " - " + req.ChecklistItem.Description
			return analyzer.verifyHypothesis(ctx, req, hypothesis)
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

	// 3. Enhanced SiteContext tracking - collect data for LLM context
	startTime := time.Now()

	// Track temporal request history
	if err := analyzer.temporalTracker.TrackRequest(
		siteContext,
		req.Method,
		req.URL.Path,
		resp.StatusCode,
		int64(time.Since(startTime).Nanoseconds()/1e6), // duration in ms
		req.Referer(),
	); err != nil {
		log.Printf("⚠️ Failed to track temporal request: %v", err)
	}

	// Extract forms from HTML responses
	if strings.Contains(contentType, "html") && respBody != "" {
		forms := analyzer.formExtractor.ExtractForms(respBody)
		for _, form := range forms {
			// Add form to site context (avoid duplicates)
			if _, exists := siteContext.Forms[form.FormID]; !exists {
				form.FirstSeen = time.Now().Unix()
				siteContext.Forms[form.FormID] = form
				log.Printf(
					"📋 Extracted form: %s %s (Fields: %d, CSRF: %v)",
					form.Method, form.Action, len(form.Fields), form.HasCSRFToken,
				)
			}
		}
	}

	// Map CRUD operations for API requests
	analyzer.crudMapper.UpdateResourceMapping(siteContext, req.Method, req.URL.String())

	// 4. Unified анализ через один orchestration flow
	//    Quick Analysis всегда выполняется - LLM сам решает нужен ли Full Analysis
	//    на основе контекста сайта и подозрительных паттернов

	// Ленивая подготовка: минимум для Quick Analysis
	analysisReq := &models.SecurityAnalysisRequest{
		URL:    req.URL.String(),
		Method: req.Method,
		Headers: func() map[string]string {
			headers := make(map[string]string)
			for k, v := range req.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			return headers
		}(),
		RequestBody:  reqBody,  // Храним raw для полного анализа
		ResponseBody: respBody, // Храним raw для полного анализа
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

	// 5. Отправляем результат в WebSocket
	analyzer.broadcastAnalysisResult(req, resp, securityAnalysis, reqBody, respBody, siteContext)

	// 6. Логируем результат
	if securityAnalysis != nil && len(securityAnalysis.Findings) > 0 {
		log.Printf(
			"🔬 Полный анализ завершен для %s %s (найдено findings: %d)",
			req.Method, req.URL.String(), len(securityAnalysis.Findings),
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
	siteContext *models.SiteContext,
) {
	// Логируем критические находки
	for _, finding := range result.Findings {
		if finding.Impact == "high" || finding.Impact == "critical" {
			log.Printf("🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - %s", req.URL.String(), finding.Title)
			log.Printf("💡 Наблюдение: %s", finding.Observation)
		}
	}

	// Convert request info
	requestInfo := models.RequestResponseInfo{
		URL:        req.URL.String(),
		Method:     req.Method,
		StatusCode: resp.StatusCode,
		ReqHeaders: func() map[string]string {
			headers := make(map[string]string)
			for k, v := range req.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			return headers
		}(),
		RespHeaders: func() map[string]string {
			headers := make(map[string]string)
			for k, v := range resp.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			return headers
		}(),
		ReqBody:  llm.TruncateString(reqBody, maxContentSizeForLLM),
		RespBody: llm.TruncateString(respBody, maxContentSizeForLLM),
	}

	// Run parallel verification for findings
	if len(result.Findings) > 0 {
		// PHASE 0: Smart pre-filtering - skip obvious cases
		originalCount := len(result.Findings)
		result.Findings = analyzer.filterFindingsForVerification(result.Findings, siteContext)

		if originalCount != len(result.Findings) {
			log.Printf(
				"🔍 Pre-filtering: %d findings → %d (filtered %d)",
				originalCount, len(result.Findings), originalCount-len(result.Findings),
			)
		}

		// PHASE 1-2: Heuristic + LLM verification
		if len(result.Findings) > 0 {
			log.Printf("🔬 Starting batch verification for %d findings", len(result.Findings))
			analyzer.verifyFindingsBatch(result.Findings, requestInfo, siteContext)

			// Filter out findings that were disproven by verification
			originalCount := len(result.Findings)
			validFindings := make([]models.Finding, 0, len(result.Findings))

			for _, finding := range result.Findings {
				if finding.VerificationStatus == "likely_false" {
					log.Printf("🗑️  Filtering out disproven finding: %s", finding.Title)
					continue
				}
				validFindings = append(validFindings, finding)
			}

			result.Findings = validFindings

			if originalCount != len(validFindings) {
				log.Printf(
					"✅ Verification completed: %d findings kept, %d filtered out",
					len(validFindings), originalCount-len(validFindings),
				)
			} else {
				log.Printf("✅ Verification completed: all %d findings kept", len(validFindings))
			}
		}
	}

	// Broadcast final result with verified findings
	reportID := uuid.New().String()
	analyzer.WsHub.Broadcast(
		models.ReportDTO{
			Report: models.VulnerabilityReport{
				ID:             reportID,
				Timestamp:      time.Now(),
				AnalysisResult: *result,
			},
			RequestResponse: requestInfo,
		},
	)
}

// verifyFindingsBatch выполняет батч-верификацию всех findings за один LLM вызов
// Это намного быстрее чем verifyFindingsParallel (1 call вместо N)
func (analyzer *GenkitSecurityAnalyzer) verifyFindingsBatch(
	findings []models.Finding,
	requestInfo models.RequestResponseInfo,
	siteContext *models.SiteContext,
) {
	if len(findings) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log.Printf("🚀 Starting batch verification for %d findings", len(findings))

	// PHASE 1: Execute all test requests in parallel
	testResults := make([]models.TestRequestForBatch, 0, len(findings))
	var wg sync.WaitGroup
	var mu sync.Mutex

	maxConcurrent := 3
	sem := make(chan struct{}, maxConcurrent)

	for i := range findings {
		// IMPORTANT FIX: Set original index for O(1) lookup in heuristic phase
		findings[i].OriginalIndex = i

		wg.Add(1)
		go func(idx int, finding *models.Finding) {
			defer wg.Done()

			// CRITICAL FIX: Check immediately after entering goroutine, before any access
			if len(finding.TestRequests) == 0 {
				log.Printf("⚠️ Finding %s has no test requests, skipping", finding.Title)
				return
			}

			defer func() {
				if r := recover(); r != nil {
					log.Printf("⚠️ PANIC in verifyFindingsBatch goroutine: %v", r)
				}
			}()
			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Execute all test requests for this finding in parallel
			var testResultsForFinding []models.TestResultForBatch
			var wgTest sync.WaitGroup

			// IMPORTANT FIX: Limit concurrent tests per finding (max 3 concurrent tests)
			maxConcurrentTests := 3
			semTest := make(chan struct{}, maxConcurrentTests)

			for testIdx, testReq := range finding.TestRequests {
				wgTest.Add(1)
				go func(tIdx int, tReq models.TestRequest) {
					defer wgTest.Done()

					// Acquire test semaphore (max 3 concurrent tests)
					semTest <- struct{}{}
					defer func() { <-semTest }() // IMPORTANT: Release with defer

					// Execute test request
					testResult := analyzer.executeTestRequest(ctx, tReq, requestInfo)

					mu.Lock()
					testResultsForFinding = append(testResultsForFinding, models.TestResultForBatch{
						TestIndex:    tIdx,
						StatusCode:   testResult.StatusCode,
						ResponseBody: llm.TruncateString(testResult.ResponseBody, 2000),
						Error:        testResult.Error,
						Purpose:      tReq.Purpose, // From the test request
					})
					mu.Unlock()

					log.Printf("✅ Executed test %d for finding %d: %s", tIdx, idx, finding.Title)
				}(testIdx, testReq)
			}

			wgTest.Wait()

			// Add to batch results (already validated that TestRequests is not empty)
			mu.Lock()

			testResults = append(testResults, models.TestRequestForBatch{
				FindingIndex: idx, // IMPORTANT FIX: Store index for O(1) lookup
				// IMPORTANT FIX: Use requestInfo.URL instead of always using test request URL
				FindingURL: func() string {
					if requestInfo.URL != "" {
						return requestInfo.URL
					}
					if len(finding.TestRequests) > 0 {
						return finding.TestRequests[0].URL
					}
					return "unknown"
				}(),
				FindingTitle: finding.Title,
				TestResults:  testResultsForFinding,
			})
			mu.Unlock()
		}(i, &findings[i])
	}

	wg.Wait()

	// PHASE 2: Heuristic analysis on test results
	heuristicDecisions := 0

	// IMPORTANT FIX: Create map for O(1) lookup by FindingIndex
	testResultsMap := make(map[int]models.TestRequestForBatch)
	for _, reqForBatch := range testResults {
		testResultsMap[reqForBatch.FindingIndex] = reqForBatch
	}

	for _, finding := range findings {
		var bestStatus string
		var bestConfidence float64
		var bestReason string

		// Try heuristic analysis on ALL test results for this finding
		originalResp := &models.ResponseData{
			StatusCode: requestInfo.StatusCode,
			Body:       requestInfo.RespBody,
		}

		// IMPORTANT FIX: Direct O(1) lookup instead of O(n²) nested loop
		// Find the corresponding test results using the finding's original index
		if requestForFinding, ok := testResultsMap[finding.OriginalIndex]; ok {
			// Check if ANY test indicates vulnerability
			for _, testResult := range requestForFinding.TestResults {
				status, confidence, reason := utils.QuickHeuristicAnalysis(&finding, &models.TestResult{
					StatusCode:   testResult.StatusCode,
					ResponseBody: testResult.ResponseBody,
					Error:        testResult.Error,
				}, originalResp)

				// Track the most confident result
				if confidence > bestConfidence {
					bestStatus = status
					bestConfidence = confidence
					bestReason = reason
				}
			}
		}

		// If ANY test shows vulnerability (bestStatus != "needs_llm"), use that result
		if bestStatus != "" && bestStatus != "needs_llm" {
			finding.VerificationStatus = bestStatus
			finding.VerificationReason = fmt.Sprintf("Heuristic (%.0f%% confidence): %s", bestConfidence*100, bestReason)
			log.Printf("⚡ Heuristic HIT (%.0f%%): %s - %s", bestConfidence*100, finding.Title, bestStatus)
			heuristicDecisions++
		}
	}

	// Filter findings that were decided by heuristics
	needsLLM := make([]models.Finding, 0, len(findings))
	needsLLMIndices := make([]int, 0, len(findings))

	for i, finding := range findings {
		if finding.VerificationStatus == "" {
			needsLLM = append(needsLLM, finding)
			needsLLMIndices = append(needsLLMIndices, i)
		}
	}

	log.Printf(
		"📊 Heuristic decisions: %d/%d, LLM needed: %d/%d",
		heuristicDecisions, len(findings), len(needsLLM), len(findings),
	)

	// PHASE 3: LLM batch analysis (only if needed)
	if len(needsLLM) > 0 {
		batchReq := &models.BatchVerificationRequest{
			Findings:        make([]models.FindingForBatchVerification, len(needsLLM)),
			OriginalRequest: requestInfo,
			TestResults:     testResults,
		}

		// Build finding list for LLM
		for i, finding := range needsLLM {
			batchReq.Findings[i] = models.FindingForBatchVerification{
				Index:                i,
				Title:                finding.Title,
				Observation:          finding.Observation,
				ExpectedIfVulnerable: finding.ExpectedIfVulnerable,
				ExpectedIfSafe:       finding.ExpectedIfSafe,
			}
		}

		// Call LLM for batch analysis
		batchResult, err := analyzer.llmProvider.AnalyzeBatchVerification(ctx, batchReq)
		if err != nil {
			log.Printf("❌ Batch verification LLM call failed: %v", err)
			// Mark all as inconclusive
			for i := range needsLLM {
				findings[needsLLMIndices[i]].VerificationStatus = "inconclusive"
				findings[needsLLMIndices[i]].VerificationReason = "LLM batch call failed"
			}
			return
		}

		// Apply batch results to findings
		if batchResult != nil {
			for _, result := range batchResult.BatchResults {
				if result.FindingIndex < len(needsLLM) {
					originalIdx := needsLLMIndices[result.FindingIndex]
					findings[originalIdx].VerificationStatus = result.Status
					findings[originalIdx].VerificationReason = result.Reasoning

					log.Printf(
						"🤖 LLM Result: Finding %d (%s) - %s (%.0f%% confidence)",
						originalIdx, findings[originalIdx].Title, result.Status, result.Confidence*100,
					)

					// Mark low confidence as likely_false
					if result.Confidence < 0.3 && result.Status != "verified" {
						findings[originalIdx].VerificationStatus = "likely_false"
						log.Printf("🔴 Low confidence (%.2f), marking as likely false", result.Confidence)
					}
				}
			}
		}
	}

	log.Printf("✅ Batch verification completed for %d findings", len(findings))
}

// filterFindingsForVerification отфильтровывает findings которые не нужно верифицировать
func (analyzer *GenkitSecurityAnalyzer) filterFindingsForVerification(
	findings []models.Finding,
	siteContext *models.SiteContext,
) []models.Finding {
	filtered := make([]models.Finding, 0, len(findings))

	for _, finding := range findings {
		// Check 1: If this pattern was already verified as safe, skip
		var patternKey string
		if len(finding.TestRequests) > 0 {
			patternKey = finding.TestRequests[0].URL + ":" + finding.Title
		} else {
			patternKey = finding.Title
		}
		if analyzer.contextManager.IsPatternVerifiedSafe(siteContext.Host, patternKey) {
			log.Printf("⏭️  Skipping pre-verified safe pattern: %s", patternKey)
			finding.VerificationStatus = "likely_false"
			finding.VerificationReason = "Previously verified as safe"
			continue
		}

		// Check 2: If pattern was verified as vulnerable, mark it confirmed
		if analyzer.contextManager.IsPatternVerifiedVulnerable(siteContext.Host, patternKey) {
			log.Printf("⏭️  Skipping pre-verified vulnerable pattern: %s", patternKey)
			finding.VerificationStatus = "confirmed"
			finding.VerificationReason = "Previously verified as vulnerable"
			continue
		}

		// Check 3: Skip if low impact + high effort
		if finding.Impact == "low" && finding.Effort == "high" {
			log.Printf("⏭️  Skipping low-impact high-effort finding: %s", finding.Title)
			finding.VerificationStatus = "manual_check"
			finding.VerificationReason = "Effort too high for automated testing"
			continue
		}

		// Keep this finding for verification
		filtered = append(filtered, finding)
	}

	return filtered
}

// updateSiteContextWithVerification обновляет SiteContext с результатами верификации
func (analyzer *GenkitSecurityAnalyzer) updateSiteContextWithVerification(
	siteContext *models.SiteContext,
	findings []models.Finding,
) {
	for _, finding := range findings {
		var patternKey, testDesc string
		if len(finding.TestRequests) > 0 {
			patternKey = finding.TestRequests[0].URL + ":" + finding.Title
			testDesc = fmt.Sprintf("%s %s", finding.TestRequests[0].Method, finding.TestRequests[0].URL)
		} else {
			patternKey = finding.Title
			testDesc = finding.Title
		}

		if finding.VerificationStatus == "confirmed" || finding.VerificationStatus == "likely_true" {
			// Mark as vulnerable
			analyzer.contextManager.MarkPatternAsVulnerable(
				siteContext.Host,
				patternKey,
				finding.Impact,
				testDesc,
			)
		} else if finding.VerificationStatus == "likely_false" {
			// Mark as safe
			analyzer.contextManager.MarkPatternAsSafe(siteContext.Host, patternKey)
		}
	}

	log.Printf("📚 Updated SiteContext with %d verified patterns for %s", len(findings), siteContext.Host)
}

// executeTestRequest выполняет HTTP запрос для тестирования
func (analyzer *GenkitSecurityAnalyzer) executeTestRequest(
	ctx context.Context,
	testReq models.TestRequest,
	originalReq models.RequestResponseInfo,
) *models.TestResult {
	// Execute HTTP request
	verifyResult, err := analyzer.verificationClient.ExecuteTestRequest(ctx, testReq)
	if err != nil {
		log.Printf("⚠️ Test request failed: %v", err)
		return &models.TestResult{
			StatusCode:   0,
			ResponseBody: "",
			Error:        err.Error(),
		}
	}

	// Convert verification.TestResult to models.TestResult
	return &models.TestResult{
		StatusCode:   verifyResult.StatusCode,
		ResponseBody: verifyResult.ResponseBody,
		Headers:      verifyResult.Headers,
		Duration:     verifyResult.Duration,
		Error:        verifyResult.Error,
	}
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
			textContent = strings.Join(strings.Fields(textContent), " ")
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
	// Быстрая проверка contentType (O(1))
	if strings.Contains(contentType, "html") {
		return true
	}
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		return true
	}

	// Проверяем body ТОЛЬКО если contentType неопределен
	if contentType == "" || contentType == "text/plain" {
		// Проверяем только первые 1KB вместо всего body
		prefix := body
		if len(body) > 1024 {
			prefix = body[:1024]
		}
		return strings.Contains(prefix, "<html") || strings.Contains(prefix, "<!DOCTYPE")
	}

	return false
}

// Функции для работы с URL паттернами

// updateURLPattern обновляет паттерн URL с новой информацией
func (analyzer *GenkitSecurityAnalyzer) updateURLPattern(
	siteContext *models.SiteContext, url, method string, urlAnalysisResp *models.URLAnalysisResponse,
) {
	if siteContext == nil || urlAnalysisResp == nil {
		return
	}

	// Если есть URLNote в ответе, используем его
	if urlAnalysisResp.URLNote != nil {
		analyzer.contextManager.UpdateURLPattern(siteContext, url, method, urlAnalysisResp.URLNote)
	} else {
		// Для обратной совместимости создаем заметку из других полей
		note := &models.URLNote{
			Content:    urlAnalysisResp.EndpointType,
			Suspicious: urlAnalysisResp.InterestLevel == "high",
			Confidence: 0.5, // default confidence
		}
		analyzer.contextManager.UpdateURLPattern(siteContext, url, method, note)
	}
}

// GenerateHypothesisForHost принудительно генерирует гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GenerateHypothesisForHost(host string) (*models.HypothesisResponse, error) {
	return analyzer.hypothesisGen.GenerateForHost(host)
}

// verifyHypothesis верифицирует гипотезу об уязвимости с помощью LLM
func (analyzer *GenkitSecurityAnalyzer) verifyHypothesis(
	ctx context.Context,
	req *models.VerificationRequest,
	hypothesis string,
) (*models.VerificationResponse, error) {
	log.Printf("🔬 Starting verification for: %s", hypothesis)

	// Шаг 1: LLM генерирует тестовые запросы на основе гипотезы
	prompt := analyzer.buildVerificationPrompt(req, hypothesis)

	llmResponse, err := analyzer.llmProvider.GenerateVerificationPlan(
		ctx, &models.VerificationPlanRequest{
			Hypothesis:      hypothesis,
			OriginalRequest: req.OriginalRequest,
			MaxAttempts:     req.MaxAttempts,
			TargetURL:       req.OriginalRequest.URL,
			AdditionalInfo:  prompt,
		},
	)

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: 0.5,
			Reasoning:         fmt.Sprintf("Failed to generate verification plan: %v", err),
			TestAttempts:      []models.TestAttempt{},
		}, nil
	}

	// Шаг 2: Выполняем сгенерированные тестовые запросы
	var testAttempts []models.TestAttempt
	var successfulTests []models.TestAttempt

	for _, testReq := range llmResponse.TestRequests {
		// Используем models.TestRequest напрямую
		verificationReq := models.TestRequest{
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
	analysisResponse, err := analyzer.llmProvider.AnalyzeVerificationResults(
		ctx, &models.VerificationAnalysisRequest{
			Hypothesis:         hypothesis,
			OriginalConfidence: 0.5, // Default initial confidence
			TestResults:        successfulTests,
			OriginalRequest:    req.OriginalRequest,
		},
	)

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: 0.5,
			Reasoning:         fmt.Sprintf("Failed to analyze verification results: %v", err),
			TestAttempts:      testAttempts,
		}, nil
	}

	log.Printf("🎯 Verification completed: %s - Status: %s", hypothesis, analysisResponse.Status)

	return &models.VerificationResponse{
		Status:            analysisResponse.Status,
		UpdatedConfidence: analysisResponse.UpdatedConfidence,
		Reasoning:         analysisResponse.Reasoning,
		TestAttempts:      testAttempts,
		RecommendedPOC:    analysisResponse.RecommendedPOC,
	}, nil
}

// buildVerificationPrompt создает промпт для LLM с контекстом верификации
func (analyzer *GenkitSecurityAnalyzer) buildVerificationPrompt(
	req *models.VerificationRequest,
	hypothesis string,
) string {
	return fmt.Sprintf(
		`You are a security verification assistant. Your task is to verify a security hypothesis by generating and analyzing test requests.

HYPOTHESIS TO VERIFY: %s
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
		hypothesis,
		req.OriginalRequest.URL,
		req.OriginalRequest.Method,
		req.OriginalRequest.URL,
		req.OriginalRequest.StatusCode,
		len(req.OriginalRequest.RespBody),
		req.MaxAttempts,
	)
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.Get(host)
}

// priorityScore вычисляет приоритет finding для сортировки
// Выше impact = выше приоритет, ниже effort = выше приоритет
func priorityScore(f models.Finding) int {
	impactScores := map[string]int{"critical": 40, "high": 30, "medium": 20, "low": 10}
	effortScores := map[string]int{"low": 3, "medium": 2, "high": 1}

	impactScore := impactScores[f.Impact]
	if impactScore == 0 {
		impactScore = 10 // default
	}

	effortScore := effortScores[f.Effort]
	if effortScore == 0 {
		effortScore = 1 // default
	}

	return impactScore + effortScore
}
