# Self-Verifying LLM Security Analysis Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan

**Goal:** Build self-verifying LLM that automatically validates all its security recommendations through GET requests and updates user-facing recommendations based on actual test results

**Architecture:** Extend existing Genkit-based security analyzer with verification flow that test all LLM-generated hypotheses automatically, analyzes responses semantically, and updates SecurityChecklist items with verification status and confidence scores

**Tech Stack:** Go, Firebase Genkit, existing security analyzer, HTTP client, WebSocket communication

---

## Implementation Overview

This feature transforms the current "generate checklist for manual verification" approach into "self-verifying analysis" where:

1. LLM generates security hypotheses
2. LLM automatically tests each hypothesis with safe GET requests
3. LLM analyzes responses semantically to confirm/deny vulnerabilities
4. SecurityChecklist items are updated with verification status and confidence
5. User gets verified results instead of raw hypotheses

## Task 1: Extend Models for Verification Support

**Files:**
- Modify: `internal/models/vulnerabilities.go:25-30`

**Step 1: Add verification fields to SecurityCheckItem**

```go
// SecurityCheckItem - элемент чеклиста для пентестера
type SecurityCheckItem struct {
    Action      string  `json:"action" jsonschema:"description=Attack action name"`
    Description string  `json:"description" jsonschema:"description=How to perform the attack"`
    Expected    string  `json:"expected" jsonschema:"description=Expected result if vulnerable vs. if protected"`

    // New verification fields
    VerificationStatus string  `json:"verification_status,omitempty" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Auto-verification status"`
    ConfidenceScore    float64 `json:"confidence_score,omitempty" jsonschema:"description=Updated confidence after verification (0.0-1.0),minimum=0,maximum=1"`
    VerificationReason string  `json:"verification_reason,omitempty" jsonschema:"description=Why this status was assigned"`
    RecommendedPOC     string  `json:"recommended_poc,omitempty" jsonschema:"description=Recommended proof-of-concept for manual testing"`
}
```

**Step 2: Add verification request/response types**

```go
// Add to internal/models/vulnerabilities.go after SecurityCheckItem

// VerificationRequest - запрос на верификацию гипотез
type VerificationRequest struct {
    OriginalRequest RequestResponseInfo `json:"original_request" jsonschema:"description=Original request being analyzed"`
    ChecklistItem   SecurityCheckItem   `json:"checklist_item" jsonschema:"description=Hypothesis to verify"`
    MaxAttempts     int                 `json:"max_attempts" jsonschema:"description=Max verification attempts"`
}

// VerificationResponse - результат верификации
type VerificationResponse struct {
    OriginalIndex     int                `json:"original_index" jsonschema:"description=Index in original checklist"`
    Status            string             `json:"status" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Verification status"`
    UpdatedConfidence float64            `json:"updated_confidence" jsonschema:"description=Updated confidence score (0.0-1.0)"`
    Reasoning         string             `json:"reasoning" jsonschema:"description=LLM reasoning about verification results"`
    TestAttempts      []TestAttempt      `json:"test_attempts,omitempty" jsonschema:"description=Test attempts performed"`
    RecommendedPOC    string             `json:"recommended_poc,omitempty" jsonschema:"description:Recommended manual POC if needed"`
}

// TestAttempt - одна попытка верификации
type TestAttempt struct {
    RequestURL    string `json:"request_url" jsonschema:"description=Test request URL"`
    RequestMethod string `json:"request_method" jsonschema:"description=HTTP method used"`
    StatusCode    int    `json:"status_code" jsonschema:"description=Response status code"`
    ResponseSize  int    `json:"response_size" jsonschema:"description=Response body size in bytes"`
    ResponseBody  string `json:"response_body" jsonschema:"description=First 1KB of response body for analysis"`
    Headers       map[string]string `json:"headers,omitempty" jsonschema:"description=Key response headers"`
    Error         string `json:"error,omitempty" jsonschema:"description=Error if request failed"`
    Duration      string `json:"duration" jsonschema:"description=Request duration"`
}
```

**Step 3: Run tests to verify models compile**

Run: `go build ./internal/models`
Expected: SUCCESS - no compilation errors

**Step 4: Commit model changes**

```bash
git add internal/models/vulnerabilities.go
git commit -m "feat: add verification fields to SecurityCheckItem and VerificationRequest/Response types"
```

## Task 2: Create Verification HTTP Client

**Files:**
- Create: `internal/verification/client.go`

**Step 1: Write the failing test**

```go
// internal/verification/client_test.go
package verification

import (
    "context"
    "testing"
    "time"
    "github.com/BetterCallFirewall/Hackerecon/internal/models"
)

func TestVerificationClient_MakeRequest(t *testing.T) {
    client := NewVerificationClient(VerificationClientConfig{
        Timeout:    10 * time.Second,
        MaxRetries: 2,
    })

    req := TestRequest{
        URL:    "https://httpbin.org/get",
        Method: "GET",
        Headers: map[string]string{
            "User-Agent": "Hackerecon-Verifier/1.0",
        },
    }

    resp, err := client.MakeRequest(context.Background(), req)

    if err != nil {
        t.Fatalf("Expected no error, got %v", err)
    }

    if resp.StatusCode != 200 {
        t.Errorf("Expected status 200, got %d", resp.StatusCode)
    }

    if len(resp.ResponseBody) == 0 {
        t.Error("Expected non-empty response body")
    }
}

func TestVerificationClient_MakeRequest_InvalidURL(t *testing.T) {
    client := NewVerificationClient(VerificationClientConfig{
        Timeout:    10 * time.Second,
        MaxRetries: 2,
    })

    req := TestRequest{
        URL:    "not-a-url",
        Method: "GET",
    }

    _, err := client.MakeRequest(context.Background(), req)

    if err == nil {
        t.Error("Expected error for invalid URL")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/verification -v`
Expected: FAIL with "package verification does not exist" or "undefined: NewVerificationClient"

**Step 3: Write minimal implementation**

```go
// internal/verification/client.go
package verification

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"
)

// VerificationClient безопасный HTTP клиент для верификации
type VerificationClient struct {
    httpClient *http.Client
    config     VerificationClientConfig
}

// VerificationClientConfig конфигурация клиента
type VerificationClientConfig struct {
    Timeout    time.Duration
    MaxRetries int
    UserAgent  string
}

// TestRequest запрос для верификации
type TestRequest struct {
    URL     string
    Method  string
    Headers map[string]string
    Body    string // Для будущих POST запросов
}

// TestResponse ответ от верификационного запроса
type TestResponse struct {
    URL         string
    StatusCode  int
    ResponseSize int
    ResponseBody string // Первые 1KB для анализа
    Headers      map[string]string
    Duration     time.Duration
}

// NewVerificationClient создает новый клиент верификации
func NewVerificationClient(config VerificationClientConfig) *VerificationClient {
    if config.Timeout == 0 {
        config.Timeout = 30 * time.Second
    }
    if config.MaxRetries == 0 {
        config.MaxRetries = 2
    }
    if config.UserAgent == "" {
        config.UserAgent = "Hackerecon-Verifier/1.0"
    }

    return &VerificationClient{
        httpClient: &http.Client{
            Timeout: config.Timeout,
            // Отключаем редиректы для безопасности
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
            },
        },
        config: config,
    }
}

// MakeRequest выполняет безопасный тестовый запрос
func (vc *VerificationClient) MakeRequest(ctx context.Context, req TestRequest) (*TestResponse, error) {
    startTime := time.Now()

    // Создаем HTTP запрос
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, fmt.Errorf("creating request: %w", err)
    }

    // Устанавливаем заголовки
    httpReq.Header.Set("User-Agent", vc.config.UserAgent)
    for k, v := range req.Headers {
        // Копируем только безопасные заголовки
        if vc.isSafeHeader(k) {
            httpReq.Header.Set(k, v)
        }
    }

    // Выполняем запрос
    httpResp, err := vc.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("executing request: %w", err)
    }
    defer httpResp.Body.Close()

    // Читаем тело с ограничением в 1KB
    body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
    if err != nil {
        return nil, fmt.Errorf("reading response body: %w", err)
    }

    // Собираем заголовки (только безопасные)
    headers := make(map[string]string)
    for k, v := range httpResp.Header {
        if vc.isSafeHeader(k) && len(v) > 0 {
            headers[k] = v[0]
        }
    }

    return &TestResponse{
        URL:          req.URL,
        StatusCode:   httpResp.StatusCode,
        ResponseSize: len(body),
        ResponseBody: string(body),
        Headers:      headers,
        Duration:     time.Since(startTime),
    }, nil
}

// isSafeHeader проверяет, безопасен ли заголовок
func (vc *VerificationClient) isSafeHeader(name string) bool {
    safeHeaders := []string{
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Content-Type",
        "Content-Length",
        "Referer",
        "Origin",
        "Cache-Control",
    }

    lower := strings.ToLower(name)
    for _, safe := range safeHeaders {
        if strings.EqualFold(lower, safe) {
            return true
        }
    }
    return false
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/verification -v`
Expected: PASS - all tests pass

**Step 5: Commit client implementation**

```bash
git add internal/verification/
git commit -m "feat: add safe HTTP client for security verification"
```

## Task 3: Create Verification Genkit Flow

**Files:**
- Modify: `internal/driven/analyzer.go:37-39` (Add new flow field)
- Modify: `internal/driven/analyzer.go:47-50` (Initialize new flow)

**Step 1: Add verification flow to GenkitSecurityAnalyzer struct**

```go
// In internal/driven/analyzer.go, modify struct definition:

type GenkitSecurityAnalyzer struct {
    // Core components
    llmProvider llm.Provider
    WsHub       *websocket.WebsocketManager
    genkitApp   *genkit.Genkit

    // Analysis flows
    unifiedAnalysisFlow *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]

    // NEW: Verification flow
    verificationFlow   *genkitcore.Flow[*models.VerificationRequest, *models.VerificationResponse, struct{}]

    // Modular components
    contextManager *SiteContextManager
    dataExtractor  *DataExtractor
    hypothesisGen  *HypothesisGenerator
    requestFilter  *utils.RequestFilter

    // NEW: Verification client
    verificationClient *verification.VerificationClient
}
```

**Step 2: Initialize verification flow in constructor**

```go
// In NewGenkitSecurityAnalyzer function, after existing flow initialization:

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
```

**Step 3: Add verification helper method**

```go
// Add to internal/driven/analyzer.go

// verifyHypothesis выполняет верификацию одной гипотезы
func (analyzer *GenkitSecurityAnalyzer) verifyHypothesis(
    ctx context.Context,
    req *models.VerificationRequest,
) (*models.VerificationResponse, error) {

    // Определяем тип уязвимости для генерации тестов
    vulnType := analyzer.detectVulnerabilityType(req.ChecklistItem.Action, req.ChecklistItem.Description)

    // Генерируем тестовые запросы через LLM
    testRequests, err := analyzer.generateTestRequests(ctx, req.ChecklistItem, req.OriginalRequest.URL, vulnType)
    if err != nil {
        return &models.VerificationResponse{
            OriginalIndex:     0, // Will be set by caller
            Status:            "inconclusive",
            UpdatedConfidence: req.ChecklistItem.ConfidenceScore,
            Reasoning:         fmt.Sprintf("Failed to generate test requests: %v", err),
        }, nil
    }

    // Выполняем тестовые запросы
    var attempts []models.TestAttempt
    for _, testReq := range testRequests {
        if len(attempts) >= req.MaxAttempts {
            break
        }

        // Выполняем GET запрос
        response, err := analyzer.verificationClient.MakeRequest(ctx, verification.TestRequest{
            URL:     testReq.URL,
            Method:  "GET",
            Headers: req.OriginalRequest.ReqHeaders,
        })

        attempt := models.TestAttempt{
            RequestURL:    testReq.URL,
            RequestMethod: "GET",
            Duration:      response.Duration.String(),
        }

        if err != nil {
            attempt.Error = err.Error()
        } else {
            attempt.StatusCode = response.StatusCode
            attempt.ResponseSize = response.ResponseSize
            attempt.ResponseBody = response.ResponseBody
            attempt.Headers = response.Headers
        }

        attempts = append(attempts, attempt)
    }

    // Анализируем результаты через LLM
    analysisResult, err := analyzer.analyzeVerificationResults(ctx, req.ChecklistItem, attempts)
    if err != nil {
        return &models.VerificationResponse{
            OriginalIndex:     0, // Will be set by caller
            Status:            "inconclusive",
            UpdatedConfidence: req.ChecklistItem.ConfidenceScore,
            Reasoning:         fmt.Sprintf("Failed to analyze results: %v", err),
            TestAttempts:      attempts,
        }, nil
    }

    return analysisResult, nil
}

// detectVulnerabilityType определяет тип уязвимости
func (analyzer *GenkitSecurityAnalyzer) detectVulnerabilityType(action, description string) string {
    text := action + " " + description

    // SQLi паттерны
    if strings.Contains(strings.ToLower(text), "sql") ||
       strings.Contains(strings.ToLower(text), "injection") ||
       strings.Contains(strings.ToLower(text), "query") {
        return "SQL Injection"
    }

    // IDOR паттерны
    if strings.Contains(strings.ToLower(text), "idor") ||
       strings.Contains(strings.ToLower(text), "access control") ||
       strings.Contains(strings.ToLower(text), "id=") {
        return "IDOR"
    }

    // XSS паттерны
    if strings.Contains(strings.ToLower(text), "xss") ||
       strings.Contains(strings.ToLower(text), "script") ||
       strings.Contains(strings.ToLower(text), "cross-site") {
        return "XSS"
    }

    return "Unknown"
}
```

**Step 4: Run compilation test**

Run: `go build ./internal/driven`
Expected: FAIL - missing generateTestRequests and analyzeVerificationResults methods

**Step 5: Add missing LLM-based methods**

```go
// Add to internal/driven/analyzer.go

// generateTestRequests генерирует тестовые запросы через LLM
func (analyzer *GenkitSecurityAnalyzer) generateTestRequests(
    ctx context.Context,
    item models.SecurityCheckItem,
    baseURL string,
    vulnType string,
) ([]TestURLRequest, error) {

    prompt := fmt.Sprintf(`Generate 3 safe GET request URLs to test for %s vulnerability.
Base URL: %s
Hypothesis: %s - %s
Expected: %s

Rules:
- Only generate GET requests (no POST/PUT/DELETE)
- Use query parameters or URL path modifications
- Include safe test payloads that won't damage the system
- Return JSON format: [{"url": "...", "description": "..."}]

Example for IDOR: [{"url": "https://example.com/api/users/123", "description": "Access user ID 123"}, {"url": "https://example.com/api/users/999", "description": "Access different user ID"}]`,
        vulnType, baseURL, item.Action, item.Description, item.Expected)

    // Используем existing LLM provider
    response, err := analyzer.llmProvider.GenerateText(ctx, prompt)
    if err != nil {
        return nil, fmt.Errorf("generating test requests: %w", err)
    }

    // Парсим JSON ответ (для простоты, в реальном коде нужен robust parsing)
    var requests []TestURLRequest
    err = json.Unmarshal([]byte(response), &requests)
    if err != nil {
        return nil, fmt.Errorf("parsing test requests: %w", err)
    }

    return requests, nil
}

// TestURLRequest запрос от LLM
type TestURLRequest struct {
    URL         string `json:"url"`
    Description string `json:"description"`
}

// analyzeVerificationResults анализирует результаты через LLM
func (analyzer *GenkitSecurityAnalyzer) analyzeVerificationResults(
    ctx context.Context,
    item models.SecurityCheckItem,
    attempts []models.TestAttempt,
) (*models.VerificationResponse, error) {

    // Формируем данные для анализа
    attemptsJSON, _ := json.MarshalIndent(attempts, "", "  ")

    prompt := fmt.Sprintf(`Analyze these verification results for security testing.

Original Hypothesis: %s - %s
Expected Behavior: %s

Test Attempts:
%s

Based on these responses, determine:
1. Is this vulnerability confirmed (responses show different behaviors/data)?
2. Is this likely a false positive (all responses identical/safe)?
3. Is this inconclusive (cannot determine from GET requests)?
4. What confidence level (0.0-1.0) should be assigned?

Return JSON format:
{
  "status": "verified|likely_false|inconclusive|manual_check",
  "confidence": 0.0-1.0,
  "reasoning": "Detailed analysis of why this status was chosen",
  "recommended_poc": "Specific POC for manual testing if needed"
}`,
        item.Action, item.Description, item.Expected, string(attemptsJSON))

    response, err := analyzer.llmProvider.GenerateText(ctx, prompt)
    if err != nil {
        return nil, fmt.Errorf("analyzing results: %w", err)
    }

    // Парсим JSON ответ
    var result struct {
        Status          string  `json:"status"`
        Confidence      float64 `json:"confidence"`
        Reasoning       string  `json:"reasoning"`
        RecommendedPOC  string  `json:"recommended_poc"`
    }

    err = json.Unmarshal([]byte(response), &result)
    if err != nil {
        return nil, fmt.Errorf("parsing analysis result: %w", err)
    }

    return &models.VerificationResponse{
        OriginalIndex:     0, // Will be set by caller
        Status:            result.Status,
        UpdatedConfidence: result.Confidence,
        Reasoning:         result.Reasoning,
        TestAttempts:      attempts,
        RecommendedPOC:    result.RecommendedPOC,
    }, nil
}
```

**Step 6: Add required imports**

```go
// Add to imports in internal/driven/analyzer.go
import (
    "encoding/json"
    "fmt"
    "strings"

    "github.com/BetterCallFirewall/Hackerecon/internal/verification"
)
```

**Step 7: Run compilation test**

Run: `go build ./internal/driven`
Expected: SUCCESS - no compilation errors

**Step 8: Commit verification flow implementation**

```bash
git add internal/driven/analyzer.go
git commit -m "feat: add Genkit verification flow for self-verifying security analysis"
```

## Task 4: Integrate Verification into Main Analysis

**Files:**
- Modify: `internal/driven/analyzer.go` (Update broadcastAnalysisResult method)

**Step 1: Add verification call to analysis result processing**

```go
// Find and modify broadcastAnalysisResult method, add verification call:

func (analyzer *GenkitSecurityAnalyzer) broadcastAnalysisResult(
    req *http.Request,
    resp *http.Response,
    result *models.SecurityAnalysisResponse,
    reqBody, respBody string,
) {
    // Convert request info
    requestInfo := models.RequestResponseInfo{
        URL:         req.URL.String(),
        Method:      req.Method,
        StatusCode:  resp.StatusCode,
        ReqHeaders:  convertHeaders(req.Header),
        RespHeaders: convertHeaders(resp.Header),
        ReqBody:     reqBody,
        RespBody:    respBody,
    }

    // Broadcast initial result immediately (fast response)
    reportID := uuid.New().String()
    analyzer.WsHub.Broadcast(models.ReportDTO{
        Report: models.VulnerabilityReport{
            ID:             reportID,
            Timestamp:      time.Now(),
            AnalysisResult: *result,
        },
        RequestResponse:   requestInfo,
        VerificationStatus: "in_progress", // NEW: track verification progress
    })

    // Start background verification if there are checklist items
    if result.HasVulnerability && len(result.SecurityChecklist) > 0 {
        go analyzer.verifyChecklistInBackground(reportID, result, requestInfo)
    }
}

// NEW: Background verification method
func (analyzer *GenkitSecurityAnalyzer) verifyChecklistInBackground(
    reportID string,
    result *models.SecurityAnalysisResponse,
    requestInfo models.RequestResponseInfo,
) {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // Verify each checklist item
    verificationResults := make([]*models.VerificationResponse, len(result.SecurityChecklist))

    for i, item := range result.SecurityChecklist {
        // Create verification request
        verificationReq := &models.VerificationRequest{
            OriginalRequest: requestInfo,
            ChecklistItem:   item,
            MaxAttempts:     3,
        }

        // Execute verification flow
        verificationResult, err := analyzer.verificationFlow.Execute(ctx, verificationReq)
        if err != nil {
            log.Printf("Verification failed for item %d: %v", i, err)

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
    }

    // Update checklist with verification results
    updatedChecklist := analyzer.applyVerificationResults(result.SecurityChecklist, verificationResults)

    // Update result
    result.SecurityChecklist = updatedChecklist
    result.ConfidenceScore = analyzer.calculateOverallConfidence(verificationResults)

    // Broadcast updated result
    analyzer.WsHub.Broadcast(models.ReportDTO{
        Report: models.VulnerabilityReport{
            ID:             reportID,
            Timestamp:      time.Now(),
            AnalysisResult: *result,
        },
        RequestResponse:    requestInfo,
        VerificationStatus: "completed",
        VerificationResults: verificationResults, // NEW: include detailed verification results
    })
}

// NEW: Apply verification results to checklist
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

// NEW: Calculate overall confidence from verification results
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
```

**Step 2: Update DTO to include verification fields**

```go
// Modify internal/models/dto.go to include verification fields:

type ReportDTO struct {
    Report              models.VulnerabilityReport `json:"report"`
    RequestResponse     models.RequestResponseInfo `json:"request_response"`

    // NEW: Verification tracking fields
    VerificationStatus   string                       `json:"verification_status,omitempty"`
    VerificationResults  []*models.VerificationResponse `json:"verification_results,omitempty"`
}
```

**Step 3: Run compilation test**

Run: `go build ./internal/driven`
Expected: SUCCESS - no compilation errors

**Step 4: Test verification integration**

```bash
# Build and run basic test
go run cmd/main.go &
# Test with some HTTP request to trigger verification
curl -x http://localhost:8090 http://httpbin.org/get
# Check logs for verification activity
```

**Step 5: Commit verification integration**

```bash
git add internal/driven/analyzer.go internal/models/dto.go
git commit -m "feat: integrate self-verification into main security analysis flow"
```

## Task 5: Add Comprehensive Tests

**Files:**
- Create: `internal/driven/analyzer_verification_test.go`

**Step 1: Write verification flow tests**

```go
package driven

import (
    "context"
    "testing"
    "time"
    "github.com/BetterCallFirewall/Hackerecon/internal/models"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// MockLLMProvider для тестирования
type MockLLMProvider struct {
    mock.Mock
}

func (m *MockLLMProvider) GenerateText(ctx context.Context, prompt string) (string, error) {
    args := m.Called(ctx, prompt)
    return args.String(0), args.Error(1)
}

func TestVerifyHypothesis_IDOR_Verified(t *testing.T) {
    // Setup
    mockProvider := &MockLLMProvider{}

    // Mock test request generation
    mockProvider.On("GenerateText", mock.Anything, mock.AnythingOfType("string")).
        Return(`[{"url": "https://example.com/api/users/123", "description": "Access user 123"}, {"url": "https://example.com/api/users/999", "description": "Access user 999"}]`, nil).
        Once()

    // Mock result analysis - LLM says vulnerability confirmed
    mockProvider.On("GenerateText", mock.Anything, mock.AnythingOfType("string")).
        Return(`{
            "status": "verified",
            "confidence": 0.9,
            "reasoning": "Different user IDs return data indicating missing access control",
            "recommended_poc": ""
        }`, nil).
        Once()

    // Create analyzer with mock provider
    analyzer := &GenkitSecurityAnalyzer{
        llmProvider:         mockProvider,
        verificationClient: verification.NewVerificationClient(verification.VerificationClientConfig{
            Timeout:    10 * time.Second,
            MaxRetries: 1,
        }),
    }

    // Setup verification request
    req := &models.VerificationRequest{
        OriginalRequest: models.RequestResponseInfo{
            URL:    "https://example.com/api/users/123",
            Method: "GET",
            ReqHeaders: map[string]string{
                "User-Agent": "test-agent",
            },
        },
        ChecklistItem: models.SecurityCheckItem{
            Action:       "IDOR via user ID substitution",
            Description:  "Test if accessing different user IDs returns their data",
            Expected:     "Different user data returned if vulnerable",
            ConfidenceScore: 0.7,
        },
        MaxAttempts: 2,
    }

    // Execute verification
    result, err := analyzer.verifyHypothesis(context.Background(), req)

    // Assertions
    assert.NoError(t, err)
    assert.Equal(t, "verified", result.Status)
    assert.Equal(t, 0.9, result.UpdatedConfidence)
    assert.Contains(t, result.Reasoning, "missing access control")
    assert.Len(t, result.TestAttempts, 2)

    mockProvider.AssertExpectations(t)
}

func TestVerifyHypothesis_SQLi_LikelyFalse(t *testing.T) {
    // Similar test for SQLi that returns "likely_false"
    mockProvider := &MockLLMProvider{}

    mockProvider.On("GenerateText", mock.Anything, mock.AnythingOfType("string")).
        Return(`[{"url": "https://example.com/search?q=test' AND '1'='1", "description": "SQLi true condition"}, {"url": "https://example.com/search?q=test' AND '1'='0", "description": "SQLi false condition"}]`, nil).
        Once()

    mockProvider.On("GenerateText", mock.Anything, mock.AnythingOfType("string")).
        Return(`{
            "status": "likely_false",
            "confidence": 0.2,
            "reasoning": "All test responses are identical, likely safe from SQLi",
            "recommended_poc": "Try POST request with: ' OR 1=1--"
        }`, nil).
        Once()

    analyzer := &GenkitSecurityAnalyzer{
        llmProvider:         mockProvider,
        verificationClient: verification.NewVerificationClient(verification.VerificationClientConfig{
            Timeout:    10 * time.Second,
            MaxRetries: 1,
        }),
    }

    req := &models.VerificationRequest{
        OriginalRequest: models.RequestResponseInfo{
            URL:    "https://example.com/search?q=test",
            Method: "GET",
        },
        ChecklistItem: models.SecurityCheckItem{
            Action:       "SQL Injection in search parameter",
            Description:  "Test search parameter for SQL injection vulnerability",
            Expected:     "Different responses if SQLi vulnerable",
            ConfidenceScore: 0.8,
        },
        MaxAttempts: 2,
    }

    result, err := analyzer.verifyHypothesis(context.Background(), req)

    assert.NoError(t, err)
    assert.Equal(t, "likely_false", result.Status)
    assert.Equal(t, 0.2, result.UpdatedConfidence)
    assert.Equal(t, "Try POST request with: ' OR 1=1--", result.RecommendedPOC)

    mockProvider.AssertExpectations(t)
}
```

**Step 2: Run verification tests**

Run: `go test ./internal/driven -v -run TestVerifyHypothesis`
Expected: PASS - all verification tests pass

**Step 3: Add integration tests**

```go
func TestFullAnalysisWithVerification(t *testing.T) {
    // This would test the full flow from analysis to verification
    // Requires more complex setup with actual HTTP responses
    t.Skip("Integration test - requires HTTP server setup")
}
```

**Step 4: Commit tests**

```bash
git add internal/driven/analyzer_verification_test.go
git commit -m "feat: add comprehensive tests for self-verification flow"
```

## Task 6: Update Documentation and Examples

**Files:**
- Create: `docs/self_verifying_analysis.md`

**Step 1: Write documentation**

```markdown
# Self-Verifying Security Analysis

## Overview

The self-verifying security analysis automatically validates all LLM-generated security hypotheses through safe GET requests and updates user recommendations based on actual test results.

## How It Works

1. **Hypothesis Generation**: LLM generates security checklist items
2. **Automatic Verification**: Each hypothesis is tested with safe GET requests
3. **Response Analysis**: LLM analyzes responses semantically to confirm/deny vulnerabilities
4. **Result Update**: Checklist items are updated with verification status and confidence
5. **POC Generation**: Manual POCs suggested for complex attacks

## Example Output

### Before (Traditional Analysis)
```
🔍 Security Checklist:
1. IDOR via user ID substitution [Manual verification needed]
2. SQLi in search parameter [Manual verification needed]
```

### After (Self-Verifying Analysis)
```
🔍 Verified Security Analysis:
1. ✅ IDOR via user ID substitution [VERIFIED - 90% confidence]
   Evidence: Successfully accessed different user data

2. ❌ SQLi in search parameter [LIKELY FALSE - 20% confidence]
   Reasoning: All test responses identical
   Manual POC: Try POST with ' OR 1=1--
```

## Verification Process

Each hypothesis undergoes:
- **Max 3 test attempts** with different payloads
- **GET-only requests** for safety
- **Semantic response analysis** by LLM
- **Confidence adjustment** based on results
- **POC generation** for manual testing

## Status Types

- `verified`: Vulnerability confirmed through testing
- `likely_false`: Probably false positive, confidence reduced
- `inconclusive`: Cannot determine from GET requests
- `manual_check`: Requires manual investigation
```

**Step 2: Update README**

```markdown
# Add to main README Features section:

- ✅ **Self-Verifying Analysis**: Automatically validates security hypotheses through safe testing
- ✅ **Confidence Scoring**: Real-time confidence updates based on verification results
- ✅ **POC Generation**: Automatic generation of proof-of-concept for manual testing
- ✅ **Background Processing**: Non-blocking verification with real-time updates
```

**Step 3: Commit documentation**

```bash
git add docs/self_verifying_analysis.md README.md
git commit -m "docs: add self-verifying analysis documentation"
```

## Task 7: Final Testing and Review

**Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: PASS - all tests pass

**Step 2: Build application**

Run: `go build -o hackerecon cmd/main.go`
Expected: SUCCESS - builds without errors

**Step 3: Manual verification test**

```bash
# Start the application
./hackerecon &

# Test with a vulnerable endpoint (using httpbin as safe test)
curl -x http://localhost:8090 "http://httpbin.org/json"

# Check WebSocket dashboard for verification results
# Should show background verification in progress and then completed results
```

**Step 4: Performance verification**

```bash
# Test with multiple concurrent requests
for i in {1..10}; do
    curl -x http://localhost:8090 "http://httpbin.org/uuid" &
done
wait

# Monitor that verification doesn't block responses
```

**Step 5: Final commit**

```bash
git add .
git commit -m "feat: complete self-verifying LLM security analysis implementation"
```

---

## Success Criteria Verification

✅ **Self-Verification**: All LLM hypotheses are automatically tested
✅ **Safe Testing**: Only GET requests, no data modification
✅ **Real-time Updates**: WebSocket shows verification progress
✅ **Confidence Adjustment**: Scores updated based on actual test results
✅ **POC Generation**: Manual testing suggestions when needed
✅ **Background Processing**: Non-blocking verification
✅ **Error Handling**: Graceful fallback when verification fails

The implementation transforms the security analysis from "generate checklist for manual verification" to "self-verifying assistant" that validates its own recommendations and provides actionable results.