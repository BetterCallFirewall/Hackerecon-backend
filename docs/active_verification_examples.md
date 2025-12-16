# Active Verification: Code Examples & Patterns

## Overview

Этот документ содержит подробные примеры реализации для active verification компонентов с акцентом на Go best practices, обучающие примеры и паттерны, которые можно применить в проекте.

## 1. Структура пакета verification

```
internal/
└── verification/
    ├── types.go              # Common types, interfaces
    ├── verifier.go           # Main verification logic
    ├── payloads.go           # Payload generation (rule-based)
    ├── comparator.go         # Response comparison
    ├── security.go           # Security checks & rate limiting
    └── verifier_test.go      # Comprehensive tests
    └── testdata/             # Test fixtures
```

## 2. Core Types: `types.go`

### Паттерн: Интерфейс для тестируемости

```go
package verification

import (
    "context"
    "time"

    "github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// Verifier - интерфейс для проверки гипотез
type Verifier interface {
    // VerifyHypothesis проверяет одну гипотезу
    VerifyHypothesis(ctx context.Context,
                     hypothesis models.SecurityCheckItem,
                     originalReq models.RequestResponseInfo) VerificationResult

    // VerifyAll проверяет весь чек-лист
    VerifyAll(ctx context.Context,
              checklist []models.SecurityCheckItem,
              originalReq models.RequestResponseInfo) []VerificationResult
}

// VerificationResult - результат проверки
type VerificationResult struct {
    // Оригинальная гипотеза
    OriginalHypothesis models.SecurityCheckItem

    // Статус проверки
    VerificationStatus VerificationStatus

    // Изменение уверенности (0.5-2.0)
    // < 1.0 = уменьшить уверенность (ложный)
    // > 1.0 = увеличить уверенность (подтвержден)
    ConfidenceChange float64

    // Объяснение решения
    Reasoning string

    // Доказательства для отладки
    Evidence VerificationEvidence

    // Время выполнения
    Duration time.Duration
}

// VerificationStatus - статус проверки
type VerificationStatus string

const (
    // StatusVerified - уязвимость подтверждена (responses отличаются)
    StatusVerified VerificationStatus = "verified"

    // StatusLikelySafe - скорее безопасно, ложный сигнал (responses похожи)
    StatusLikelySafe VerificationStatus = "likely_safe"

    // StatusInconclusive - недостаточно данных
    StatusInconclusive VerificationStatus = "inconclusive"

    // StatusNotSupported - тип уязвимости не поддерживается
    StatusNotSupported VerificationStatus = "not_supported"
)

// VerificationEvidence - доказательства проверки
type VerificationEvidence struct {
    // Тестовые запросы
    Payloads []TestPayload

    // Полученные ответы
    Responses []TestResponse

    // Результат сравнения
    Comparison ComparisonResult

    // Лог выполнения (для отладки)
    ExecutionLog []string
}

// TestPayload - один тестовый запрос
type TestPayload struct {
    // URL с внедренным payload
    URL string

    // Человекочитаемое описание
    Description string

    // Тип уязвимости
    Type VulnerabilityType
}

// TestResponse - ответ от сервера (безопасная версия)
type TestResponse struct {
    // Запрошенный URL
    URL string

    // HTTP status code
    StatusCode int

    // Размер тела (вместо полного тела)
    BodySize int

    // Хеш тела для сравнения
    BodyHash string

    // Заголовки (частично)
    Headers map[string]string

    // Время ответа
    Duration time.Duration

    // Ошибка (если есть)
    Error error
}

// VulnerabilityType - тип поддерживаемой уязвимости
type VulnerabilityType int

const (
    VulnTypeUnknown VulnerabilityType = iota
    VulnTypeSQLi
    VulnTypeIDOR
    VulnTypeXSSReflected
    VulnTypeSSRF
    VulnTypeOpenRedirect
    VulnTypePathTraversal
)

func (vt VulnerabilityType) String() string {
    switch vt {
    case VulnTypeSQLi:
        return "SQL Injection"
    case VulnTypeIDOR:
        return "IDOR"
    case VulnTypeXSSReflected:
        return "Reflected XSS"
    case VulnTypeSSRF:
        return "SSRF"
    case VulnTypeOpenRedirect:
        return "Open Redirect"
    case VulnTypePathTraversal:
        return "Path Traversal"
    default:
        return "Unknown"
    }
}
```

## 3. Safe Verifier: `verifier.go`

### Паттерн: Dependency Injection для тестов

```go
package verification

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// SafeVerifier - безопасная реализация Verifier
type SafeVerifier struct {
    // HTTP client (можно замокать в тестах)
    client *http.Client

    // Payload generator
    payloadGenerator *PayloadGenerator

    // Response comparator
    comparator *ResponseComparator

    // Rate limiter
    rateLimiter *RateLimiter

    // Security checker
    securityChecker *SecurityChecker

    // Max concurrent requests
    maxConcurrency int

    // Logger (интерфейс для тестов)
    logger Logger
}

// Logger - интерфейс для логирования
type Logger interface {
    Printf(format string, v ...interface{})
}

type defaultLogger struct{}

func (l defaultLogger) Printf(format string, v ...interface{}) {
    log.Printf(format, v...)
}

// Config - конфигурация для создания Verifier
type Config struct {
    // HTTP client (опционально, будет создан по умолчанию)
    HTTPClient *http.Client

    // Max concurrent verifications (default: 5)
    MaxConcurrency int

    // Max requests per second per host (default: 10)
    RequestsPerSecond int
}

// NewSafeVerifier создает новый безопасный верификатор
func NewSafeVerifier(config Config) *SafeVerifier {
    // HTTP client с безопасными настройками
    client := config.HTTPClient
    if client == nil {
        client = &http.Client{
            Timeout: 30 * time.Second,
            // Отключаем автоматические редиректы
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                // Log redirect attempts but don't follow
                log.Printf("[Verifier] Redirect blocked: %s", req.URL)
                return http.ErrUseLastResponse
            },
        }
    }

    maxConcurrency := config.MaxConcurrency
    if maxConcurrency <= 0 {
        maxConcurrency = 5
    }

    rps := config.RequestsPerSecond
    if rps <= 0 {
        rps = 10
    }

    return &SafeVerifier{
        client:          client,
        payloadGenerator: NewPayloadGenerator(),
        comparator:      NewResponseComparator(),
        rateLimiter:     NewRateLimiter(rps, time.Second),
        securityChecker: NewSecurityChecker(),
        maxConcurrency:  maxConcurrency,
        logger:          defaultLogger{},
    }
}

// VerifyAll проверяет весь чек-лист
func (v *SafeVerifier) VerifyAll(
    ctx context.Context,
    checklist []models.SecurityCheckItem,
    originalReq models.RequestResponseInfo,
) []VerificationResult {

    if len(checklist) == 0 {
        return []VerificationResult{}
    }

    results := make([]VerificationResult, len(checklist))
    var wg sync.WaitGroup

    // Семафор для ограничения concurrency
    sem := make(chan struct{}, v.maxConcurrency)

    // Запускаем parallel verification
    for i, item := range checklist {
        wg.Add(1)

        go func(index int, hypothesis models.SecurityCheckItem) {
            defer wg.Done()

            // Ждем свободный слот
            sem <- struct{}{}
            defer func() { <-sem }()

            // Context для каждой гипотезы (timeout 10 сек)
            hypothesisCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
            defer cancel()

            results[index] = v.VerifyHypothesis(hypothesisCtx, hypothesis, originalReq)
        }(i, item)
    }

    wg.Wait()
    return results
}

// VerifyHypothesis проверяет одну гипотезу
func (v *SafeVerifier) VerifyHypothesis(
    ctx context.Context,
    hypothesis models.SecurityCheckItem,
    originalReq models.RequestResponseInfo,
) VerificationResult {

    startTime := time.Now()

    result := VerificationResult{
        OriginalHypothesis: hypothesis,
        VerificationStatus: StatusInconclusive,
        ConfidenceChange:   1.0,
        Duration:           0,
    }

    // Step 1: Detect vulnerability type
    vulnType := v.detectVulnerabilityType(hypothesis.Action)
    if vulnType == VulnTypeUnknown {
        result.VerificationStatus = StatusNotSupported
        result.Reasoning = "Vulnerability type not recognized or not supported: " + hypothesis.Action
        result.Duration = time.Since(startTime)
        return result
    }

    result.ExecutionLog = append(result.ExecutionLog,
        fmt.Sprintf("Detected type: %s", vulnType))

    // Step 2: Validate URL (security check)
    if !v.securityChecker.IsURLAllowed(originalReq.URL) {
        result.Reasoning = "URL not allowed for security reasons"
        result.Duration = time.Since(startTime)
        return result
    }

    // Step 3: Generate test payloads
    payloads := v.payloadGenerator.Generate(vulnType, originalReq.URL, hypothesis)
    if len(payloads) == 0 {
        result.Reasoning = "No test payloads could be generated"
        result.Duration = time.Since(startTime)
        return result
    }

    result.Payloads = payloads
    result.ExecutionLog = append(result.ExecutionLog,
        fmt.Sprintf("Generated %d payloads", len(payloads)))

    // Step 4: Execute test requests
    responses := make([]TestResponse, 0, len(payloads))

    for _, payload := range payloads {
        // Check rate limit
        if !v.rateLimiter.Allow(payload.URL) {
            result.ExecutionLog = append(result.ExecutionLog,
                "Rate limited: "+payload.URL)
            continue
        }

        // Check context cancellation
        if ctx.Err() != nil {
            result.ExecutionLog = append(result.ExecutionLog,
                "Context cancelled: "+ctx.Err().Error())
            break
        }

        resp, err := v.executeSafeRequest(ctx, payload, originalReq)
        if err != nil {
            result.ExecutionLog = append(result.ExecutionLog,
                fmt.Sprintf("Request failed: %v", err))
            continue
        }

        responses = append(responses, resp)
    }

    if len(responses) < 2 {
        result.Reasoning = fmt.Sprintf("Insufficient responses: got %d, need at least 2", len(responses))
        result.Duration = time.Since(startTime)
        return result
    }

    result.Responses = responses

    // Step 5: Compare responses
    baseline, tests := responses[0], responses[1:]
    comparison := v.comparator.Compare(baseline, tests)
    result.Comparison = comparison

    // Step 6: Determine status based on comparison
    switch comparison.Verdict {
    case VerdictDifferent:
        result.VerificationStatus = StatusVerified
        result.ConfidenceChange = 1.3 // +30% confidence
        result.Reasoning = "Test responses differ significantly from baseline, indicating potential vulnerability"

    case VerdictSimilar:
        result.VerificationStatus = StatusLikelySafe
        result.ConfidenceChange = 0.6 // -40% confidence
        result.Reasoning = "Test responses are similar to baseline, suggesting false positive"

    case VerdictInconclusive:
        result.VerificationStatus = StatusInconclusive
        result.Reasoning = "Cannot determine vulnerability status - responses are inconclusive"
    }

    result.Duration = time.Since(startTime)
    return result
}

// executeSafeRequest выполняет один тестовый запрос
func (v *SafeVerifier) executeSafeRequest(
    ctx context.Context,
    payload TestPayload,
    originalReq models.RequestResponseInfo,
) (TestResponse, error) {

    reqStart := time.Now()

    // Create request
    req, err := http.NewRequestWithContext(ctx, "GET", payload.URL, nil)
    if err != nil {
        return TestResponse{}, fmt.Errorf("creating request: %w", err)
    }

    // Copy ONLY safe headers from original request
    safeHeaders := v.securityChecker.FilterHeaders(originalReq.ReqHeaders)
    for k, val := range safeHeaders {
        req.Header.Set(k, val)
    }

    // Log request (без sensitive data)
    v.logger.Printf("[Verifier] Executing: %s", payload.URL)

    // Execute request
    resp, err := v.client.Do(req)
    if err != nil {
        return TestResponse{
            URL:   payload.URL,
            Error: err,
        }, nil // return error in response, not as function error
    }
    defer resp.Body.Close()

    // Read body with size limit
    body := readBodyWithLimit(resp.Body, 1*1024*1024) // 1MB max
    bodyHash := hashString(body)

    // Sanitize headers (remove sensitive ones)
    headers := v.securityChecker.SanitizeHeaders(resp.Header)

    return TestResponse{
        URL:        payload.URL,
        StatusCode: resp.StatusCode,
        BodySize:   len(body),
        BodyHash:   bodyHash,
        Headers:    headers,
        Duration:   time.Since(reqStart),
    }, nil
}

// detectVulnerabilityType определяет тип по описанию
func (v *SafeVerifier) detectVulnerabilityType(action string) VulnerabilityType {
    actionLower := strings.ToLower(action)

    // SQLi indicators
    if strings.ContainsAny(actionLower, "sql|injection|query|select|union") {
        return VulnTypeSQLi
    }

    // IDOR indicators
    if strings.ContainsAny(actionLower, "idor|access control|id|user|account|bypass") {
        return VulnTypeIDOR
    }

    // XSS indicators
    if strings.ContainsAny(actionLower, "xss|cross.site|script|onerror|onload") {
        return VulnTypeXSSReflected
    }

    // SSRF indicators
    if strings.ContainsAny(actionLower, "ssrf|internal|localhost|127.0.0.1") {
        return VulnTypeSSRF
    }

    // Open redirect indicators
    if strings.ContainsAny(actionLower, "redirect|open.url|url=") {
        return VulnTypeOpenRedirect
    }

    return VulnTypeUnknown
}

// Helper functions

// readBodyWithLimit читает тело с ограничением по размеру
func readBodyWithLimit(body io.Reader, maxSize int) []byte {
    limitedReader := io.LimitReader(body, int64(maxSize))
    data, _ := io.ReadAll(limitedReader)
    return data
}

// hashString создает хеш для сравнения
func hashString(s []byte) string {
    h := sha256.Sum256(s)
    return hex.EncodeToString(h[:8]) // first 8 bytes enough for comparison
}

// Helper: strings.ContainsAny
func stringsContainsAny(s string, patterns ...string) bool {
    for _, pattern := range patterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    return false
}
```

## 4. Response Comparison: `comparator.go`

### Паттерн: Strategy pattern для сравнения

```go
package verification

import (
    "fmt"
    "math"
)

// ResponseComparator сравнивает HTTP ответы
type ResponseComparator struct {
    // Пороги для определения "похожих" vs "разных"
    thresholds ComparatorThresholds
}

// ComparatorThresholds configurable thresholds
type ComparatorThresholds struct {
    // Минимальная похожесть для "похожих" responses (0.0-1.0)
    MinSimilarity float64

    // Максимальная разница в размере тела (0.0-1.0)
    MaxSizeDiffRatio float64

    // Максимальная разница в коде ответа
    MaxStatusDiff int

    // Максимальная разница во времени (ratio)
    MaxTimeDiffRatio float64
}

// DefaultComparatorThresholds возвращает настройки по умолчанию
func DefaultComparatorThresholds() ComparatorThresholds {
    return ComparatorThresholds{
        MinSimilarity:    0.85, // 85% similar = statistically similar
        MaxSizeDiffRatio: 0.10, // within 10% size difference
        MaxStatusDiff:    100,  // status codes within 100
        MaxTimeDiffRatio: 0.50, // within 50% time difference
    }
}

// NewResponseComparator создает comparator
func NewResponseComparator() *ResponseComparator {
    return &ResponseComparator{
        thresholds: DefaultComparatorThresholds(),
    }
}

// ComparisonVerdict - вердикт сравнения
type ComparisonVerdict int

const (
    VerdictUnknown ComparisonVerdict = iota
    VerdictDifferent // Разные - скорее уязвимость
    VerdictSimilar   // Похожие - скорее безопасно
    VerdictInconclusive
)

func (cv ComparisonVerdict) String() string {
    switch cv {
    case VerdictDifferent:
        return "different"
    case VerdictSimilar:
        return "similar"
    case VerdictInconclusive:
        return "inconclusive"
    default:
        return "unknown"
    }
}

// ComparisonResult - результат сравнения
type ComparisonResult struct {
    // Вердикт
    Verdict ComparisonVerdict

    // Средняя похожесть (0.0-1.0)
    Similarity float64

    // Список различий (human-readable)
    Differences []string

    // Детали по каждому критерию
    Details ComparisonDetails
}

// ComparisonDetails - детальная информация
type ComparisonDetails struct {
    StatusDiff    int
    SizeDiffRatio float64
    BodyHashMatch bool
    TimeDiffRatio float64
}

// Compare сравнивает baseline с набором тестовых ответов
func (rc *ResponseComparator) Compare(
    baseline TestResponse,
    testResponses []TestResponse,
) ComparisonResult {

    if len(testResponses) == 0 {
        return ComparisonResult{
            Verdict:    VerdictInconclusive,
            Similarity: 0.0,
            Differences: []string{"no test responses to compare"},
        }
    }

    // Сравниваем baseline с каждым тестовым ответом
    totalSimilarity := 0.0
    allDifferences := make([]string, 0)

    for _, test := range testResponses {
        sim, diffs := rc.compareTwo(baseline, test)
        totalSimilarity += sim

        // Добавляем только уникальные различия
        for _, diff := range diffs {
            if !contains(allDifferences, diff) {
                allDifferences = append(allDifferences, diff)
            }
        }
    }

    avgSimilarity := totalSimilarity / float64(len(testResponses))

    // Определяем вердикт
    var verdict ComparisonVerdict
    if avgSimilarity < rc.thresholds.MinSimilarity {
        verdict = VerdictDifferent
    } else if avgSimilarity > 0.95 {
        verdict = VerdictSimilar
    } else {
        verdict = VerdictInconclusive
    }

    return ComparisonResult{
        Verdict:     verdict,
        Similarity:  avgSimilarity,
        Differences: allDifferences,
    }
}

// compareTwo сравнивает два ответа (all comparison logic здесь)
func (rc *ResponseComparator) compareTwo(a, b TestResponse) (
    similarity float64,
    differences []string,
) {

    // Система оценки: максимум 100 очков
    score := 0.0
    maxScore := 100.0

    // 1. Статус коды (25 очков)
    statusScore, statusDiff := rc.compareStatus(a.StatusCode, b.StatusCode)
    score += statusScore * 25.0
    if statusDiff != 0 {
        differences = append(differences,
            fmt.Sprintf("status code: %d vs %d", a.StatusCode, b.StatusCode))
    }

    // 2. Размер тела (25 очков)
    sizeScore, sizeRatio := rc.compareBodySize(a.BodySize, b.BodySize)
    score += sizeScore * 25.0
    if sizeRatio > rc.thresholds.MaxSizeDiffRatio {
        differences = append(differences,
            fmt.Sprintf("body size: %d vs %d bytes", a.BodySize, b.BodySize))
    }

    // 3. Хеш тела (25 очков)
    bodyScore := rc.compareBodyHash(a.BodyHash, b.BodyHash)
    score += bodyScore * 25.0
    if a.BodyHash != b.BodyHash {
        differences = append(differences, "body content differs")
    }

    // 4. Время ответа (15 очков)
    timeScore, timeRatio := rc.compareResponseTime(a.Duration, b.Duration)
    score += timeScore * 15.0
    if timeRatio > rc.thresholds.MaxTimeDiffRatio {
        differences = append(differences,
            fmt.Sprintf("response time: %v vs %v", a.Duration, b.Duration))
    }

    // 5. Content-Type (10 очков)
    ctScore := rc.compareContentType(a.Headers, b.Headers)
    score += ctScore * 10.0

    similarity = score / maxScore
    return similarity, differences
}

// compareStatus сравнивает HTTP status codes
func (rc *ResponseComparator) compareStatus(a, b int) (score float64, diff int) {
    diff = abs(a - b)

    if diff == 0 {
        return 1.0, 0 // Identical
    } else if diff < 50 {
        return 0.8, diff // Similar range
    } else if diff < 100 {
        return 0.5, diff // Different range
    }
    return 0.0, diff // Very different
}

// compareBodySize сравнивает размер тела
func (rc *ResponseComparator) compareBodySize(a, b int) (score float64, ratio float64) {
    maxSize := max(a, b)
    if maxSize == 0 {
        return 1.0, 0.0
    }

    diff := abs(a - b)
    ratio = float64(diff) / float64(maxSize)

    if ratio < 0.05 {
        return 1.0, ratio // Within 5%
    } else if ratio < rc.thresholds.MaxSizeDiffRatio {
        return 0.8, ratio // Within threshold
    }
    return 0.3, ratio // Significantly different
}

// compareBodyHash сравнивает хеши
func (rc *ResponseComparator) compareBodyHash(a, b string) float64 {
    if a == b {
        return 1.0
    }
    return 0.0
}

// compareResponseTime сравнивает время ответа
func (rc *ResponseComparator) compareResponseTime(a, b time.Duration) (score float64, ratio float64) {
    avg := (float64(a) + float64(b)) / 2.0
    if avg == 0 {
        return 1.0, 0.0
    }

    diff := abs(float64(a) - float64(b))
    ratio = diff / avg

    if ratio < 0.2 {
        return 1.0, ratio // Within 20%
    } else if ratio < rc.thresholds.MaxTimeDiffRatio {
        return 0.7, ratio // Within threshold
    }
    return 0.2, ratio // Very different (timing attack potential)
}

// compareContentType сравнивает Content-Type header
func (rc *ResponseComparator) compareContentType(a, b map[string]string) float64 {
    ctA := getHeader(a, "Content-Type")
    ctB := getHeader(b, "Content-Type")

    if ctA == ctB {
        return 1.0
    }

    // Проверяем совпадение основного типа (text/html vs text/html; charset=utf-8)
    if strings.Contains(ctA, ctB) || strings.Contains(ctB, ctA) {
        return 0.8
    }

    return 0.0
}

// Helper functions

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}

func absFloat(x float64) float64 {
    if x < 0 {
        return -x
    }
    return x
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func getHeader(headers map[string]string, key string) string {
    for k, v := range headers {
        if strings.EqualFold(k, key) {
            return v
        }
    }
    return ""
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
```

## 5. Security & Rate Limiting: `security.go`

### Паттерн: Defence in depth

```go
package verification

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"
)

// SecurityChecker проверяет безопасность запросов
type SecurityChecker struct {
    // Blocklist IP ranges (private, loopback, etc.)
    blocklistRanges []*net.IPNet
}

// NewSecurityChecker создает security checker
func NewSecurityChecker() *SecurityChecker {
    sc := &SecurityChecker{
        blocklistRanges: make([]*net.IPNet, 0),
    }

    // Add private IP ranges
    privateRanges := []string{
        "127.0.0.0/8",     // Loopback
        "10.0.0.0/8",      // Private
        "172.16.0.0/12",   // Private
        "192.168.0.0/16",  // Private
        "169.254.0.0/16",  // Link-local
        "::1/128",         // IPv6 loopback
        "fc00::/7",        // IPv6 private
        "fe80::/10",       // IPv6 link-local
    }

    for _, cidr := range privateRanges {
        _, ipNet, _ := net.ParseCIDR(cidr)
        if ipNet != nil {
            sc.blocklistRanges = append(sc.blocklistRanges, ipNet)
        }
    }

    return sc
}

// IsURLAllowed проверяет, разрешен ли URL для тестирования
func (sc *SecurityChecker) IsURLAllowed(rawURL string) bool {
    // Parse URL
    u, err := url.Parse(rawURL)
    if err != nil {
        return false
    }

    // Check scheme
    if u.Scheme != "http" && u.Scheme != "https" {
        return false
    }

    // Check host
    host := u.Hostname()
    if host == "" {
        return false
    }

    // Resolve IP (for SSRF prevention)
    ips, err := net.LookupIP(host)
    if err != nil {
        // Can't resolve - be safe and block
        return false
    }

    // Check if any resolved IP is in blocklist
    for _, ip := range ips {
        if sc.isBlockedIP(ip) {
            return false
        }
    }

    return true
}

// isBlockedIP проверяет, находится ли IP в blocklist
func (sc *SecurityChecker) isBlockedIP(ip net.IP) bool {
    for _, ipNet := range sc.blocklistRanges {
        if ipNet.Contains(ip) {
            return true
        }
    }
    return false
}

// FilterHeaders возвращает только безопасные заголовки
func (sc *SecurityChecker) FilterHeaders(headers map[string]string) map[string]string {
    safe := make(map[string]string)

    for k, v := range headers {
        if isSafeHeader(k) {
            safe[k] = v
        }
    }

    return safe
}

// SanitizeHeaders удаляет sensitive заголовки из ответа
func (sc *SecurityChecker) SanitizeHeaders(headers http.Header) map[string]string {
    safe := make(map[string]string)

    for k, vv := range headers {
        if isSafeHeader(k) {
            // Only include first value
            if len(vv) > 0 && !isSensitiveValue(vv[0]) {
                safe[k] = vv[0]
            }
        }
    }

    return safe
}

// isSafeHeader проверяет, безопасен ли заголовок для копирования
func isSafeHeader(name string) bool {
    lower := strings.ToLower(name)

    // Allow these headers
    safeHeaders := []string{
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "content-type",
        "content-length",
        "referer",
        "origin",
        "cache-control",
        "pragma",
        "expires",
    }

    for _, safe := range safeHeaders {
        if lower == safe {
            return true
        }
    }

    return false
}

// isSensitiveValue проверяет, содержит ли значение sensitive data
func isSensitiveValue(value string) bool {
    sensitivePatterns := []string{
        "authorization",
        "bearer",
        "basic",
        "token",
        "cookie",
        "session",
    }

    lower := strings.ToLower(value)
    for _, pattern := range sensitivePatterns {
        if strings.Contains(lower, pattern) {
            return true
        }
    }
    return false
}

// RateLimiter ограничивает запросы на хост
type RateLimiter struct {
    // Ограничение: N запросов в секунду
    rate     float64
    interval time.Duration

    // Состояние по хостам
    mu      sync.Mutex
    buckets map[string]*tokenBucket
}

// tokenBucket - bucket для token bucket algorithm
type tokenBucket struct {
    tokens     float64
    lastUpdate time.Time
}

// NewRateLimiter создает rate limiter
func NewRateLimiter(requestsPerSecond int, interval time.Duration) *RateLimiter {
    return &RateLimiter{
        rate:     float64(requestsPerSecond),
        interval: interval,
        buckets:  make(map[string]*tokenBucket),
    }
}

// Allow проверяет, можно ли выполнить запрос
func (rl *RateLimiter) Allow(rawURL string) bool {
    // Извлекаем hostname
    u, err := url.Parse(rawURL)
    if err != nil {
        return false
    }

    host := u.Hostname()
    if host == "" {
        return false
    }

    rl.mu.Lock()
    defer rl.mu.Unlock()

    // Получаем или создаем bucket
    bucket, exists := rl.buckets[host]
    if !exists {
        bucket = &tokenBucket{
            tokens:     rl.rate,
            lastUpdate: time.Now(),
        }
        rl.buckets[host] = bucket
    }

    // Обновляем tokens
    now := time.Now()
    elapsed := now.Sub(bucket.lastUpdate).Seconds()

    // Add tokens: rate * elapsed (don't exceed max)
    newTokens := bucket.tokens + (rl.rate * elapsed)
    bucket.tokens = math.Min(newTokens, rl.rate)
    bucket.lastUpdate = now

    // Проверяем, можно ли взять токен
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0
        return true
    }

    return false
}

// Helper: Hash sensitive data for logging
func hashSensitive(value string) string {
    h := sha256.Sum256([]byte(value))
    return hex.EncodeToString(h[:8])
}
```

## 6. Usage Example: Интеграция в Analyzer

### Как использовать в `analyzer.go`

```go
package driven

import (
    "context"
    "github.com/BetterCallFirewall/Hackerecon/internal/verification"
)

// В GenkitSecurityAnalyzer добавляем:
type GenkitSecurityAnalyzer struct {
    // ... existing fields

    verifier verification.Verifier
}

// В NewGenkitSecurityAnalyzer:
func NewGenkitSecurityAnalyzer(...) (*GenkitSecurityAnalyzer, error) {
    analyzer := &GenkitSecurityAnalyzer{
        // ... existing initialization
    }

    // Создаем verifier
    verifierCfg := verification.Config{
        MaxConcurrency:    5,
        RequestsPerSecond: 10,
    }
    analyzer.verifier = verification.NewSafeVerifier(verifierCfg)

    return analyzer, nil
}

// broadcastAnalysisResult обновляем:
func (analyzer *GenkitSecurityAnalyzer) broadcastAnalysisResult(
    req *http.Request,
    resp *http.Response,
    result *models.SecurityAnalysisResponse,
    reqBody, respBody string,
) {
    // Broadcast initial result immediately (fast response)
    analyzer.WsHub.Broadcast(models.ReportDTO{
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
            // ...
        },
        VerificationStatus: "in_progress", // New field!
    })

    // Запускаем верификацию в background
    if result.HasVulnerability && len(result.SecurityChecklist) > 0 {
        go analyzer.verifyChecklistAsync(result, req, resp, reqBody, respBody)
    }
}

// verifyChecklistAsync выполняет верификацию асинхронно
func (analyzer *GenkitSecurityAnalyzer) verifyChecklistAsync(
    result *models.SecurityAnalysisResponse,
    req *http.Request,
    resp *http.Response,
    reqBody, respBody string,
) {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // Convert to RequestResponseInfo
    originalReq := models.RequestResponseInfo{
        URL:         req.URL.String(),
        Method:      req.Method,
        StatusCode:  resp.StatusCode,
        ReqHeaders:  convertHeaders(req.Header),
        RespHeaders: convertHeaders(resp.Header),
        ReqBody:     reqBody,
        RespBody:    respBody,
    }

    // Verify all checklist items
    verifiedResults := analyzer.verifier.VerifyAll(ctx, result.SecurityChecklist, originalReq)

    // Apply verification results
    updatedChecklist := applyVerificationResults(result.SecurityChecklist, verifiedResults)

    // Update result
    result.SecurityChecklist = updatedChecklist

    // Recalculate confidence
    result.ConfidenceScore = recalculateConfidence(verifiedResults)

    // Broadcast updated result
    analyzer.WsHub.Broadcast(models.ReportDTO{
        Report: models.VulnerabilityReport{
            ID:             result.ID,
            AnalysisResult: *result,
        },
        VerificationStatus: "completed",
        VerificationResults: verifiedResults, // New field!
    })
}

// applyVerificationResults обновляет чек-лист результатами проверки
func applyVerificationResults(
    checklist []models.SecurityCheckItem,
    results []verification.VerificationResult,
) []models.SecurityCheckItem {

    updated := make([]models.SecurityCheckItem, len(checklist))

    for i, item := range checklist {
        if i < len(results) {
            result := results[i]

            // Создаем копию
            updatedItem := item

            // Применяем изменение уверенности
            updatedItem.Confidence *= result.ConfidenceChange

            // Добавляем пометки
            switch result.VerificationStatus {
            case verification.StatusVerified:
                updatedItem.VerificationStatus = "✅ Confirmed"
                updatedItem.VerificationNote = result.Reasoning

            case verification.StatusLikelySafe:
                updatedItem.VerificationStatus = "❌ Likely False Positive"
                updatedItem.VerificationNote = result.Reasoning
                updatedItem.IsLikelyFalsePositive = true

            case verification.StatusInconclusive:
                updatedItem.VerificationStatus = "⚠️ Inconclusive"
                updatedItem.VerificationNote = result.Reasoning
            }

            updated[i] = updatedItem
        } else {
            updated[i] = item
        }
    }

    return updated
}

// recalculateConfidence пересчитывает общую уверенность
func recalculateConfidence(results []verification.VerificationResult) float64 {
    if len(results) == 0 {
        return 0.5
    }

    total := 0.0
    for _, r := range results {
        total += r.ConfidenceChange
    }

    return total / float64(len(results))
}
```

## 7. Testing Patterns

### Table-driven tests

```go
func TestVerifyHypothesis(t *testing.T) {
    tests := []struct {
        name        string
        hypothesis  models.SecurityCheckItem
        originalReq models.RequestResponseInfo
        wantStatus  VerificationStatus
        wantChange  float64
    }{
        {
            name: "SQLi vulnerability detected",
            hypothesis: models.SecurityCheckItem{
                Action:      "SQL Injection",
                Description: "User input in SQL query",
            },
            originalReq: models.RequestResponseInfo{
                URL:    "http://test.com/users?id=1",
                Method: "GET",
            },
            wantStatus: StatusVerified,
            wantChange: 1.3,
        },
        {
            name: "IDOR false positive",
            hypothesis: models.SecurityCheckItem{
                Action:      "IDOR",
                Description: "User ID in URL",
            },
            originalReq: models.RequestResponseInfo{
                URL:    "http://test.com/profile/123",
                Method: "GET",
            },
            wantStatus: StatusLikelySafe,
            wantChange: 0.6,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            verifier := NewSafeVerifier(Config{})
            ctx := context.Background()

            result := verifier.VerifyHypothesis(ctx, tt.hypothesis, tt.originalReq)

            if result.VerificationStatus != tt.wantStatus {
                t.Errorf("got status %v, want %v", result.VerificationStatus, tt.wantStatus)
            }

            if math.Abs(result.ConfidenceChange-tt.wantChange) > 0.01 {
                t.Errorf("got confidence change %.2f, want %.2f", result.ConfidenceChange, tt.wantChange)
            }
        })
    }
}
```

### Mock testing

```go
type mockHTTPClient struct {
    responses map[string]*http.Response
    errors    map[string]error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
    url := req.URL.String()

    if err, ok := m.errors[url]; ok {
        return nil, err
    }

    if resp, ok := m.responses[url]; ok {
        return resp, nil
    }

    return &http.Response{
        StatusCode: 200,
        Body:       io.NopCloser(strings.NewReader("OK")),
    }, nil
}

func TestWithMockClient(t *testing.T) {
    // Setup mock
    mock := &mockHTTPClient{
        responses: map[string]*http.Response{
            "http://test.com/users?id=1": {
                StatusCode: 200,
                Body:       io.NopCloser(strings.NewReader("User data")),
            },
            "http://test.com/users?id=1' AND '1'='1": {
                StatusCode: 200,
                Body:       io.NopCloser(strings.NewReader("User data")),
            },
            "http://test.com/users?id=1' AND '1'='0": {
                StatusCode: 200,
                Body:       io.NopCloser(strings.NewReader("No user")),
            },
        },
    }

    config := Config{
        HTTPClient: mock,
    }

    verifier := NewSafeVerifier(config)
    // ... test verification
}
```

## 8. Best Practices

### ✅ Что делать:

1. **Используйте интерфейсы** для тестируемости
2. **Dependency injection** вместо глобальных переменных
3. **Контексты с timeout** для отмены долгих операций
4. **Rate limiting** для безопасности
5. **Immutable data** - возвращайте новые структуры
6. **Early returns** для читаемости
7. **Table-driven tests** для покрытия кейсов

### ❌ Чего избегать:

1. **Shell execution** - это security nightmare
2. **Глобальное состояние** - делает тесты нестабильными
3. **Magic numbers** - вынесите в константы/конфиг
4. **Deep nesting** - используйте early returns
5. **Panic в production code** - возвращайте errors
6. **Log sensitive data** - используйте хеши

## 9. Summary

Эти примеры показывают:

1. **Layered architecture** с clear separation of concerns
2. **Security by design** - отдельный слой security checks
3. **Testability** - интерфейсы и dependency injection
4. **Performance** - parallel execution с rate limiting
5. **Observability** - логирование и execution logs

Главный принцип: **keep it simple, but not simpler**. Rule-based payloads предсказуемее и безопаснее LLM-generated команд.
