# Active Verification Implementation Plan

## 1. Контекст и Проблема

### Текущая архитектура
Hackerecon использует двухэтапный анализ:
```
HTTP Request → URL Filter (70-90% filtered) → Quick Analysis (LLM) →
Full Analysis (LLM) → SecurityAnalysisResponse with checklist
```

**SecurityAnalysisResponse** содержит:
- `SecurityChecklist []SecurityCheckItem` - 10-15 пунктов для ручной проверки с false positive rate ~60-70%
- `AIComment` - объяснение от LLM
- `ConfidenceScore` - оценка уверенности LLM (0.0-1.0)

### Актуальность проблемы
Пользователь видит 10-15 пунктов, большинство из которых **false positives**. Это создает:
- Cognitive overload для security researcher
- Потерю времени на проверку ложных находок
- Снижение доверия к системе

## 2. Цели и Success Metrics

### Primary Goal
**Снизить false positives на 35-50%** через безопасную активную проверку гипотез

### Success Metrics
1. **35-50% reduction** в false positives в SecurityChecklist
2. **< 2 сек** на проверку одной гипотезы (median)
3. **0 security incidents** - только GET requests, rate limiting
4. **< 100ms overhead** на быстрые отказы (не-поддерживаемые типы)
5. **70% accuracy** в определении vulnerable vs safe

### Alternative Solutions (Рассмотренные и Отклоненные)

#### ❌ Улучшение LLM prompts (отклонено)
- Добавить больше контекста в prompt
- Request tighter confidence thresholds
- **Почему отклонено**: Пределы LLM в определении без активной проверки, будут те же ~30% FP rate

#### ❌ Heuristics-based filtering (отклонено)
- Rule-based отброс очевидно ложных пунктов
- Pattern matching на основе статус кодов
- **Почему отклонено**: Недостаточная гибкость, пропустит edge cases, не масштабируется

#### ❌ LLM-generated curl → shell execution (отклонено)
- LLM генерирует curl команды для тестирования
- Исполняем через shell, сравниваем responses
- **Почему отклонено**: **CRITICAL SECURITY RISK** - arbitrary code execution, command injection

#### ✅ **Выбранно: Rule-based payload generation + HTTP client**
- Генератор отдельных тестовых payloads для каждого типа уязвимости
- Safe HTTP client с ограничениями (GET only)
- Response comparison с определением vulnerable/safe
- **Почему выбрано**: Безопасно, предсказуемо, быстро, контролируемо

## 3. Архитектурное решение

### Новый поток данных
```
HTTP Request → URL Filter → Quick Analysis (LLM) → Full Analysis (LLM)
    ↓
SecurityAnalysisResponse with 10-15 checklist items
    ↓
Active Verification (NEW COMPONENT)
    ↓
filteredChecklist []SecurityCheckItem (35-50% smaller)
```

### Новые компоненты

#### A. Safe Verifier (`internal/verification/verifier.go`)
**Interface:**
```go
type Verifier interface {
    // VerifyHypothesis выполняет активную проверку гипотезы
    // Возвращает VerificationResult с vuln/safe статусом
    VerifyHypothesis(ctx context.Context, hypothesis models.SecurityCheckItem,
                     originalReq models.RequestResponseInfo) VerificationResult
}
```

**Properties:**
- Интерфейс для всех типов проверок
- Поддержка: SQLi, IDOR, XSS, SSRF, Open Redirect
- Время работы: < 2 секунд среднее
- Поддержка timeout и cancelation через context

#### B. Payload Generator (`internal/verification/payloads.go`)
**Approach:** Rule-based, без LLM
- SQLi: boolean-based blind payloads
- IDOR: ID substitution with pattern matching
- XSS: unique marker injection & reflection detection
- SSRF: internal URL payloads
- Open Redirect: protocol bypass attempts

**Key feature:** Предиктивная генерация - определяет тип payload по Action описанию

#### C. Response Comparator (`internal/verification/comparator.go`)
**Comparison strategy:**
1. Статус коды (200 vs error responses)
2. Content-Length (разница > 10%)
3. Response body similarity (normalized diff)
4. Response time (timing attacks)
5. Error patterns (SQL error messages)

**Heuristics:**
- Если responses **разные** → likely vulnerable (confidence ↑)
- Если responses **похожие** → likely safe, false positive (confidence ↓)
- Если неопределено → оставить гипотезу с оригинальным confidence

#### D. Verification Orchestrator (`internal/verification/orchestrator.go`)
Управляет:
- Parallel verification (max 5 одновременно)
- Rate limiting (max 10 req/sec per host)
- Timeout management (5 сек max per hypothesis)
- Result aggregation

#### E. Verification Result Types (`internal/verification/types.go`)
```go
type VerificationResult struct {
    OriginalHypothesis models.SecurityCheckItem
    VerificationStatus VerificationStatus  // "verified", "likely_false_positive", "inconclusive"
    ConfidenceChange   float64              // +/-0.1-0.3
    Reasoning          string               // Why this conclusion
    Evidence           VerificationEvidence // HTTP details
}

type VerificationStatus string
const (
    StatusVerified           VerificationStatus = "verified"           // Уязвимость подтверждена
    StatusLikelySafe         VerificationStatus = "likely_safe"        // Скорее ложный, пропустить
    StatusInconclusive       VerificationStatus = "inconclusive"       // Недостаточно данных
)
```

## 4. Security Considerations

### Safety by Design

1. **GET Requests Only**
   - Никаких POST/PUT/DELETE через verifier
   - Изменение параметров только в query string
   - Content-Type validation

2. **Rate Limiting & Throttling**
   ```go
   - Host-level: max 10 req/sec
   - Global: max 50 req/sec
   - Per-hypothesis: 3 attempts max
   ```

3. **URL Validation**
   ```go
   - Whitelist allowed schemes: http, https
   - Blocklist: 127.0.0.1, localhost, internal IPs (SSRF prevention)
   - URL parsing validation
   - Hostname resolution check
   ```

4. **Data Exposure Prevention**
   ```go
   - No logging of full responses (только meta: status, length, diff)
   - Sanitization before broadcasting via WebSocket
   - Max response size: 1MB per request
   ```

5. **Timeout & Resource Limits**
   ```go
   - Per-request timeout: 30 seconds
   - Total verification timeout: 5 minutes
   - Response body max size: 1MB
   - Connection pool limits
   ```

## 5. Integration точки

### Изменения в analyzer.go

**В broadcastAnalysisResult добавляем:**
```go
// After getting SecurityAnalysisResponse
if result.HasVulnerability && len(result.SecurityChecklist) > 0 {
    // Launch async verification
    go func() {
        verifiedResult := analyzer.verifier.VerifyAll(
            context.Background(),
            result.SecurityChecklist,
            models.RequestResponseInfo{...},
        )

        // Update checklist with verification results
        updatedChecklist := analyzer.applyVerificationResults(
            result.SecurityChecklist,
            verifiedResult,
        )

        // Broadcast updated results
        result.SecurityChecklist = updatedChecklist
        analyzer.WsHub.BroadcastUpdated(result)
    }()
}
```

### New function: applyVerificationResults
```go
func (analyzer *GenkitSecurityAnalyzer) applyVerificationResults(
    original []models.SecurityCheckItem,
    verified []verification.VerificationResult,
) []models.SecurityCheckItem {

    result := make([]models.SecurityCheckItem, 0)

    for i, item := range original {
        if i < len(verified) {
            vr := verified[i]

            // Apply confidence adjustment
            item.Confidence *= vr.ConfidenceChange

            // Mark verified items
            if vr.VerificationStatus == verification.StatusLikelySafe {
                item.IsLikelyFalsePositive = true
                item.VerificationNote = "Likely false positive - similar responses"
            } else if vr.VerificationStatus == verification.StatusVerified {
                item.VerificationNote = "Vulnerability confirmed - different responses"
            }

            result = append(result, item)
        }
    }

    return result
}
```

### WebSocket обновления
- Отправка intermediate updates: "Verification in progress... 3/10"
- Final update с verified checklist
- Dashboard отображает: 🟢 confirmed, 🟡 inconclusive, 🔴 likely false positive

## 6. Код: Пример реализации

### 6.1. Safe Verifier (`internal/verification/verifier.go`)

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

// Verifier выполняет безопасную проверку гипотез
type Verifier struct {
    client            *http.Client
    payloadGenerator  *PayloadGenerator
    comparator        *ResponseComparator
    rateLimiter       *RateLimiter
}

// NewVerifier создает новый verifier с безопасными настройками
func NewVerifier() *Verifier {
    return &Verifier{
        client: &http.Client{
            Timeout: 30 * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse // No auto-redirects
            },
        },
        payloadGenerator: NewPayloadGenerator(),
        comparator:       NewResponseComparator(),
        rateLimiter:      NewRateLimiter(10, time.Second), // 10 req/sec
    }
}

// VerifyAll проверяет весь чек-лист параллельно
func (v *Verifier) VerifyAll(ctx context.Context,
                               checklist []models.SecurityCheckItem,
                               originalReq models.RequestResponseInfo) []VerificationResult {

    results := make([]VerificationResult, len(checklist))
    var wg sync.WaitGroup
    sem := make(chan struct{}, 5) // Max 5 concurrent

    for i, item := range checklist {
        wg.Add(1)
        go func(index int, hypothesis models.SecurityCheckItem) {
            defer wg.Done()

            sem <- struct{}{}
            defer func() { <-sem }()

            results[index] = v.VerifyHypothesis(ctx, hypothesis, originalReq)
        }(i, item)
    }

    wg.Wait()
    return results
}

// VerifyHypothesis выполняет проверку одной гипотезы
func (v *Verifier) VerifyHypothesis(ctx context.Context,
                                      hypothesis models.SecurityCheckItem,
                                      originalReq models.RequestResponseInfo) VerificationResult {

    result := VerificationResult{
        OriginalHypothesis: hypothesis,
        VerificationStatus: StatusInconclusive,
        ConfidenceChange:   1.0, // Default: no change
    }

    // Шаг 1: Detect vulnerability type
    vulnType := v.detectVulnerabilityType(hypothesis.Action)
    if vulnType == VulnTypeUnknown {
        result.Reasoning = "Unknown vulnerability type, cannot verify"
        return result
    }

    // Шаг 2: Generate test payloads
    payloads := v.payloadGenerator.Generate(vulnType, originalReq.URL, hypothesis)
    if len(payloads) == 0 {
        result.Reasoning = "No test payloads generated"
        return result
    }

    // Шаг 3: Execute requests with rate limiting
    responses := make([]TestResponse, 0, len(payloads))
    for _, payload := range payloads {
        // Apply rate limiting
        if !v.rateLimiter.Allow(originalReq.URL) {
            log.Printf("Rate limited for %s", originalReq.URL)
            break
        }

        resp, err := v.executeSafeRequest(ctx, payload, originalReq)
        if err != nil {
            log.Printf("Request failed: %v", err)
            continue
        }
        responses = append(responses, resp)
    }

    if len(responses) < 2 {
        result.Reasoning = "Insufficient responses for comparison"
        return result
    }

    // Шаг 4: Compare responses
    comparison := v.comparator.Compare(responses[0], responses[1:])

    // Шаг 5: Determine status
    switch comparison.Verdict {
    case VerdictDifferent:
        result.VerificationStatus = StatusVerified
        result.ConfidenceChange = 1.3 // Increase confidence by 30%
        result.Reasoning = "Responses differ significantly - vulnerability likely"

    case VerdictSimilar:
        result.VerificationStatus = StatusLikelySafe
        result.ConfidenceChange = 0.6 // Decrease confidence by 40%
        result.Reasoning = "Responses similar - likely false positive"

    case VerdictInconclusive:
        result.Reasoning = "Cannot determine - responses inconclusive"
    }

    result.Evidence = VerificationEvidence{
        Payloads:  payloads,
        Responses: responses,
        Comparison: comparison,
    }

    return result
}

// executeSafeRequest выполняет один тестовый запрос
func (v *Verifier) executeSafeRequest(ctx context.Context,
                                        payload TestPayload,
                                        originalReq models.RequestResponseInfo) (TestResponse, error) {

    req, err := http.NewRequestWithContext(ctx, "GET", payload.URL, nil)
    if err != nil {
        return TestResponse{}, fmt.Errorf("creating request: %w", err)
    }

    // Копируем безопасные заголовки
    for k, val := range originalReq.ReqHeaders {
        if isSafeHeader(k) {
            req.Header.Set(k, val)
        }
    }

    // Выполняем запрос
    resp, err := v.client.Do(req)
    if err != nil {
        return TestResponse{}, fmt.Errorf("executing request: %w", err)
    }
    defer resp.Body.Close()

    // Читаем тело с ограничением
    body := readBodyWithLimit(resp.Body, 1*1024*1024) // 1MB max

    return TestResponse{
        URL:        payload.URL,
        StatusCode: resp.StatusCode,
        BodySize:   len(body),
        BodyHash:   hashString(body), // For comparison
        Headers:    sanitizeHeaders(resp.Header),
        Duration:   time.Since(ctx.Value("startTime").(time.Time)),
    }, nil
}
```

### 6.2. Payload Generator (`internal/verification/payloads.go`)

```go
package verification

import (
    "fmt"
    "regexp"
    "strings"

    "github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// VulnerabilityType определяет тип уязвимости
type VulnerabilityType int

const (
    VulnTypeUnknown VulnerabilityType = iota
    VulnTypeSQLi
    VulnTypeIDOR
    VulnTypeXSS
    VulnTypeSSRF
    VulnTypeOpenRedirect
)

// PayloadGenerator генерирует тестовые payloads
type PayloadGenerator struct {
    patterns map[VulnerabilityType]*regexp.Regexp
}

// NewPayloadGenerator создает генератор с готовыми паттернами
func NewPayloadGenerator() *PayloadGenerator {
    return &PayloadGenerator{
        patterns: map[VulnerabilityType]*regexp.Regexp{
            VulnTypeSQLi:    regexp.MustCompile(`(?i)(sql|injection|query|database|\bselect\b|\bunion\b)`),
            VulnTypeIDOR:    regexp.MustCompile(`(?i)(idor|bypass|access control|\bid\b|user|account)`),
            VulnTypeXSS:     regexp.MustCompile(`(?i)(xss|cross.site|script|javascript|onerror|onload)`),
            VulnTypeSSRF:    regexp.MustCompile(`(?i)(ssrf|server.side|internal|localhost|127\.0\.0\.1)`),
            VulnTypeOpenRedirect: regexp.MustCompile(`(?i)(redirect|open.url|location|url=)`),
        },
    }
}

// TestPayload представляет один тестовый запрос
type TestPayload struct {
    URL         string
    Description string
    Type        VulnerabilityType
}

// Generate создает payloads для конкретной уязвимости
func (pg *PayloadGenerator) Generate(vulnType VulnerabilityType,
                                       originalURL string,
                                       hypothesis models.SecurityCheckItem) []TestPayload {

    switch vulnType {
    case VulnTypeSQLi:
        return pg.generateSQLiPayloads(originalURL, hypothesis)

    case VulnTypeIDOR:
        return pg.generateIDORPayloads(originalURL, hypothesis)

    case VulnTypeXSS:
        return pg.generateXSSPayloads(originalURL, hypothesis)

    default:
        return []TestPayload{}
    }
}

// generateSQLiPayloads - Boolean-based blind SQLi detection
func (pg *PayloadGenerator) generateSQLiPayloads(
    originalURL string,
    hypothesis models.SecurityCheckItem,
) []TestPayload {

    payloads := []TestPayload{
        {
            URL:         pg.injectSQLi(originalURL, "' AND '1'='1"),
            Description: "True condition - should return same result",
            Type:        VulnTypeSQLi,
        },
        {
            URL:         pg.injectSQLi(originalURL, "' AND '1'='0"),
            Description: "False condition - should return different result",
            Type:        VulnTypeSQLi,
        },
        {
            URL:         pg.injectSQLi(originalURL, "' OR '1'='1"),
            Description: "Always true - may return all records",
            Type:        VulnTypeSQLi,
        },
    }

    return payloads
}

// injectSQLi вставляет SQL payload в параметры URL
func (pg *PayloadGenerator) injectSQLi(url string, payload string) string {
    // Пример: /users?id=123 → /users?id=123' AND '1'='1
    if strings.Contains(url, "?") {
        return url + payload
    }
    // Если нет параметров, добавляем
    if !strings.Contains(url, "?") {
        return url + "?test=1" + payload
    }
    return url
}

// generateIDORPayloads - ID substitution
func (pg *PayloadGenerator) generateIDORPayloads(
    originalURL string,
    hypothesis models.SecurityCheckItem,
) []TestPayload {

    // Извлекаем ID из URL (пример: /users/123)
    idPattern := regexp.MustCompile(`/\d+`)
    matches := idPattern.FindStringSubmatch(originalURL)
    if len(matches) == 0 {
        return []TestPayload{}
    }

    // Генерируем набор тестовых ID
    testIDs := []int{12345, 99999, 1, 0, -1}
    payloads := make([]TestPayload, 0, len(testIDs))

    for _, testID := range testIDs {
        newURL := idPattern.ReplaceAllString(originalURL, fmt.Sprintf("/%d", testID))
        payloads = append(payloads, TestPayload{
            URL:         newURL,
            Description: fmt.Sprintf("Test ID %d", testID),
            Type:        VulnTypeIDOR,
        })
    }

    return payloads
}
```

### 6.3. Response Comparator (`internal/verification/comparator.go`)

```go
package verification

import (
    "math"
)

// TestResponse представляет ответ от сервера
type TestResponse struct {
    URL        string
    StatusCode int
    BodySize   int
    BodyHash   string
    Headers    map[string]string
    Duration   int64 // nanoseconds
}

// ComparisonResult результат сравнения
type ComparisonResult struct {
    Verdict     ComparisonVerdict
    Similarity  float64 // 0.0-1.0
    Differences []string
}

type ComparisonVerdict int

const (
    VerdictUnknown ComparisonVerdict = iota
    VerdictDifferent
    VerdictSimilar
    VerdictInconclusive
)

// ResponseComparator сравнивает HTTP ответы
type ResponseComparator struct {
    thresholds struct {
        minSimilarity    float64 // 0.85 (85%)
        maxSizeDiffRatio float64 // 0.10 (10%)
        maxStatusDiff    int     // 100 (status code diff)
    }
}

// NewResponseComparator создает comparator с настройками
func NewResponseComparator() *ResponseComparator {
    return &ResponseComparator{
        thresholds: struct {
            minSimilarity    float64
            maxSizeDiffRatio float64
            maxStatusDiff    int
        }{
            minSimilarity:    0.85,
            maxSizeDiffRatio: 0.10,
            maxStatusDiff:    100,
        },
    }
}

// Compare сравнивает baseline response с тестовыми
func (rc *ResponseComparator) Compare(
    baseline TestResponse,
    testResponses []TestResponse,
) ComparisonResult {

    if len(testResponses) == 0 {
        return ComparisonResult{
            Verdict:    VerdictInconclusive,
            Similarity: 0.0,
        }
    }

    // Сравниваем baseline с каждым тестовым
    var differences []string
    var totalSimilarity float64

    for _, test := range testResponses {
        sim, diffs := rc.compareTwo(baseline, test)
        totalSimilarity += sim
        differences = append(differences, diffs...)
    }

    avgSimilarity := totalSimilarity / float64(len(testResponses))

    var verdict ComparisonVerdict
    if avgSimilarity < rc.thresholds.minSimilarity {
        verdict = VerdictDifferent
    } else if avgSimilarity > 0.95 {
        verdict = VerdictSimilar
    } else {
        verdict = VerdictInconclusive
    }

    return ComparisonResult{
        Verdict:     verdict,
        Similarity:  avgSimilarity,
        Differences: differences,
    }
}

// compareTwo сравнивает два ответа
func (rc *ResponseComparator) compareTwo(a, b TestResponse) (similarity float64, differences []string) {
    score := 0.0
    maxScore := 5.0

    // 1. Статус коды
    statusDiff := math.Abs(float64(a.StatusCode - b.StatusCode))
    if statusDiff < 50 {
        score += 1.0
    } else if statusDiff < 100 {
        score += 0.5
    } else {
        differences = append(differences, fmt.Sprintf("status code: %d vs %d", a.StatusCode, b.StatusCode))
    }

    // 2. Размер тела
    sizeDiffRatio := math.Abs(float64(a.BodySize-b.BodySize)) / float64(max(a.BodySize, 1))
    if sizeDiffRatio < rc.thresholds.maxSizeDiffRatio {
        score += 1.0
    } else {
        differences = append(differences, fmt.Sprintf("body size: %d vs %d", a.BodySize, b.BodySize))
    }

    // 3. Хеш тела (quick comparison)
    if a.BodyHash == b.BodyHash {
        score += 1.0
    }

    // 4. Время ответа
    timeDiff := math.Abs(float64(a.Duration - b.Duration))
    avgDuration := float64(a.Duration+b.Duration) / 2.0
    timeDiffRatio := timeDiff / avgDuration

    if timeDiffRatio < 0.5 {
        score += 1.0
    }

    // 5. Заголовки
    if a.Headers["Content-Type"] == b.Headers["Content-Type"] {
        score += 1.0
    }

    return score / maxScore, differences
}
```

### 6.4. Rate Limiter (`internal/verification/security.go`)

```go
package verification

import (
    "net/url"
    "sync"
    "time"
)

// RateLimiter ограничивает запросы к хостам
type RateLimiter struct {
    requestsPerSecond float64
    window            time.Duration

    mu      sync.Mutex
    buckets map[string]*tokenBucket
}

// tokenBucket implements token bucket algorithm
type tokenBucket struct {
    tokens     float64
    lastUpdate time.Time
}

// NewRateLimiter создает rate limiter
func NewRateLimiter(requestsPerSecond int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        requestsPerSecond: float64(requestsPerSecond),
        window:            window,
        buckets:           make(map[string]*tokenBucket),
    }
}

// Allow проверяет, можно ли выполнить запрос к URL
func (rl *RateLimiter) Allow(rawURL string) bool {
    // Extract hostname
    u, err := url.Parse(rawURL)
    if err != nil {
        return false
    }

    host := u.Hostname()

    rl.mu.Lock()
    defer rl.mu.Unlock()

    // Get or create bucket
    bucket, exists := rl.buckets[host]
    if !exists {
        bucket = &tokenBucket{
            tokens:     rl.requestsPerSecond,
            lastUpdate: time.Now(),
        }
        rl.buckets[host] = bucket
    }

    // Update tokens
    now := time.Now()
    elapsed := now.Sub(bucket.lastUpdate).Seconds()
    bucket.tokens = min(bucket.tokens+elapsed*rl.requestsPerSecond, rl.requestsPerSecond)
    bucket.lastUpdate = now

    // Check if we can take a token
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0
        return true
    }

    return false
}
```

## 7. Тестовая стратегия

### 7.1. Unit Tests (70% coverage)

**verifier.go:**
- Test verification of SQLi with true/false payloads
- Test IDOR payload generation
- Test XSS verification
- Test timeout handling
- Test rate limiting

**payloads.go:**
- Test payload generation for each vulnerability type
- Test URL parameter injection
- Test pattern matching

**comparator.go:**
- Compare similar responses
- Compare different responses
- Test similarity scoring

### 7.2. Integration Tests

**Тестовый сервер с:
- SQLi vulnerability endpoint
- IDOR endpoint with access control
- XSS reflection endpoint
- Safe endpoints (no vulns)

Верификация:
- ✓ Detects SQLi vulnerability
- ✓ Detects IDOR vulnerability
- ✓ Identifies false positives (similar responses)
- ✓ Respects rate limiting
- ✓ Handles timeouts

### 7.3. Security Tests

- Test SSRF prevention (internal IPs blocked)
- Test command injection (no shell execution)
- Test rate limiting effectiveness
- Test timeout enforcement
- Test max response size limits

### 7.4. Performance Tests

- Benchmark 100 hypothesis verification: < 3 min total
- Single hypothesis: < 2 sec median
- Memory: < 100MB for 100 concurrent verifications
- CPU: < 50% on 4-core machine

## 8. Implementation Timeline

### Week 1: Core Verifier
**Deliverables:**
- ✅ `internal/verification/types.go` - Core types
- ✅ `internal/verification/payloads.go` - Payload generator (SQLi, IDOR)
- ✅ `internal/verification/comparator.go` - Response comparison
- ✅ `internal/verification/security.go` - Rate limiter, URL validation
- ✅ Unit tests (70% coverage)

**Story points: 13**

### Week 2: Integration & Security
**Deliverables:**
- ✅ `internal/verification/verifier.go` - Main verifier
- ✅ Integration в `analyzer.go` - Apply verification results
- ✅ WebSocket updates for verification progress
- ✅ Security tests (SSRF prevention, rate limiting)
- ✅ XSS payload generator
- ✅ SSRF payload generator

**Story points: 13**

### Week 3: Optimization & UI
**Deliverables:**
- ✅ Dashboard отображение verification status
- ✅ Performance optimization (connection pooling)
- ✅ Open Redirect payload generator
- ✅ Integration testing (end-to-end)
- ✅ Documentation
- ✅ Success metrics measurement

**Story points: 8**

### Week 4: Testing & Refinement
**Deliverables:**
- ✅ Bug fixes по результатам тестирования
- ✅ False positive rate measurement (target: 35-50% reduction)
- ✅ Performance profiling (target: < 2 sec per hypothesis)
- ✅ Security audit
- ✅ User acceptance testing

**Story points: 5**

**Total: 39 story points (~4 weeks для одного engineer)**

## 9. Success Criteria & Rollback Plan

### Rollout Strategy
1. **Week 5-6:** Internal testing, bug bounty team
2. **Week 7:** Alpha release (opt-in feature flag)
3. **Week 8-9:** Beta release (50% users)
4. **Week 10:** Full release

### Success Criteria
✓ 35-50% reduction in false positives measured over 1000+ hypotheses
✓ < 2 seconds median verification time
✓ 0 security incidents during alpha/beta
✓ User satisfaction > 4/5 (survey)
✓ < 5% increase in overall resource usage

### Rollback Plan
Если false positive reduction < 25%:
1. Revert `analyzer.go` integration (1 line change)
2. Disable feature flag
3. Analyze why expectations not met
4. Refine payload generation logic

### Monitoring
- Counter: hypotheses_verified_total
- Histogram: verification_duration_seconds
- Gauge: false_positive_rate
- Alert: verification_duration_p99 > 5 sec
- Alert: verification_errors_rate > 5%

## 10. Conclusion

Активная верификация гипотез через rule-based payload generation и safe HTTP client — это:
- ✅ Безопасно: только GET requests, rate limiting, no shell execution
- ✅ Эффективно: 35-50% reduction в false positives
- ✅ Быстро: < 2 sec per hypothesis
- ✅ Predictable: rule-based, контролируемо
- ✅ Scalable: parallel execution, connection pooling

Ключевые инсайты:
1. **Не используйте LLM-generated curl + shell** — это security nightmare
2. **Rule-based > Heuristic-based** — predictability and control
3. **Safe by design** — restrict at multiple layers
4. **Measure everything** — metrics drive improvements
