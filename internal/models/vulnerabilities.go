package models

import (
	"time"
)

// VulnerabilityReport полный отчет о уязвимости
type VulnerabilityReport struct {
	ID             string                   `json:"id" jsonschema:"description=Unique report ID"`
	Timestamp      time.Time                `json:"timestamp" jsonschema:"description=Report timestamp"`
	AnalysisResult SecurityAnalysisResponse `json:"analysis_result" jsonschema:"description=LLM analysis result"`
}

// SecurityAnalysisResponse структурированный ответ от LLM (только данные для анализа)
type SecurityAnalysisResponse struct {
	Summary         string          `json:"summary" jsonschema:"description=One sentence summary of the endpoint"`
	Findings        []Finding       `json:"findings" jsonschema:"description=List of findings (max 5)"`
	ContextForLater ContextForLater `json:"context_for_later" jsonschema:"description=Context for future analysis"`
}

// Finding - конкретная находка/проверка
type Finding struct {
	Title                string        `json:"title" jsonschema:"description=Short title (concrete, not generic)"`
	Observation          string        `json:"observation" jsonschema:"description=What is visible in the traffic"`
	TestRequests         []TestRequest `json:"test_requests" jsonschema:"description=List of test requests (1-5)"`
	ExpectedIfVulnerable string        `json:"expected_if_vulnerable" jsonschema:"description=What we'll see if vulnerable"`
	ExpectedIfSafe       string        `json:"expected_if_safe" jsonschema:"description=What we'll see if protected"`
	Effort               string        `json:"effort" jsonschema:"enum=low,enum=medium,enum=high,description=Effort to test"`
	Impact               string        `json:"impact" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Impact if exploited"`

	// IMPORTANT FIX: Index in original findings array for O(1) lookup
	OriginalIndex int `json:"-"` // Internal field, not exposed to JSON

	// Verification results
	VerificationStatus string `json:"verification_status,omitempty" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Auto-verification status"`
	VerificationReason string `json:"verification_reason,omitempty" jsonschema:"description=Why this status was assigned"`
}

// ContextForLater - контекст для дальнейшего анализа
type ContextForLater struct {
	IdentifiedPatterns []string `json:"identified_patterns,omitempty" jsonschema:"description=Patterns identified for SiteContext"`
	RelatedEndpoints   []string `json:"related_endpoints,omitempty" jsonschema:"description=Related endpoints if visible"`
	UserRoleDetected   string   `json:"user_role_detected,omitempty" jsonschema:"enum=guest,enum=user,enum=admin,enum=unknown,description=User role detected"`
}

// SecurityCheckItem - элемент чеклиста для пентестера
type SecurityCheckItem struct {
	Action      string `json:"action" jsonschema:"description=Attack action name"`
	Description string `json:"description" jsonschema:"description=How to perform the attack"`
	Expected    string `json:"expected" jsonschema:"description=Expected result if vulnerable vs. if protected"`

	// Verification results (заполняется после проверки)
	VerificationStatus string  `json:"verification_status,omitempty" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Auto-verification status"`
	ConfidenceScore    float64 `json:"confidence_score,omitempty" jsonschema:"description=Confidence after verification (0.0-1.0),minimum=0,maximum=1"`
	VerificationReason string  `json:"verification_reason,omitempty" jsonschema:"description=Why this status was assigned"`
	RecommendedPOC     string  `json:"recommended_poc,omitempty" jsonschema:"description=Recommended proof-of-concept for manual testing"`
}

// VerificationRequest - запрос на верификацию гипотез
type VerificationRequest struct {
	OriginalRequest RequestResponseInfo `json:"original_request" jsonschema:"description=Original request being analyzed"`
	ChecklistItem   SecurityCheckItem   `json:"checklist_item" jsonschema:"description=Hypothesis to verify"`
	MaxAttempts     int                 `json:"max_attempts" jsonschema:"description=Max verification attempts"`
}

// VerificationResponse - результат верификации
type VerificationResponse struct {
	Status            string        `json:"status" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Verification status"`
	UpdatedConfidence float64       `json:"updated_confidence" jsonschema:"description=Updated confidence score (0.0-1.0)"`
	Reasoning         string        `json:"reasoning" jsonschema:"description=LLM reasoning about verification results"`
	TestAttempts      []TestAttempt `json:"test_attempts,omitempty" jsonschema:"description=Test attempts performed"`
	RecommendedPOC    string        `json:"recommended_poc,omitempty" jsonschema:"description=Recommended manual POC if needed"`
}

// TestAttempt - одна попытка верификации
type TestAttempt struct {
	RequestURL    string            `json:"request_url" jsonschema:"description=Test request URL"`
	RequestMethod string            `json:"request_method" jsonschema:"description=HTTP method used"`
	StatusCode    int               `json:"status_code" jsonschema:"description=Response status code"`
	ResponseSize  int               `json:"response_size" jsonschema:"description=Response body size in bytes"`
	ResponseBody  string            `json:"response_body" jsonschema:"description=First 1KB of response body for analysis"`
	Headers       map[string]string `json:"headers,omitempty" jsonschema:"description=Key response headers"`
	Error         string            `json:"error,omitempty" jsonschema:"description=Error if request failed"`
	Duration      string            `json:"duration" jsonschema:"description=Request duration"`
}

// ExtractedSecret найденный секрет или чувствительные данные
type ExtractedSecret struct {
	Type       string  `json:"type" jsonschema:"description=Type of secret (API key, token, etc.)"`
	Value      string  `json:"value" jsonschema:"description=Secret value (truncated for security)"`
	Context    string  `json:"context" jsonschema:"description=Context where secret was found"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0),minimum=0,maximum=1"`
	Location   string  `json:"location" jsonschema:"description=Where the secret was found (request/response)"`
}

// SecurityAnalysisRequest входные данные для анализа безопасности
type SecurityAnalysisRequest struct {
	URL           string            `json:"url" jsonschema:"description=Target URL for analysis"`
	Method        string            `json:"method" jsonschema:"description=HTTP method (GET, POST, etc.)"`
	Headers       map[string]string `json:"headers" jsonschema:"description=HTTP headers"`
	RequestBody   string            `json:"request_body,omitempty" jsonschema:"description=Request body content"`
	ResponseBody  string            `json:"response_body,omitempty" jsonschema:"description=Response body content"`
	ContentType   string            `json:"content_type" jsonschema:"description=Response content type"`
	ExtractedData ExtractedData     `json:"extracted_data" jsonschema:"description=Pre-extracted data from content"`

	SiteContext *SiteContext `json:"site_context" jsonschema:"description=Contextual information about the target site"`
}

// ExtractedData данные, извлеченные из контента перед анализом
// Упрощенная версия после рефакторинга - оставлено только то, что сложно найти LLM
type ExtractedData struct {
	FormActions []string `json:"form_actions" jsonschema:"description=Form action URLs"`
	Comments    []string `json:"comments" jsonschema:"description=HTML comments"`
}

// Структуры для двухэтапного анализа

// URLAnalysisRequest запрос для быстрой оценки URL
type URLAnalysisRequest struct {
	URL          string            `json:"url" jsonschema:"description=URL to analyze"`
	Method       string            `json:"method" jsonschema:"description=HTTP method"`
	Headers      map[string]string `json:"headers" jsonschema:"description=HTTP headers"`
	ResponseBody string            `json:"response_body" jsonschema:"description=Response body content"`
	ContentType  string            `json:"content_type" jsonschema:"description=Response content type"`
	SiteContext  *SiteContext      `json:"site_context" jsonschema:"description=Current site context"`
}

// URLAnalysisResponse ответ быстрой оценки URL
type URLAnalysisResponse struct {
	InterestLevel   string           `json:"interest_level" jsonschema:"enum=high,enum=medium,enum=low,description=Interest level for analysis"`
	EndpointType    string           `json:"endpoint_type" jsonschema:"enum=auth,enum=api,enum=admin,enum=crud,enum=static,enum=unknown,description=Type of endpoint"`
	Observations    []string         `json:"observations" jsonschema:"description=Concrete observations from request/response"`
	SuggestedChecks []SuggestedCheck `json:"suggested_checks" jsonschema:"description=What to check and how"`
	DetectedTech    DetectedTech     `json:"detected_tech" jsonschema:"description=Detected technologies"`
	Tags            []string         `json:"tags" jsonschema:"description=Tags for grouping"`
	URLNote         *URLNote         `json:"url_note" jsonschema:"description=AI-generated note about this URL"`
}

// SuggestedCheck - проверка для выполнения
type SuggestedCheck struct {
	What string `json:"what" jsonschema:"description=What to check"`
	How  string `json:"how" jsonschema:"description=How to check (concrete request)"`
	Why  string `json:"why" jsonschema:"description=Why this is interesting"`
}

// DetectedTech - обнаруженные технологии
type DetectedTech struct {
	Database string `json:"database" jsonschema:"description=Detected database"`
	Backend  string `json:"backend" jsonschema:"description=Detected backend framework"`
	Evidence string `json:"evidence" jsonschema:"description=Evidence for detection"`
}

// HypothesisRequest запрос для генерации гипотезы
type HypothesisRequest struct {
	SiteContext           *SiteContext           `json:"site_context" jsonschema:"description=Current site context"`
	SuspiciousPatterns    []*URLPattern          `json:"suspicious_patterns" jsonschema:"description=Suspicious URL patterns"`
	TechVulnerabilities   []string               `json:"tech_vulnerabilities" jsonschema:"description=Known vulnerabilities in detected tech"`
	PreviousHypothesis    *SecurityHypothesis    `json:"previous_hypothesis,omitempty" jsonschema:"description=Previous hypothesis for comparison"`
	VerificationResults   *VerificationSummary   `json:"verification_results,omitempty" jsonschema:"description=Results from verification phase"`
	CrossEndpointPatterns []CrossEndpointPattern `json:"cross_endpoint_patterns,omitempty" jsonschema:"description=Patterns affecting multiple endpoints"`
}

// VerificationSummary итоговая информация о результатах верификации
type VerificationSummary struct {
	TotalPatternsAnalyzed int      `json:"total_patterns_analyzed" jsonschema:"description=Total findings analyzed"`
	ConfirmedVulnerable   int      `json:"confirmed_vulnerable" jsonschema:"description=Findings confirmed as vulnerable"`
	ConfirmedSafe         int      `json:"confirmed_safe" jsonschema:"description=Findings confirmed as safe"`
	Inconclusive          int      `json:"inconclusive" jsonschema:"description=Inconclusive findings"`
	HighConfidenceMatches []string `json:"high_confidence_matches" jsonschema:"description=High confidence vulnerability matches"`
	RepeatingPatterns     []string `json:"repeating_patterns" jsonschema:"description=Patterns seen on multiple endpoints"`
}

// VerificationPlanRequest запрос к LLM для генерации плана верификации
type VerificationPlanRequest struct {
	Hypothesis      string              `json:"hypothesis" jsonschema:"description=Security hypothesis to verify"`
	OriginalRequest RequestResponseInfo `json:"original_request" jsonschema:"description=Original request being analyzed"`
	MaxAttempts     int                 `json:"max_attempts" jsonschema:"description=Maximum number of test attempts"`
	TargetURL       string              `json:"target_url" jsonschema:"description=Target URL for testing"`
	AdditionalInfo  string              `json:"additional_info" jsonschema:"description=Additional context for LLM"`
}

// VerificationPlanResponse ответ от LLM с планом верификации
type VerificationPlanResponse struct {
	TestRequests []TestRequest `json:"test_requests" jsonschema:"description=Generated test requests"`
	Reasoning    string        `json:"reasoning" jsonschema:"description=LLM reasoning for test generation"`
}

// TestRequest структура тестового запроса (для LLM)
type TestRequest struct {
	URL                  string            `json:"url" jsonschema:"description=Test request URL"`
	Method               string            `json:"method" jsonschema:"description=HTTP method"`
	Headers              map[string]string `json:"headers,omitempty" jsonschema:"description=Request headers"`
	Body                 string            `json:"body,omitempty" jsonschema:"description=Request body (for POST/PUT)"`
	Purpose              string            `json:"purpose" jsonschema:"description=What this specific test checks"`
	ExpectedIfVulnerable string            `json:"expected_if_vulnerable,omitempty" jsonschema:"description=Expected response if vulnerable"`
	ExpectedIfSafe       string            `json:"expected_if_safe,omitempty" jsonschema:"description=Expected response if protected"`
}

// TestResult результат выполнения тестового запроса
type TestResult struct {
	StatusCode   int
	ResponseBody string
	Headers      map[string]string
	Duration     time.Duration
	Error        string
}

// RequestData данные HTTP запроса
type RequestData struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// ResponseData данные HTTP ответа
type ResponseData struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// VerificationAnalysisRequest запрос к LLM для анализа результатов верификации
type VerificationAnalysisRequest struct {
	Hypothesis         string              `json:"hypothesis" jsonschema:"description=Original security hypothesis"`
	OriginalConfidence float64             `json:"original_confidence" jsonschema:"description=Original confidence score (0.0-1.0)"`
	TestResults        []TestAttempt       `json:"test_results" jsonschema:"description=Results of test attempts"`
	OriginalRequest    RequestResponseInfo `json:"original_request" jsonschema:"description=Original request context"`
}

// VerificationAnalysisResponse ответ от LLM с анализом результатов верификации
type VerificationAnalysisResponse struct {
	Status            string  `json:"status" jsonschema:"enum=verified,enum=likely_false,enum=inconclusive,enum=manual_check,description=Verification status"`
	UpdatedConfidence float64 `json:"updated_confidence" jsonschema:"description=Updated confidence score (0.0-1.0)"`
	Reasoning         string  `json:"reasoning" jsonschema:"description=LLM reasoning about verification results"`
	RecommendedPOC    string  `json:"recommended_poc,omitempty" jsonschema:"description=Recommended manual proof of concept"`
}

// BatchVerificationRequest запрос для батч-верификации нескольких findings
type BatchVerificationRequest struct {
	Findings        []FindingForBatchVerification `json:"findings" jsonschema:"description=Findings to verify"`
	OriginalRequest RequestResponseInfo           `json:"original_request" jsonschema:"description=Original HTTP request context"`
	TestResults     []TestRequestForBatch         `json:"test_results" jsonschema:"description=Results from all test attempts"`
}

// FindingForBatchVerification информация о finding для батч-верификации
type FindingForBatchVerification struct {
	Index                int    `json:"index" jsonschema:"description=Index in findings array"`
	Title                string `json:"title" jsonschema:"description=Finding title"`
	Observation          string `json:"observation" jsonschema:"description=What is visible"`
	ExpectedIfVulnerable string `json:"expected_if_vulnerable,omitempty" jsonschema:"description=Expected if vulnerable"`
	ExpectedIfSafe       string `json:"expected_if_safe,omitempty" jsonschema:"description=Expected if safe"`
}

// TestRequestForBatch stores test results for a specific finding
type TestRequestForBatch struct {
	FindingIndex int                  `json:"finding_index" jsonschema:"description=Index of finding in original array for O(1) lookup"`
	FindingURL   string               `json:"finding_url" jsonschema:"description=URL of the finding"`
	FindingTitle string               `json:"finding_title" jsonschema:"description=Title of the finding"`
	TestResults  []TestResultForBatch `json:"test_results" jsonschema:"description=Results of all tests for this finding"`
}

// TestResultForBatch is the result of ONE test attempt
type TestResultForBatch struct {
	TestIndex    int    `json:"test_index" jsonschema:"description=Index of test in the array"`
	StatusCode   int    `json:"status_code" jsonschema:"description=Response status code"`
	ResponseBody string `json:"response_body" jsonschema:"description=Response body (truncated)"`
	Error        string `json:"error,omitempty" jsonschema:"description=Error if test failed"`
	Purpose      string `json:"purpose" jsonschema:"description=What this test was checking"`
}

// BatchVerificationResult результат батч-верификации
type BatchVerificationResult struct {
	BatchResults []FindingVerificationResult `json:"batch_results" jsonschema:"description=Results for each finding"`
}

// FindingVerificationResult результат верификации одного finding
type FindingVerificationResult struct {
	FindingIndex int     `json:"finding_index" jsonschema:"description=Index of finding"`
	Status       string  `json:"status" jsonschema:"enum=verified,enum=likely_true,enum=likely_false,enum=inconclusive,description=Verification status"`
	Confidence   float64 `json:"confidence" jsonschema:"description=Confidence score (0.0-1.0)"`
	Reasoning    string  `json:"reasoning" jsonschema:"description=Detailed reasoning"`
}

// HypothesisResponse - ответ на запрос генерации гипотез
type HypothesisResponse struct {
	InvestigationSuggestions []InvestigationSuggestion `json:"investigation_suggestions" jsonschema:"description=Suggested investigations"`
	SiteUnderstanding        SiteUnderstanding         `json:"site_understanding" jsonschema:"description=Understanding of the site"`
}
