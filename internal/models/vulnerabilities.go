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
	HasVulnerability   bool                `json:"has_vulnerability" jsonschema:"description=Indicates if a vulnerability was found"`
	RiskLevel          string              `json:"risk_level" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Risk level assessment"`
	AIComment          string              `json:"ai_comment" jsonschema:"description=AI analysis comment and explanation"`
	SecurityChecklist  []SecurityCheckItem `json:"security_checklist,omitempty" jsonschema:"description=Manual verification checklist for found vulnerabilities"`
	VulnerabilityTypes []string            `json:"vulnerability_types,omitempty" jsonschema:"description=List of detected vulnerability types"`
	ConfidenceScore    float64             `json:"confidence_score,omitempty" jsonschema:"description=Confidence in analysis (0.0-1.0),minimum=0,maximum=1"`
	ExtractedSecrets   []ExtractedSecret   `json:"extracted_secrets,omitempty" jsonschema:"description=Found secrets and sensitive data"`
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
	URLNote       *URLNote `json:"url_note" jsonschema:"description=AI-generated note about this URL"`
	ShouldAnalyze bool     `json:"should_analyze" jsonschema:"description=Whether this URL deserves full security analysis"`
	Priority      string   `json:"priority" jsonschema:"enum=low,enum=medium,enum=high,description=Analysis priority"`
}

// HypothesisRequest запрос для генерации гипотезы
type HypothesisRequest struct {
	SiteContext         *SiteContext        `json:"site_context" jsonschema:"description=Current site context"`
	SuspiciousPatterns  []*URLPattern       `json:"suspicious_patterns" jsonschema:"description=Suspicious URL patterns"`
	TechVulnerabilities []string            `json:"tech_vulnerabilities" jsonschema:"description=Known vulnerabilities in detected tech"`
	PreviousHypothesis  *SecurityHypothesis `json:"previous_hypothesis,omitempty" jsonschema:"description=Previous hypothesis for comparison"`
}

// HypothesisResponse ответ с генерированными гипотезами
type HypothesisResponse struct {
	AttackVectors []*SecurityHypothesis `json:"attack_vectors" jsonschema:"description=List of possible attack vectors sorted by priority"`
	Reasoning     string                `json:"reasoning" jsonschema:"description=AI reasoning behind the hypothesis"`
}

// Verification-related models for LLM-based verification

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
	URL     string            `json:"url" jsonschema:"description=Test request URL"`
	Method  string            `json:"method" jsonschema:"description=HTTP method"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"description=Request headers"`
	Body    string            `json:"body,omitempty" jsonschema:"description=Request body (for POST/PUT)"`
	Purpose string            `json:"purpose" jsonschema:"description=Purpose of this test request"`
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
