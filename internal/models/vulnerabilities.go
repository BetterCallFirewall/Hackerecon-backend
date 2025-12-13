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

// SecurityCheckItem - элемент чеклиста для пентестера (как эксплуатировать уязвимость)
type SecurityCheckItem struct {
	Action      string `json:"action" jsonschema:"description=Attack action name (e.g., 'IDOR via ID substitution')"`
	Description string `json:"description" jsonschema:"description=How to perform the attack (specific HTTP request)"`
	Expected    string `json:"expected" jsonschema:"description=Expected result if vulnerable vs. if protected"`
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
