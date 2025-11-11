package models

import (
	"time"
)

// VulnerabilityReport полный отчет о уязвимости
type VulnerabilityReport struct {
	ID             string                   `json:"id" jsonschema:"description=Unique report ID"`
	Timestamp      time.Time                `json:"timestamp" jsonschema:"description=Report timestamp"`
	AnalysisResult SecurityAnalysisResponse `json:"analysis_result" jsonschema:"description=LLM analysis result"`
	ProcessingTime time.Duration            `json:"-" jsonschema:"description=Time taken for analysis"`
}

// SecurityAnalysisResponse структурированный ответ от LLM
type SecurityAnalysisResponse struct {
	HasVulnerability   bool                `json:"has_vulnerability" jsonschema:"description=Indicates if a vulnerability was found"`
	RiskLevel          string              `json:"risk_level" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Risk level assessment"`
	AIComment          string              `json:"ai_comment" jsonschema:"description=AI analysis comment and explanation"`
	SecurityChecklist  []SecurityCheckItem `json:"security_checklist,omitempty" jsonschema:"description=Manual verification checklist for found vulnerabilities"`
	VulnerabilityTypes []string            `json:"vulnerability_types,omitempty" jsonschema:"description=List of detected vulnerability types"`
	ConfidenceScore    float64             `json:"confidence_score,omitempty" jsonschema:"description=Confidence in analysis (0.0-1.0)"`
	ExtractedSecrets   []ExtractedSecret   `json:"extracted_secrets,omitempty" jsonschema:"description=Found secrets and sensitive data"`
	Timestamp          time.Time           `json:"timestamp" jsonschema:"description=Analysis timestamp"`

	IdentifiedUserRole    string       `json:"identified_user_role,omitempty" jsonschema:"description=The user role identified in this request (e.g., 'guest', 'user', 'admin')"`
	IdentifiedDataObjects []DataObject `json:"-" jsonschema:"description=Data objects and their fields found in the request/response"`
}

// SecurityCheckItem - элемент чеклиста для ручной проверки уязвимости
type SecurityCheckItem struct {
	Action      string `json:"action" jsonschema:"description=Test action to verify the vulnerability"`
	Description string `json:"description" jsonschema:"description=What to check and why"`
	Expected    string `json:"expected" jsonschema:"description=Expected secure behavior if properly protected"`
}

// ExtractedSecret найденный секрет или чувствительные данные
type ExtractedSecret struct {
	Type       string  `json:"type" jsonschema:"description=Type of secret (API key, token, etc.)"`
	Value      string  `json:"value" jsonschema:"description=Secret value (truncated for security)"`
	Context    string  `json:"context" jsonschema:"description=Context where secret was found"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0)"`
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
type ExtractedData struct {
	URLs          []string          `json:"urls" jsonschema:"description=Extracted URLs"`
	APIKeys       []ExtractedSecret `json:"api_keys" jsonschema:"description=Found API keys"`
	Secrets       []ExtractedSecret `json:"secrets" jsonschema:"description=Other secrets found"`
	JSFunctions   []JSFunction      `json:"js_functions" jsonschema:"description=JavaScript functions found"`
	FormActions   []string          `json:"form_actions" jsonschema:"description=Form action URLs"`
	Comments      []string          `json:"comments" jsonschema:"description=HTML/JS comments"`
	ExternalHosts []string          `json:"external_hosts" jsonschema:"description=External domains referenced"`
}

type DataObject struct {
	Name   string   `json:"name" jsonschema:"description=The name of the data object (e.g., 'user', 'order')"`
	Fields []string `json:"fields" jsonschema:"description=A list of fields found for this object (e.g., ['id', 'email', 'role'])"`
}
