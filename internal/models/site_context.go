package models

// SiteContext хранит накопленную информацию о целевом сайте (только для LLM анализа)
type SiteContext struct {
	Host        string                 `json:"host" jsonschema:"description=The target host/domain"`
	URLPatterns map[string]*URLPattern `json:"url_patterns" jsonschema:"description=Normalized URL patterns with AI notes"`
	TechStack   *TechStack             `json:"tech_stack,omitempty" jsonschema:"description=Detected technology stack"`
}

// NewSiteContext создает новый экземпляр контекста для сайта.
func NewSiteContext(host string) *SiteContext {
	return &SiteContext{
		Host:        host,
		URLPatterns: make(map[string]*URLPattern),
	}
}

// URLPattern представляет нормализованный паттерн URL с заметками (только для LLM)
type URLPattern struct {
	Pattern string    `json:"pattern" jsonschema:"description=Normalized URL pattern with placeholders"`
	Method  string    `json:"method" jsonschema:"enum=GET,enum=POST,enum=PUT,enum=DELETE,enum=PATCH,enum=OPTIONS,enum=HEAD,description=HTTP method"`
	Purpose string    `json:"purpose" jsonschema:"description=Purpose of this endpoint (e.g., 'User profile viewing')"`
	Notes   []URLNote `json:"notes" jsonschema:"description=Historical notes about this URL pattern (max 100)"`
}

// URLNote содержит заметку LLM о URL (только для анализа)
type URLNote struct {
	Content    string  `json:"content" jsonschema:"description=Note content describing the URL purpose"`
	Suspicious bool    `json:"suspicious" jsonschema:"description=Whether this URL looks suspicious"`
	VulnHint   string  `json:"vuln_hint,omitempty" jsonschema:"description=Hint about potential vulnerability"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence level (0.0-1.0)"`
}

// TechStack содержит список обнаруженных технологий (упрощенная версия для LLM)
type TechStack struct {
	Technologies []Technology `json:"technologies" jsonschema:"description=List of detected technologies"`
}

// Technology представляет обнаруженную технологию (упрощенная версия для LLM)
type Technology struct {
	Name       string  `json:"name" jsonschema:"description=Technology name with version (e.g., 'React 18.2', 'PostgreSQL 14')"`
	Reason     string  `json:"reason" jsonschema:"description=Why this technology was detected"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0)"`
}

// SecurityHypothesis представляет гипотезу об уязвимости (только для LLM анализа)
type SecurityHypothesis struct {
	Title          string       `json:"title" jsonschema:"description=Hypothesis title"`
	Description    string       `json:"description" jsonschema:"description=Detailed description"`
	AttackVector   string       `json:"attack_vector" jsonschema:"description=Type of attack vector"`
	TargetURLs     []string     `json:"target_urls" jsonschema:"description=URLs to investigate for this hypothesis"`
	AttackSequence []AttackStep `json:"attack_sequence" jsonschema:"description=Step-by-step attack plan"`
	Confidence     float64      `json:"confidence" jsonschema:"description=Hypothesis confidence (0.0-1.0)"`
	Impact         string       `json:"impact" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Potential impact"`
	Effort         string       `json:"effort" jsonschema:"enum=low,enum=medium,enum=high,description=Effort required to exploit"`
}

// AttackStep описывает один шаг в атаке для пентестера
type AttackStep struct {
	Step        int    `json:"step" jsonschema:"description=Step number in sequence"`
	Action      string `json:"action" jsonschema:"description=Attack action name"`
	Description string `json:"description" jsonschema:"description=How to perform this step (specific HTTP request)"`
	Expected    string `json:"expected" jsonschema:"description=Expected result if vulnerable vs. if protected"`
}

// HypothesisStatus представляет статус гипотезы
type HypothesisStatus string

const (
	HypothesisActive    HypothesisStatus = "active"
	HypothesisValidated HypothesisStatus = "validated"
	HypothesisDebunked  HypothesisStatus = "debunked"
)
