package models

import "time"

// SiteContext хранит накопленную информацию о целевом сайте.
type SiteContext struct {
	Host                 string                 `json:"host" jsonschema:"description=The target host/domain"`
	URLPatterns          map[string]*URLPattern `json:"url_patterns" jsonschema:"description=Normalized URL patterns with AI notes"`
	TechStack            *TechStack             `json:"tech_stack,omitempty" jsonschema:"description=Detected technology stack"`
	MainHypothesis       *SecurityHypothesis    `json:"main_hypothesis,omitempty" jsonschema:"description=Main security hypothesis"`
	LastHypothesisUpdate time.Time              `json:"last_hypothesis_update" jsonschema:"description=Last time hypothesis was updated"`
	LastUpdated          time.Time              `json:"last_updated" jsonschema:"description=Last context update timestamp"`
}

// NewSiteContext создает новый экземпляр контекста для сайта.
func NewSiteContext(host string) *SiteContext {
	return &SiteContext{
		Host:        host,
		URLPatterns: make(map[string]*URLPattern),
		LastUpdated: time.Now(),
	}
}

// URLPattern представляет нормализованный паттерн URL с заметками
type URLPattern struct {
	Pattern string `json:"pattern" jsonschema:"description=Normalized URL pattern with placeholders"`
	Method  string `json:"method" jsonschema:"enum=GET,enum=POST,enum=PUT,enum=DELETE,enum=PATCH,enum=OPTIONS,enum=HEAD,description=HTTP method"`
	Purpose string `json:"purpose" jsonschema:"description=Purpose of this endpoint (e.g., 'User profile viewing')"`

	Notes    []URLNote `json:"notes" jsonschema:"description=Historical notes about this URL pattern (max 100)"`
	LastNote *URLNote  `json:"last_note,omitempty" jsonschema:"description=Most recent note about this pattern"`

	FirstSeen   time.Time `json:"first_seen" jsonschema:"description=When this pattern was first discovered"`
	LastSeen    time.Time `json:"last_seen" jsonschema:"description=When this pattern was last accessed"`
	AccessCount int       `json:"access_count" jsonschema:"description=How many times this pattern was accessed"`
}

// URLNote содержит заметку LLM о URL
type URLNote struct {
	Timestamp  time.Time `json:"timestamp" jsonschema:"description=When the note was created"`
	Content    string    `json:"content" jsonschema:"description=Note content describing the URL purpose"`
	Suspicious bool      `json:"suspicious" jsonschema:"description=Whether this URL looks suspicious"`
	VulnHint   string    `json:"vuln_hint,omitempty" jsonschema:"description=Hint about potential vulnerability"`
	Confidence float64   `json:"confidence" jsonschema:"description=Confidence level (0.0-1.0)"`
	Context    string    `json:"context,omitempty" jsonschema:"description=Additional context for the note"`
}

// TechStack содержит информацию об обнаруженных технологиях
type TechStack struct {
	Frontend    []Technology `json:"frontend" jsonschema:"description=Frontend technologies"`
	Backend     []Technology `json:"backend" jsonschema:"description=Backend technologies"`
	Database    []Technology `json:"database" jsonschema:"description=Database technologies"`
	Frameworks  []Technology `json:"frameworks" jsonschema:"description=Web frameworks"`
	Servers     []Technology `json:"servers" jsonschema:"description=Web servers"`
	Other       []Technology `json:"other" jsonschema:"description=Other technologies"`
	LastUpdated time.Time    `json:"last_updated" jsonschema:"description=Last update timestamp"`
	Confidence  float64      `json:"confidence" jsonschema:"description=Overall confidence in tech detection"`
}

// Technology представляет одну технологию
type Technology struct {
	Name       string     `json:"name" jsonschema:"description=Technology name"`
	Version    string     `json:"version,omitempty" jsonschema:"description=Detected version"`
	Category   string     `json:"category" jsonschema:"enum=frontend,enum=backend,enum=database,enum=framework,enum=server,enum=other,description=Technology category"`
	Confidence float64    `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0)"`
	Evidence   []Evidence `json:"evidence" jsonschema:"description=Evidence supporting this detection"`
}

// Evidence является доказательством обнаружения технологии
type Evidence struct {
	Type       string  `json:"type" jsonschema:"enum=header,enum=html,enum=js,enum=error,enum=cookie,enum=url,description=Type of evidence"`
	Location   string  `json:"location" jsonschema:"description=Where evidence was found"`
	Content    string  `json:"content" jsonschema:"description=Actual evidence content"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in this piece of evidence"`
}

// SecurityHypothesis представляет главную гипотезу об уязвимости
type SecurityHypothesis struct {
	ID             string           `json:"id" jsonschema:"description=Unique hypothesis ID"`
	Title          string           `json:"title" jsonschema:"description=Hypothesis title"`
	Description    string           `json:"description" jsonschema:"description=Detailed description"`
	AttackVector   string           `json:"attack_vector" jsonschema:"description=Type of attack vector"`
	TargetURLs     []string         `json:"target_urls" jsonschema:"description=URLs to investigate for this hypothesis"`
	AttackSequence []AttackStep     `json:"attack_sequence" jsonschema:"description=Step-by-step attack plan"`
	RequiredRole   string           `json:"required_role,omitempty" jsonschema:"description=Required user role"`
	Prereqs        []string         `json:"prereqs,omitempty" jsonschema:"description=Prerequisites for exploitation"`
	Confidence     float64          `json:"confidence" jsonschema:"description=Hypothesis confidence (0.0-1.0)"`
	Impact         string           `json:"impact" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Potential impact"`
	Effort         string           `json:"effort" jsonschema:"enum=low,enum=medium,enum=high,description=Effort required to exploit"`
	CreatedAt      time.Time        `json:"created_at" jsonschema:"description=Creation timestamp"`
	UpdatedAt      time.Time        `json:"updated_at" jsonschema:"description=Last update timestamp"`
	Status         HypothesisStatus `json:"status" jsonschema:"enum=active,enum=validated,enum=debunked,description=Current status"`
}

// AttackStep описывает один шаг в атаке
type AttackStep struct {
	Step        int    `json:"step" jsonschema:"description=Step number in sequence"`
	Action      string `json:"action" jsonschema:"description=Action to perform"`
	Description string `json:"description" jsonschema:"description=Detailed description of the step"`
	Expected    string `json:"expected" jsonschema:"description=Expected result if vulnerable"`
}

// HypothesisStatus представляет статус гипотезы
type HypothesisStatus string

const (
	HypothesisActive    HypothesisStatus = "active"
	HypothesisValidated HypothesisStatus = "validated"
	HypothesisDebunked  HypothesisStatus = "debunked"
)
