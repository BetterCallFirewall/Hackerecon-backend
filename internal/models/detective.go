package models

import (
	"time"
)

// HTTPExchange represents a complete HTTP request-response pair
// This is the fundamental unit of analysis in security testing
type HTTPExchange struct {
	ID        string       `json:"id" jsonschema:"description=Unique exchange ID (e.g., exch-123)"`
	Request   RequestPart  `json:"request" jsonschema:"description=HTTP request details"`
	Response  ResponsePart `json:"response" jsonschema:"description=HTTP response details"`
	Timestamp time.Time    `json:"timestamp" jsonschema:"description=Unix timestamp when exchange occurred"`
}

// RequestPart represents the HTTP request portion
type RequestPart struct {
	Method  string            `json:"method" jsonschema:"description=HTTP method,enum=GET,enum=POST,enum=PUT,enum=DELETE,enum=PATCH"`
	URL     string            `json:"url" jsonschema:"description=Full URL including protocol and path"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"description=Request headers"`
	Body    string            `json:"body,omitempty" jsonschema:"description=Request body (truncated if large)"`
}

// ResponsePart represents the HTTP response portion
type ResponsePart struct {
	StatusCode int               `json:"status_code" jsonschema:"description=HTTP status code,minimum=100,maximum=599"`
	Headers    map[string]string `json:"headers,omitempty" jsonschema:"description=Response headers"`
	Body       string            `json:"body,omitempty" jsonschema:"description=Response body (truncated if large)"`
}

// Observation represents a security-relevant fact
// Key principle: Observation = FACT, not interpretation
// NOT common patterns like JWT or session string - these are baseline
type Observation struct {
	ID         string    `json:"id" jsonschema:"description=Unique observation ID (e.g., obs-123)"`
	ExchangeID string    `json:"exchange_id" jsonschema:"description=Reference to HTTPExchange"`
	What       string    `json:"what" jsonschema:"description=EXACT fact observed (no interpretation)"`
	Where      string    `json:"where" jsonschema:"description=Precise location with value"`
	Why        string    `json:"why" jsonschema:"description=Why this fact is useful for understanding/attacking"`
	CreatedAt  time.Time `json:"created_at" jsonschema:"description=Unix timestamp when observation was created"`
	// REMOVED: Severity - facts don't have severity, only leads/findings do
}

// Lead represents an actionable security lead (replaces Hypothesis + Finding)
type Lead struct {
	ID             string     `json:"id" jsonschema:"description=Unique lead ID (e.g., lead-456)"`
	ObservationID  string     `json:"observation_id" jsonschema:"description=Reference to Observation"`
	Title          string     `json:"title" jsonschema:"description=Short title (max 10 words)"`
	ActionableStep string     `json:"actionable_step" jsonschema:"description=Concrete testing step"`
	PoCs           []PoCEntry `json:"pocs,omitempty" jsonschema:"description=Human-readable PoC instructions"`
	CreatedAt      time.Time  `json:"created_at" jsonschema:"description=Unix timestamp when lead was created"`
	// REMOVED: CanAutoVerify, AutoVerified, VerificationResult - no auto-verification
}

// PoCEntry represents a proof-of-concept instruction (human-readable)
type PoCEntry struct {
	Payload string `json:"payload" jsonschema:"description=Testing instruction (curl, description, steps)"`
	Comment string `json:"comment" jsonschema:"description=Explanation of what this PoC tests"`
}

// Connection represents a relationship between two entities
type Connection struct {
	ID1       string    `json:"id1" jsonschema:"description=First entity ID (e.g., obs-1)"`
	ID2       string    `json:"id2" jsonschema:"description=Second entity ID (e.g., obs-3)"`
	Reason    string    `json:"reason" jsonschema:"description=Why they are connected"`
	CreatedAt time.Time `json:"created_at" jsonschema:"description=Unix timestamp when connection was created"`
}

// BigPicture represents high-level understanding of the target (LLM-driven updates)
type BigPicture struct {
	Description     string `json:"description" jsonschema:"description=High-level app description (e.g., 'Ticketing system with purchase form')"`
	Functionalities string `json:"functionalities" jsonschema:"description=Main features detected (e.g., 'authentication, view tickets, purchase, payment')"`
	Technologies    string `json:"technologies" jsonschema:"description=Technologies detected (e.g., 'MongoDB, AES encryption, JWT tokens')"`
	LastUpdated     int64  `json:"last_updated" jsonschema:"description=Unix timestamp of last update"`
}

// BigPictureImpact represents a suggested update to the big picture
type BigPictureImpact struct {
	Field  string `json:"field" jsonschema:"description=Field to update,enum=description,enum=functionalities,enum=technologies"`
	Value  string `json:"value" jsonschema:"description=New value for the field"`
	Reason string `json:"reason" jsonschema:"description=Why this update is needed"`
	// REMOVED: Confidence - if LLM suggests it, apply it directly
}

// SiteMapEntry represents an entry in the site map (Burp-style)
type SiteMapEntry struct {
	ID       string       `json:"id" jsonschema:"description=Unique site map entry ID"`
	Method   string       `json:"method" jsonschema:"description=HTTP method"`
	URL      string       `json:"url" jsonschema:"description=Full URL"`
	Comment  string       `json:"comment" jsonschema:"description=LLM-generated comment about this entry"`
	Request  RequestPart  `json:"request" jsonschema:"description=Request portion"`
	Response ResponsePart `json:"response" jsonschema:"description=Response portion"`
	Children []string     `json:"children,omitempty" jsonschema:"description=Child IDs for hierarchy"`
}
