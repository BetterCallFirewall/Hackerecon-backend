package websocket

import "github.com/BetterCallFirewall/Hackerecon/internal/models"

// DetectiveDTO represents the complete detective analysis result
// This is the single message type for the detective flow, sent via WebSocket
// to the frontend after unified analysis is complete.
type DetectiveDTO struct {
	ExchangeID   string               `json:"exchange_id"`
	Method       string               `json:"method"`
	URL          string               `json:"url"`
	StatusCode   int                  `json:"status_code"`
	Comment      string               `json:"comment"`
	Observations []models.Observation `json:"observations,omitempty"`
	Connections  []models.Connection  `json:"connections,omitempty"`
	BigPicture   *models.BigPicture   `json:"big_picture,omitempty"`
	Leads        []models.Lead        `json:"leads,omitempty"` // Included if generated
}

// AnalystDTO - real-time result from Analyst
type AnalystDTO struct {
	ExchangeID    string                `json:"exchange_id"`
	Method        string                `json:"method"`
	URL           string                `json:"url"`
	StatusCode    int                   `json:"status_code"`
	Exchange      models.HTTPExchange   `json:"exchange"`                 // FULL exchange
	Observations  []models.Observation  `json:"observations"`             // Raw observations
	TrafficDigest *models.TrafficDigest `json:"traffic_digest,omitempty"` // Architectural summary
}

// DeepAnalysisDTO - result from Strategist + Tactician + Architect
type DeepAnalysisDTO struct {
	Observations       []models.Observation       `json:"observations"`
	Connections        []models.Connection        `json:"connections"`
	Leads              []models.Lead              `json:"leads"`
	BigPicture         *models.BigPicture         `json:"big_picture"`
	SystemArchitecture *models.SystemArchitecture `json:"system_architecture"`
	TacticianTasks     []models.TacticianTask     `json:"tactician_tasks"`
	SiteMap            []models.SiteMapEntry      `json:"site_map"`
}
