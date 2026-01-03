package websocket

import "github.com/BetterCallFirewall/Hackerecon/internal/models"

// DetectiveDTO represents the complete detective analysis result
// This is the single message type for the detective flow, sent via WebSocket
// to the frontend after unified analysis is complete.
type DetectiveDTO struct {
	ExchangeID  string              `json:"exchange_id"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	StatusCode  int                 `json:"status_code"`
	Comment     string              `json:"comment"`
	Observation *models.Observation `json:"observation,omitempty"`
	Connections []models.Connection `json:"connections,omitempty"`
	BigPicture  *models.BigPicture  `json:"big_picture,omitempty"`
	Lead        *models.Lead        `json:"lead,omitempty"` // Included if generated
}
