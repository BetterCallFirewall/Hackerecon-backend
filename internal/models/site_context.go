package models

import "time"

// SiteContext хранит накопленную информацию о целевом сайте.
type SiteContext struct {
	Host                string              `json:"host"`
	DiscoveredEndpoints map[string]bool     `json:"discovered_endpoints"`
	DataObjects         map[string][]string `json:"data_objects"` // e.g., "user": ["id", "email", "role"]
	UserRoles           map[string]bool     `json:"user_roles"`
	AuthType            string              `json:"auth_type"` // "Cookie", "JWT Bearer", "Unknown"
	LastUpdated         time.Time           `json:"last_updated"`
}

// NewSiteContext создает новый экземпляр контекста для сайта.
func NewSiteContext(host string) *SiteContext {
	return &SiteContext{
		Host:                host,
		DiscoveredEndpoints: make(map[string]bool),
		DataObjects:         make(map[string][]string),
		UserRoles:           make(map[string]bool),
		AuthType:            "Unknown",
		LastUpdated:         time.Now(),
	}
}
