package models

type ReportDTO struct {
	Report          VulnerabilityReport `json:"report"`
	RequestResponse RequestResponseInfo `json:"request_response"`
}

type RequestResponseInfo struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	StatusCode  int               `json:"status_code"`
	ReqHeaders  map[string]string `json:"request_headers"`
	RespHeaders map[string]string `json:"response_headers"`
	ReqBody     string            `json:"request_body,omitempty"`
	RespBody    string            `json:"response_body,omitempty"`
}

// HypothesisDTO используется для отправки гипотезы через API
type HypothesisDTO struct {
	Type string          `json:"type"`
	Data *HypothesisData `json:"data"`
}

// HypothesisData содержит данные гипотезы
type HypothesisData struct {
	AttackVectors []*SecurityHypothesis `json:"attack_vectors"`
	TechStack     *TechStack            `json:"tech_stack,omitempty"`
}
