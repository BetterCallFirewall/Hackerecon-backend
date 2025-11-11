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
