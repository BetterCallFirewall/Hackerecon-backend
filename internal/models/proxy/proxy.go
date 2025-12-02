package proxy

import (
	"net/http"
	"time"
)

type RequestData struct {
	ID        string        `json:"id"`
	URL       string        `json:"url"`
	Method    string        `json:"method"`
	Headers   http.Header   `json:"headers"`
	Body      string        `json:"body"`
	Timestamp time.Time     `json:"timestamp"`
	Response  *ResponseData `json:"response,omitempty"`
}

type ResponseData struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}
