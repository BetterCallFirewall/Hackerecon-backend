package driven

import (
	"net/http"
)

func convertHeaders(h http.Header) map[string]string {
	headers := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}
