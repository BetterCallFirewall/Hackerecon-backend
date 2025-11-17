package driven

import (
	"net/http"
	"regexp"
)

func createSecretRegexPatterns() []*regexp.Regexp {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)(access[_\-\s]*token[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{20,}['"]|[a-zA-Z0-9]{20,})`),
		regexp.MustCompile(`(?i)(secret[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
	}
	return patterns
}

// identifySecretType, calculateSecretConfidence и isSuspiciousFunction удалены
// LLM теперь сам определяет типы секретов и подозрительность функций на основе контекста

func truncateSecret(secret string) string {
	if len(secret) <= 10 {
		return secret
	}
	return secret[:6] + "***" + secret[len(secret)-4:]
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func convertHeaders(h http.Header) map[string]string {
	headers := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}
