package llm

import (
	"strings"
	"testing"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

func TestBuildSecurityAnalysisPrompt_IncludesHeaders(t *testing.T) {
	req := &models.SecurityAnalysisRequest{
		URL:    "http://example.com/api/users/123",
		Method: "GET",
		Headers: map[string]string{
			"Cookie":        "session=abc123; user_id=5",
			"Authorization": "Bearer token123",
			"User-Agent":    "TestAgent/1.0",
		},
		RequestBody:  "",
		ResponseBody: `{"id": 123, "name": "admin"}`,
		SiteContext: &models.SiteContext{
			Host: "example.com",
		},
		ExtractedData: models.ExtractedData{
			FormActions: []string{},
			Comments:    []string{},
		},
	}

	prompt := BuildSecurityAnalysisPrompt(req)

	// Проверяем, что в промпте есть заголовки
	if !strings.Contains(prompt, "Cookie:") {
		t.Error("Промпт не содержит Cookie заголовок")
	}

	if !strings.Contains(prompt, "session=abc123") {
		t.Error("Промпт не содержит значение Cookie")
	}

	if !strings.Contains(prompt, "Authorization:") {
		t.Error("Промпт не содержит Authorization заголовок")
	}

	if !strings.Contains(prompt, "Bearer token123") {
		t.Error("Промпт не содержит значение Authorization")
	}

	// Проверяем, что заголовок Headers: присутствует
	if !strings.Contains(prompt, "Headers:") {
		t.Error("Промпт не содержит секцию Headers")
	}

	t.Logf("Фрагмент промпта с заголовками:\n%s", extractHeadersSection(prompt))
}

func TestFormatHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected []string // строки, которые должны быть в результате
	}{
		{
			name:     "пустые заголовки",
			headers:  map[string]string{},
			expected: []string{"(нет заголовков)"},
		},
		{
			name: "несколько заголовков",
			headers: map[string]string{
				"Cookie":        "session=123",
				"Authorization": "Bearer token",
			},
			expected: []string{"Cookie:", "session=123", "Authorization:", "Bearer token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatHeaders(tt.headers)

			for _, exp := range tt.expected {
				if !strings.Contains(result, exp) {
					t.Errorf("formatHeaders() не содержит ожидаемую строку %q. Результат: %s", exp, result)
				}
			}
		})
	}
}

// extractHeadersSection извлекает секцию с заголовками из промпта для отладки
func extractHeadersSection(prompt string) string {
	lines := strings.Split(prompt, "\n")
	var result []string

	for i, line := range lines {
		if strings.Contains(line, "Headers:") {
			// Берем 5 строк после Headers:
			for j := i; j < i+5 && j < len(lines); j++ {
				result = append(result, lines[j])
			}
			break
		}
	}

	return strings.Join(result, "\n")
}
