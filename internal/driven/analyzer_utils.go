package driven

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// buildSecurityAnalysisPrompt создает детальный промпт для анализа
func (analyzer *GenkitSecurityAnalyzer) buildSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	extractedDataJson, _ := json.MarshalIndent(req.ExtractedData, "", "  ")

	return fmt.Sprintf(
		`
Ты — элитный специалист по кибербезопасности и пентестеру, специализирующийся на поиске уязвимостей в бизнес-логике. Твоя задача — проанализировать HTTP-обмен, используя предоставленный контекст сессии, чтобы выявить сложные и неочевидные уязвимости.

### КОНТЕКСТ СЕССИИ ДЛЯ ХОСТА %s (Что мы уже знаем):
%s

### ТЕКУЩИЙ HTTP-ОБМЕН ДЛЯ АНАЛИЗА:
- URL: %s
- Метод: %s
- Заголовки: %v
- Тело запроса (сокращено/обработано): %s
- Тело ответа (сокращено/обработано): %s
- Content-Type: %s

### ПРЕДВАРИТЕЛЬНО ИЗВЛЕЧЕННЫЕ ДАННЫЕ ИЗ ТРАФИКА:
%s

### ТВОИ ЗАДАЧИ:

1.  **АНАЛИЗ БИЗНЕС-ЛОГИКИ (Рассуждай по шагам - Chain of Thought):**
    *   **Шаг 1: Каково назначение этого запроса?** Опиши, какую бизнес-операцию пытается выполнить пользователь (например, "обновление профиля", "просмотр заказа", "удаление пользователя").
    *   **Шаг 2: Сопоставь с контекстом.** Сравни текущий запрос с известной информацией о сайте. Есть ли аномалии? Например:
        - Пытается ли пользователь с ролью 'user' получить доступ к эндпоинту, похожему на админский (например, '/api/v1/users/delete')?
        - Манипулирует ли пользователь объектом данных (например, заказом), который, судя по ID, ему не принадлежит?
        - Происходит ли неожиданное изменение состояния или раскрытие данных?
    *   **Шаг 3: Сформулируй гипотезы уязвимостей.** На основе аномалий предложи конкретные типы уязвимостей (IDOR, Broken Access Control, Race Conditions, etc.).

2.  **ПОИСК ТЕХНИЧЕСКИХ УЯЗВИМОСТЕЙ:**
    *   Проверь на классические уязвимости: SQLi, XSS, CSRF, Command Injection, Path Traversal.
    *   Проанализируй заголовки на предмет отсутствия важных политик безопасности (CSP, HSTS, etc.).
    *   Оцени критичность найденных секретов и ключей.

3.  **ОБОГАЩЕНИЕ КОНТЕКСТА (Помоги мне учиться):**
    *   Определи роль пользователя в этом запросе (например, 'guest', 'user', 'admin'). Укажи это в поле 'identified_user_role''.
    *   Найди в запросе или ответе новые объекты данных и их поля (например, объект "order" с полями "id", "user_id", "amount"). Укажи их в 'identified_data_objects'' в формате [{"name": "order", "fields": ["id", "user_id", "amount"]}].

4.  **ИТОГОВЫЙ ВЕРДИКТ (Строго в формате JSON):**
    *   Заполни все поля JSON-схемы, включая 'has_vulnerability'', 'risk_level'', 'ai_comment'' (с объяснением твоих рассуждений), 'recommendations'' и 'security_checklist''.
    *   Включи в ответ новые поля 'identified_user_role'' и 'identified_data_objects''.

В первую очередь сосредоточься на анализе бизнес-логики и поиске уязвимостей, связанных с обходом бизнес-правил.
Также понижай уровень риска уязвимостей, для которых необходимо подбирать ключи.
Не обращай внимание на протокол HTTP вместо HTTPS.
Ответь строго в JSON формате согласно предоставленной схеме.
`,
		req.SiteContext.Host,
		string(contextJson),
		req.URL,
		req.Method,
		req.Headers,
		truncateString(req.RequestBody, 500),
		truncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson),
	)
}

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

func identifySecretType(match string) string {
	lowerMatch := strings.ToLower(match)

	typeMap := map[string]string{
		"api":     "API Key",
		"token":   "Access Token",
		"secret":  "Secret Key",
		"akia":    "AWS Access Key",
		"aiza":    "Google API Key",
		"ghp_":    "GitHub Token",
		"sk_live": "Stripe Secret Key",
		"eyj":     "JWT Token",
	}

	for pattern, secretType := range typeMap {
		if strings.Contains(lowerMatch, pattern) {
			return secretType
		}
	}

	return "Unknown Secret"
}

func calculateSecretConfidence(secretType, value string) float64 {
	confidence := 0.5

	if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "AIza") {
		confidence = 0.95
	} else if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "sk_live_") {
		confidence = 0.95
	} else if len(value) > 32 && (strings.Contains(secretType, "API") || strings.Contains(secretType, "Secret")) {
		confidence = 0.8
	} else if len(value) > 16 {
		confidence = 0.7
	}

	return confidence
}

func isSuspiciousFunction(funcName, context string) (bool, string) {
	suspiciousFunctions := map[string]string{
		"eval":        "Выполнение произвольного кода",
		"settimeout":  "Потенциальное выполнение кода",
		"setinterval": "Потенциальное выполнение кода",
		"function":    "Динамическое создание функций",
		"innerhtml":   "Возможность XSS",
		"outerhtml":   "Возможность XSS",
	}

	lowerName := strings.ToLower(funcName)
	if reason, exists := suspiciousFunctions[lowerName]; exists {
		return true, reason
	}

	// Проверяем контекст
	suspiciousPatterns := []string{"crypto", "encrypt", "decrypt", "hash", "password", "token", "secret"}
	lowerContext := strings.ToLower(context)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerContext, pattern) {
			return true, fmt.Sprintf("Содержит подозрительный паттерн: %s", pattern)
		}
	}

	return false, ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func truncateSecret(secret string) string {
	if len(secret) <= 10 {
		return secret
	}
	return secret[:6] + "***" + secret[len(secret)-4:]
}

func generateReportID() string {
	return fmt.Sprintf("VR-%d", time.Now().UnixNano())
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

func copyHeaders(dst, src http.Header) {
	// Заголовки, которые нужно исключить или обработать особо
	excludeHeaders := map[string]bool{
		"Connection":          true,
		"Proxy-Connection":    true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Upgrade":             true,
	}

	for name, values := range src {
		if excludeHeaders[name] {
			continue
		}

		// Копируем остальные заголовки
		for _, value := range values {
			dst.Add(name, value)
		}
	}
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

var skippableContentTypePrefixes = []string{
	"image/", "font/", "video/", "audio/", "application/font-woff", "application/octet-stream",
}

var skippableFileExtensions = []string{
	".css", ".ico", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
}

func isSkippableContent(contentType, urlPath string) bool {
	// Проверка по Content-Type
	for _, prefix := range skippableContentTypePrefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}

	// Проверка по расширению файла в URL
	lowerPath := strings.ToLower(urlPath)
	for _, ext := range skippableFileExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}

	return false
}
