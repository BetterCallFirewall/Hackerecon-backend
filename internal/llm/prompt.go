package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildSecurityAnalysisPrompt создаёт детальный промпт для анализа безопасности
// Это универсальная функция, которую могут использовать все провайдеры
func BuildSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest) string {
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
    *   Определи роль пользователя в этом запросе (например, 'guest', 'user', 'admin'). Укажи это в поле 'identified_user_role'.
    *   Найди в запросе или ответе новые объекты данных и их поля (например, объект "order" с полями "id", "user_id", "amount"). Укажи их в 'identified_data_objects' в формате [{"name": "order", "fields": ["id", "user_id", "amount"]}].

4.  **ИТОГОВЫЙ ВЕРДИКТ (Строго в формате JSON):**
    *   Заполни все поля JSON-схемы, включая 'has_vulnerability', 'risk_level', 'ai_comment' (с объяснением твоих рассуждений), 'recommendations'.
    *   **ВАЖНО**: Поле 'risk_level' ДОЛЖНО быть СТРОГО одним из значений: "low", "medium", "high", "critical" (только маленькими буквами).
    *   **ВАЖНО для 'security_checklist'**: Если найдена уязвимость, предложи 3-5 разных способов её проверить/воспроизвести. Каждая проверка независима от других. Формат:
        "security_checklist": [{"action": "Подмена user_id", "description": "Замени user_id=123 на user_id=456 в запросе", "expected": "Сервер должен вернуть 403 Forbidden"}]
    *   Включи в ответ новые поля 'identified_user_role' и 'identified_data_objects'.
	*   **ВАЖНО**: поля ai_comment, action, description должны быть на русском языке.

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
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson),
	)
}

// TruncateString обрезает строку до указанной длины
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// BuildURLAnalysisPrompt создает промпт для быстрой оценки URL
func BuildURLAnalysisPrompt(req *models.URLAnalysisRequest) string {
	return fmt.Sprintf(`
Ты - эксперт по веб-безопасности. Быстро оцени этот URL эндпоинт.

### ЗАПРОС:
URL: %s %s
Content-Type: %s
Размер ответа: %d байт

### КОНТЕКСТ САЙТА:
Хост: %s
Роли: %v
Технологии: %s
Найдено эндпоинтов: %d

### ЗАДАЧА:
Определи, заслуживает ли этот эндпоинт полного анализа безопасности.

КРИТЕРИИ ОЦЕНКИ:
1. Содержит бизнес-логику (авторизация, данные, платежи)
2. Может содержать уязвимости
3. Не является статикой или аналитикой
4. Имеет интересный response контент

ОТВЕТ СТРОГО В JSON:
{
    "url_note": {
        "content": "Краткое описание назначения эндпоинта (2-3 слова)",
        "suspicious": false,
        "vuln_hint": "Подозрение на уязвимость, если есть",
        "confidence": 0.9,
        "context": "Дополнительный контекст (роль пользователя, тип данных)"
    },
    "should_analyze": true,
    "priority": "high"
}

ВАЖНО:
- should_analyze: true/false - нужен ли полный анализ
- priority: "low", "medium", "high" - приоритет анализа
- Все текстовые поля на русском языке
`,
		req.Method,
		req.NormalizedURL,
		req.ContentType,
		len(req.ResponseBody),
		req.SiteContext.Host,
		req.SiteContext.UserRoles,
		formatTechStackCompact(req.SiteContext.TechStack),
		len(req.SiteContext.URLPatterns),
	)
}

// BuildFullSecurityAnalysisPrompt создает промпт для полного анализа (с заметкой)
func BuildFullSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest, urlNote *models.URLNote) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	extractedDataJson, _ := json.MarshalIndent(req.ExtractedData, "", "  ")

	urlNoteJson, _ := json.MarshalIndent(urlNote, "", "  ")

	return fmt.Sprintf(`
ПОЛНЫЙ АНАЛИЗ БЕЗОПАСНОСТИ

### ЗАМЕЧАНИЕ ПО URL:
%s

### КОНТЕКСТ СЕССИИ ДЛЯ ХОСТА %s:
%s

### ТЕКУЩИЙ HTTP-ОБМЕН:
- URL: %s
- Метод: %s
- Заголовки: %v
- Тело запроса: %s
- Тело ответа: %s
- Content-Type: %s

### ИЗВЛЕЧЕННЫЕ ДАННЫЕ:
%s

### ЗАДАЧИ:

1. **АНАЛИЗ С УЧЕТОМ ЗАМЕТКИ:**
   - Используй заметку о назначении URL для фокусировки анализа
   - Проверь именно те уязвимости, которые актуальны для этого типа эндпоинта

2. **БИЗНЕС-ЛОГИКА:**
   - Проверь на IDOR, Broken Access Control, Race Conditions
   - Проанализируй соответствие роли пользователя и прав доступа

3. **ТЕХНИЧЕСКИЕ УЯЗВИМОСТИ:**
   - SQLi, XSS, CSRF, Command Injection
   - Отсутствие заголовков безопасности

4. **ИТОГОВЫЙ ВЕРДИКТ (JSON):**
   - Заполни все поля согласно схеме
   - Учитывай заметку о подозрительной активности
   - ai_comment на русском языке

Ответ строго в JSON формате.
`,
		string(urlNoteJson),
		req.SiteContext.Host,
		string(contextJson),
		req.URL,
		req.Method,
		req.Headers,
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson),
	)
}

// BuildHypothesisPrompt создает промпт для генерации гипотезы
func BuildHypothesisPrompt(req *models.HypothesisRequest) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	suspiciousJson, _ := json.MarshalIndent(req.SuspiciousPatterns, "", "  ")
	attackSequencesJson, _ := json.MarshalIndent(req.AttackSequences, "", "  ")

	previousHypothesisText := "Нет предыдущей гипотезы"
	if req.PreviousHypothesis != nil {
		phJson, _ := json.MarshalIndent(req.PreviousHypothesis, "", "  ")
		previousHypothesisText = string(phJson)
	}

	return fmt.Sprintf(`
ГЕНЕРАЦИЯ ГЛАВНОЙ ГИПОТЕЗЫ УЯЗВИМОСТИ

### КОНТЕКСТ САЙТА:
%s

### ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ URL:
%s

### ВОЗМОЖНЫЕ ПОСЛЕДОВАТЕЛЬНОСТИ АТАК:
%s

### ИЗВЕСТНЫЕ УЯЗВИМОСТИ ТЕХНОЛОГИЙ:
%v

### ПРЕДЫДУЩАЯ ГИПОТЕЗА:
%s

### ЗАДАЧА:
Сформируй наиболее вероятную гипотезу об уязвимости или определи URL для дополнительного исследования.

АНАЛИЗ:
1. Найди связи между подозрительными эндпоинтами
2. Определи возможные векторы атак
3. Учитывай обнаруженный стек технологий
4. Сравни с предыдущей гипотезой (если есть)

ОТВЕТ СТРОГО В JSON:
{
    "hypothesis": {
        "id": "уникальный_id",
        "title": "Краткое название гипотезы",
        "description": "Подробное описание гипотезы",
        "attack_vector": "Privilege Escalation",
        "target_urls": ["/api/v1/admin/users", "/api/v1/orders"],
        "attack_sequence": [
            {
                "step": 1,
                "action": "Действие 1",
                "description": "Описание шага 1",
                "expected": "Ожидаемый результат"
            }
        ],
        "required_role": "user",
        "prereqs": ["аутентификация"],
        "confidence": 0.8,
        "impact": "high",
        "effort": "low",
        "status": "active"
    },
    "reasoning": "Объяснение логики построения гипотезы"
}

Все текстовые поля на русском языке.
`,
		string(contextJson),
		string(suspiciousJson),
		string(attackSequencesJson),
		req.TechVulnerabilities,
		previousHypothesisText,
	)
}

// Вспомогательные функции

func formatTechStackCompact(techStack *models.TechStack) string {
	if techStack == nil {
		return "не определен"
	}

	var technologies []string

	if len(techStack.Frontend) > 0 {
		for _, tech := range techStack.Frontend {
			technologies = append(technologies, tech.Name)
		}
	}
	if len(techStack.Backend) > 0 {
		for _, tech := range techStack.Backend {
			technologies = append(technologies, tech.Name)
		}
	}
	if len(techStack.Database) > 0 {
		for _, tech := range techStack.Database {
			technologies = append(technologies, tech.Name)
		}
	}

	if len(technologies) == 0 {
		return "не определен"
	}

	// Возвращаем первые 5 технологий
	if len(technologies) > 5 {
		technologies = technologies[:5]
	}

	return strings.Join(technologies, ", ")
}
