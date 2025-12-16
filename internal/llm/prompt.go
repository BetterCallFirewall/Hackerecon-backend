package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// formatJSON форматирует структуру в красивый JSON для промпта
func formatJSON(data interface{}) string {
	result, _ := json.MarshalIndent(data, "", "  ")
	return string(result)
}

// BuildSecurityAnalysisPrompt создаёт детальный промпт для анализа безопасности
// Использует техники промптинга: role playing, few-shot examples, structured output
func BuildSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest) string {
	contextJson := formatJSON(req.SiteContext)
	extractedDataJson := formatJSON(req.ExtractedData)
	return fmt.Sprintf(
		`Глубокий анализ безопасности HTTP запроса. Специализация: бизнес-логика, IDOR, инъекции.

URL: %s | Метод: %s | Content-Type: %s
Headers: %v

Request Body: %s
Response Body: %s

Извлеченные данные: %s
Контекст сайта (%s): %s

ЗАДАЧИ:

1. АНАЛИЗ БИЗНЕС-ЛОГИКИ (приоритет #1):
   Шаг 1: Определи назначение ("просмотр профиля", "удаление заказа", "обновление настроек")
   Шаг 2: Проверь на IDOR:
   • Числовой ID в URL/body? Есть ли owner_id/user_id? Можно подменить?
   • Иерархия: /users/{user_id}/orders/{order_id} - проверяется ли владение?
   • MongoDB ObjectId (24 hex) - средний риск, UUID - низкий риск
   Шаг 3: Broken Access Control:
   • Роль пользователя vs права endpoint (user → admin path?)
   • Манипуляция статусами (draft → published без проверки)
   • Horizontal privilege escalation (просмотр чужих данных)

2. ОПРЕДЕЛЕНИЕ ТЕХНОЛОГИЙ + ИНЪЕКЦИИ:
   • БД hints: error messages (pq:, mysql_, SQLSTATE), headers (X-Powered-By), cookies
   • SQL БД (PostgreSQL/MySQL): проверь WHERE, ORDER BY, LIMIT на injection
   • MongoDB: ищи $operators ($eq, $ne, $regex) - NoSQL Injection риск
   • ORM patterns: filter[]=, {"where": {}}, GraphQL queries
   → Заполни "identified_tech_stack": {"database": "PostgreSQL", "backend": "Express", "confidence": 0.9}

3. ТЕХНИЧЕСКИЕ УЯЗВИМОСТИ:
   • XSS в полях ввода/вывода
   • CSRF на изменяющих операциях (POST/PUT/DELETE)
   • Path Traversal (../../../etc/passwd)
   • Секреты в ответе (API keys, tokens)
   • Отсутствие CSP, HSTS, X-Frame-Options

4. КОНТЕКСТ:
   • identified_user_role: guest/user/admin/service
   • identified_data_objects: [{"name": "order", "fields": ["id", "user_id", "total"]}]

5. ВЕРДИКТ В JSON:
   • risk_level: "low|medium|high|critical" (строго lowercase!)
   • ai_comment: ход мыслей на русском - ЧТО нашел, ПОЧЕМУ уязвимость, КАК эксплуатировать
   • security_checklist: 2-4 шага для пентестера:
     [
       {
         "action": "Название атаки",
         "description": "Конкретные шаги: GET /api/orders/123 → /api/orders/124",
         "expected": "Уязвимость: 200 OK + чужие данные. Защита: 403 Forbidden"
       }
     ]

ПРИОРИТЕТЫ:
✅ Бизнес-логика (IDOR, BAC) > технические уязвимости
✅ Эксплуатируемые находки > теоретические риски
⚠️ Понижай риск для UUID, длинных хешей (требуют brute-force)
⚠️ HTTP вместо HTTPS - не критично для локальных тестов

ОТВЕТ СТРОГО В JSON (все текстовые поля на русском).
`,
		req.URL,
		req.Method,
		req.ContentType,
		req.Headers,
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		string(extractedDataJson),
		req.SiteContext.Host,
		string(contextJson),
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
// Быстрое решение: нужен ли детальный анализ или можно пропустить?
func BuildURLAnalysisPrompt(req *models.URLAnalysisRequest) string {
	techStackInfo := "не определен"
	if req.SiteContext.TechStack != nil {
		if req.SiteContext.TechStack != nil && len(req.SiteContext.TechStack.Technologies) > 0 {
			techs := make([]string, 0, len(req.SiteContext.TechStack.Technologies))
			for _, tech := range req.SiteContext.TechStack.Technologies {
				techs = append(techs, tech.Name)
			}
			// Ограничиваем до 5 технологий для краткости
			if len(techs) > 5 {
				techs = techs[:5]
			}
			techStackInfo = strings.Join(techs, ", ")
		}
	} else {
		req.SiteContext.TechStack = &models.TechStack{Technologies: make([]models.Technology, 0)}
	}

	responsePreview := TruncateString(req.ResponseBody, 300)
	return fmt.Sprintf(
		`Быстрая оценка endpoint для принятия решения о детальном анализе.

URL: %s
Метод: %s
Content-Type: %s
Response preview: %s
Известные технологии: %s

ЗАДАЧА: Определи нужен ли полный анализ безопасности.

КРАСНЫЕ ФЛАГИ (требуют анализа):
🔴 Числовой ID в URL (/users/123, /api/orders/456) → высокий риск IDOR
🔴 Админские пути (/admin, /manage, /dashboard) → проверка доступа
🔴 CRUD операции (POST/PUT/DELETE на /api/*) → бизнес-логика
🔴 MongoDB hints: ObjectId 24hex, $operators в query → NoSQL Injection
🔴 SQL hints: WHERE/ORDER BY в params, error messages → SQL Injection
🔴 Авторизация/аутентификация (/login, /auth, /oauth)

ЗЕЛЕНЫЕ ФЛАГИ (можно пропустить):
🟢 Статика (.js, .css, .png, .jpg, /static, /assets, /public)
🟢 Health checks (/health, /ping, /status, /metrics)
🟢 UUID в URL (невозможен brute-force)
🟢 Длинные хеши >32 символов

ОТВЕТ В JSON:
{
  "url_note": {
    "content": "краткое описание endpoint",
    "suspicious": true/false,
    "vuln_hint": "основная угроза если есть",
    "confidence": 0.0-1.0,
  },
  "should_analyze": true/false,
  "priority": "low|medium|high"
}

ПРИМЕРЫ:
• /api/users/123 → should_analyze: true, priority: high, vuln_hint: "IDOR числовой ID"
• /static/bundle.js → should_analyze: false, priority: low
• /admin/users → should_analyze: true, priority: high, vuln_hint: "Админская зона"
`,
		req.URL,
		req.Method,
		req.ContentType,
		responsePreview,
		techStackInfo,
	)
}

// BuildHypothesisPrompt создает промпт для генерации гипотезы
func BuildHypothesisPrompt(req *models.HypothesisRequest) string {
	// Конвертируем map в slice для фильтрации
	allPatterns := make([]*models.URLPattern, 0, len(req.SiteContext.URLPatterns))
	for _, p := range req.SiteContext.URLPatterns {
		allPatterns = append(allPatterns, p)
	}

	// Фильтруем только высококачественные паттерны (confidence >= 0.7)
	highQualityPatterns := filterHighQualityPatterns(allPatterns)

	// Группируем паттерны по типу возможной атаки
	groupedPatterns := groupPatternsByAttackType(highQualityPatterns)

	// Форматируем подозрительные паттерны более структурировано
	suspiciousText := formatSuspiciousPatterns(req.SuspiciousPatterns)

	previousHypothesisText := "Нет предыдущей гипотезы"
	if req.PreviousHypothesis != nil {
		previousHypothesisText = fmt.Sprintf(
			"Предыдущая гипотеза: %s\nВектор атаки: %s\nConfidence: %.2f",
			req.PreviousHypothesis.Title,
			req.PreviousHypothesis.AttackVector,
			req.PreviousHypothesis.Confidence,
		)
	}

	// Форматируем стек технологий
	techStackDesc := "Стек технологий не определен"
	if req.SiteContext.TechStack != nil && len(req.SiteContext.TechStack.Technologies) > 0 {
		techs := make([]string, 0, len(req.SiteContext.TechStack.Technologies))
		for _, tech := range req.SiteContext.TechStack.Technologies {
			techs = append(techs, fmt.Sprintf("%s (%.2f)", tech.Name, tech.Confidence))
		}
		techStackDesc = strings.Join(techs, ", ")
	}

	return fmt.Sprintf(
		`Генерация главной гипотезы уязвимости на основе накопленных данных о сайте.

ТЕХНОЛОГИИ: %s
УЯЗВИМОСТИ СТЕКА: %v
ПРЕДЫДУЩАЯ ГИПОТЕЗА: %s

ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ (confidence >= 0.7):
%s

ГРУППИРОВКА ПО АТАКАМ:
%s

ЗАДАЧА: Сформируй 2-4 независимых вектора атаки, отсортированных по приоритету.

ПРАВИЛА:
1. Используй ТОЛЬКО реальные endpoints из списка выше
2. НЕ выдумывай параметры, которых нет в запросах
3. ИГНОРИРУЙ UUID и длинные хеши (>32 символов) - низкий риск
4. ФОКУС на: числовые ID, MongoDB ObjectId, SQL/NoSQL Injection, админские пути

ПРИОРИТИЗАЦИЯ:
🔴 HIGH: Числовой ID без owner check, SQL/NoSQL Injection в фильтрах
🟡 MEDIUM: MongoDB ObjectId IDOR (требует знания формата)
🟢 LOW: UUID, длинные хеши, теоретические уязвимости

АНАЛИЗ (шаг за шагом):
1. Фильтруй низкоприоритетные находки (UUID, хеши)
2. Определи паттерн атаки: IDOR/Injection/BAC
3. Проверь эксплуатируемость: есть owner_id? можно подменить?
4. Учти технологии: PostgreSQL → SQLi, MongoDB → NoSQL Injection
5. Найди связи: CRUD на один объект, admin vs user endpoints
6. Сравни с предыдущей гипотезой

ФОРМАТ attack_sequence:
• action: название шага для пентестера
• description: конкретный HTTP запрос (GET /api/orders/123 → /124)
• expected: "Уязвимость: 200 OK + данные. Защита: 403 Forbidden"

ПРИМЕР ОТВЕТА:
{
  "attack_vectors": [
    {
      "id": "idor_orders_001",
      "title": "IDOR в просмотре заказов",
      "description": "Числовой ID без проверки владения",
      "attack_vector": "IDOR",
      "target_urls": ["/api/orders/{id}"],
      "attack_sequence": [
        {"step": 1, "action": "Авторизация", "description": "POST /api/login", "expected": "JWT токен"},
        {"step": 2, "action": "Свой заказ", "description": "GET /api/orders/100", "expected": "200 OK"},
        {"step": 3, "action": "IDOR", "description": "GET /api/orders/101", "expected": "Уязвимость: 200 + чужие данные. Защита: 403"}
      ],
      "required_role": "user",
      "prereqs": ["аутентификация"],
      "confidence": 0.9,
      "impact": "high",
      "effort": "low",
      "status": "active"
    }
  ],
  "reasoning": "Объяснение выбора векторов и приоритизации"
}

ОТВЕТ В JSON (все тексты на русском):
`,
		techStackDesc,
		req.TechVulnerabilities,
		previousHypothesisText,
		suspiciousText,
		groupedPatterns,
	)
}

// filterHighQualityPatterns фильтрует паттерны с высоким confidence
func filterHighQualityPatterns(patterns []*models.URLPattern) []*models.URLPattern {
	filtered := make([]*models.URLPattern, 0)
	for _, pattern := range patterns {
		// Берем последнюю заметку из массива
		if len(pattern.Notes) > 0 {
			lastNote := pattern.Notes[len(pattern.Notes)-1]
			if lastNote.Confidence >= 0.7 {
				filtered = append(filtered, pattern)
			}
		}
	}
	return filtered
}

// groupPatternsByAttackType группирует паттерны по возможному типу атаки
func groupPatternsByAttackType(patterns []*models.URLPattern) string {
	idorPatterns := make([]string, 0)
	sqlPatterns := make([]string, 0)
	authPatterns := make([]string, 0)
	otherPatterns := make([]string, 0)

	for _, p := range patterns {
		// Получаем последнюю заметку
		var lastNote *models.URLNote
		if len(p.Notes) > 0 {
			lastNote = &p.Notes[len(p.Notes)-1]
		}

		if lastNote == nil {
			continue
		}

		patternStr := fmt.Sprintf("- %s (confidence: %.2f)", p.Pattern, lastNote.Confidence)
		patternStr += fmt.Sprintf(" - %s", lastNote.Content)

		// Классифицируем по вероятному типу атаки
		if strings.Contains(p.Pattern, "{") || strings.Contains(strings.ToLower(p.Pattern), "id") {
			idorPatterns = append(idorPatterns, patternStr)
		} else if strings.Contains(strings.ToLower(p.Pattern), "admin") || strings.Contains(
			strings.ToLower(p.Pattern), "auth",
		) {
			authPatterns = append(authPatterns, patternStr)
		} else if strings.Contains(
			strings.ToLower(lastNote.VulnHint), "sql",
		) || strings.Contains(strings.ToLower(lastNote.VulnHint), "injection") {
			sqlPatterns = append(sqlPatterns, patternStr)
		} else {
			otherPatterns = append(otherPatterns, patternStr)
		}
	}

	var result strings.Builder

	if len(idorPatterns) > 0 {
		result.WriteString("\n**Возможный IDOR:**\n")
		result.WriteString(strings.Join(idorPatterns, "\n"))
	}

	if len(authPatterns) > 0 {
		result.WriteString("\n\n**Возможный Broken Access Control:**\n")
		result.WriteString(strings.Join(authPatterns, "\n"))
	}

	if len(sqlPatterns) > 0 {
		result.WriteString("\n\n**Возможный SQL/NoSQL Injection:**\n")
		result.WriteString(strings.Join(sqlPatterns, "\n"))
	}

	if len(otherPatterns) > 0 {
		result.WriteString("\n\n**Другие подозрительные паттерны:**\n")
		result.WriteString(strings.Join(otherPatterns, "\n"))
	}

	if result.Len() == 0 {
		return "Нет сгруппированных паттернов"
	}

	return result.String()
}

// formatSuspiciousPatterns форматирует подозрительные паттерны для промпта
func formatSuspiciousPatterns(patterns []*models.URLPattern) string {
	if len(patterns) == 0 {
		return "Не найдено подозрительных паттернов с высокой уверенностью"
	}

	var result strings.Builder
	for i, p := range patterns {
		// Получаем последнюю заметку
		var lastNote *models.URLNote
		if len(p.Notes) > 0 {
			lastNote = &p.Notes[len(p.Notes)-1]
		}

		if lastNote == nil || lastNote.Confidence < 0.7 {
			continue // Пропускаем низкокачественные
		}

		result.WriteString(fmt.Sprintf("\n%d. URL Pattern: %s\n", i+1, p.Pattern))
		result.WriteString(fmt.Sprintf("   Заметка: %s\n", lastNote.Content))
		result.WriteString(
			fmt.Sprintf(
				"   Подозрительность: %v (confidence: %.2f)\n", lastNote.Suspicious, lastNote.Confidence,
			),
		)
		if lastNote.VulnHint != "" {
			result.WriteString(fmt.Sprintf("   Подсказка: %s\n", lastNote.VulnHint))
		}
	}

	if result.Len() == 0 {
		return "Не найдено подозрительных паттернов с confidence >= 0.7"
	}

	return result.String()
}

// Вспомогательные функции удалены (formatTechList, formatTechStackCompact) - больше не нужны

// BuildVerificationPlanPrompt создает промпт для генерации плана верификации
func BuildVerificationPlanPrompt(req *models.VerificationPlanRequest) string {
	return fmt.Sprintf(`Ты - эксперт по безопасности веб-приложений. Твоя задача создать детальный план верификации гипотезы об уязвимости.

ГИПОТЕЗА:
%s

ОРИГИНАЛЬНЫЙ ЗАПРОС:
URL: %s
Метод: %s
Status: %d

КОНТЕКСТ:
%s

ЗАДАЧА:
Создай план верификации этой гипотезы через безопасные GET запросы.

ПРАВИЛА:
1. Только GET запросы (никаких POST/PUT/DELETE)
2. Максимально %d попыток проверки
3. Создай конкретные URL с тестовыми параметрами
4. Объясни логику каждого теста

ФОРМАТ ОТВЕТА:
{
  "test_requests": [
    {
      "url": "конкретный URL для проверки",
      "method": "GET",
      "headers": {"Header-Name": "Header-Value"},
      "body": "",
      "purpose": "что этот запрос проверяет"
    }
  ],
  "reasoning": "объяснение логики проверки и почему выбраны такие запросы"
}

ОТВЕТ В JSON:`,
		req.Hypothesis,
		req.TargetURL,
		req.OriginalRequest.Method,
		req.OriginalRequest.StatusCode,
		req.AdditionalInfo,
		req.MaxAttempts,
	)
}

// BuildVerificationAnalysisPrompt создает промпт для анализа результатов верификации
func BuildVerificationAnalysisPrompt(req *models.VerificationAnalysisRequest) string {
	resultsJSON, _ := json.MarshalIndent(req.TestResults, "", "  ")

	return fmt.Sprintf(`Ты - эксперт по безопасности. Проанализируй результаты верификации гипотезы.

ИСХОДНАЯ ГИПОТЕЗА:
%s

ИСХОДНАЯ УВЕРЕННОСТЬ: %.2f

РЕЗУЛЬТАТЫ ПРОВЕРОК:
%s

АНАЛИЗ:
На основе ответов сервера определи:

1. **Подтверждена ли уязвимость** (разные ответы показывают уязвимость)
2. **Скорее ложный срабатывание** (все ответы одинаковые и безопасные)
3. **Недостаточно данных** (нельзя определить из GET запросов)

КРИТЕРИИ АНАЛИЗА:
- Разные status codes = возможно уязвимо
- Разные размеры ответов = возможно уязвимо
- Разное содержимое = скорее уязвимо
- Одинаковые ответы = скорее безопасно

ФОРМАТ ОТВЕТА:
{
  "status": "verified|likely_false|inconclusive|manual_check",
  "updated_confidence": 0.0-1.0,
  "reasoning": "детальный анализ почему сделан такой вывод",
  "recommended_poc": "конкретный POC для ручной проверки если нужно"
}

ОТВЕТ В JSON:`,
		req.Hypothesis,
		req.OriginalConfidence,
		string(resultsJSON),
	)
}
