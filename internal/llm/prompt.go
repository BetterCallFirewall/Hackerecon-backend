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
	extractedDataJson := formatJSON(req.ExtractedData)

	blacklist := `## ЧТО НЕ УПОМИНАТЬ (ОБЯЗАТЕЛЬНО ИГНОРИРОВАТЬ)

### Категория 1: Теоретические атаки (не уязвимости приложения)
НЕ предлагать:
- Брутфорс паролей / credential stuffing
- Создание CSRF форм (если токен есть — это защита)
- Перехват HTTP трафика / MITM атаки
- Социальная инженерия / фишинг
- DoS / DDoS атаки

### Категория 2: Инфраструктурные проблемы
НЕ предлагать:
- HTTP вместо HTTPS (норма для локального тестирования)
- Отсутствие HSTS, X-Frame-Options, CSP

### Категория 3: Общие фразы без конкретики
НЕ писать:
- "Проверить на SQL Injection" (без конкретного параметра)
- "Возможна XSS атака" (без конкретного вектора)
- "Потенциальная уязвимость" (без конкретики)`

	return fmt.Sprintf(
		`Ты — ассистент пентестера на CTF/Bug Bounty.

### КОНТЕКСТ:
URL: %s
Method: %s
Request Body: %s
Response Body: %s
Site Context: %s

Извлеченные данные: %s

%s

### ЗАДАЧА:
Проанализируй этот HTTP обмен и предложи КОНКРЕТНЫЕ проверки.

### ОГРАНИЧЕНИЯ:
- Максимум 5 проверок (лучше 2-3 качественных, чем 10 общих)
- Каждая проверка = конкретное изменение запроса
- Приоритет по ЭКСПЛУАТИРУЕМОСТИ, не по "возможности"

### ФОРМАТ ОТВЕТА В JSON:

{
  "summary": "Одно предложение: что это за endpoint и что интересного",

  "findings": [
    {
      "title": "Короткое название (не 'Possible SQLi', а 'SQL в параметре sort')",
      "observation": "Что конкретно видно в трафике",
      "test_requests": [
        {
          "method": "GET",
          "url": "Полный URL с изменённым параметром",
          "headers": {"Header": "Value"},
          "body": "Если POST/PUT",
          "purpose": "Что конкретно этот запрос проверяет"
        }
      ],
      "expected_if_vulnerable": "Что увидим если уязвимо",
      "expected_if_safe": "Что увидим если защищено",
      "effort": "low|medium|high",
      "impact": "low|medium|high|critical"
    }
  ],

  "context_for_later": {
    "identified_patterns": ["Паттерны для SiteContext"],
    "related_endpoints": ["Связанные endpoints если видны"],
    "user_role_detected": "guest|user|admin|unknown"
  }
}

### ПРИОРИТИЗАЦИЯ FINDINGS:

Включать в первую очередь (effort: low, impact: high):
- IDOR с числовым ID (просто поменять число)
- Отсутствие проверки владельца (owner_id)
- Доступ к admin endpoints без проверки роли
- Явные ошибки в ответе (stack traces, SQL errors)

Включать во вторую очередь (effort: medium):
- NoSQL injection (если MongoDB и видны $операторы)
- Path traversal (если есть параметр с путём)
- SSRF (если URL в параметре)

НЕ включать (effort: high, низкая вероятность):
- SQLi без признаков (просто потому что есть input)
- XSS без reflection (просто потому что есть поле)
- Теоретические атаки из blacklist

ПРИМЕРЫ:

Пример 1 - Простой IDOR (1 тест):
{
  "summary": "GET /api/orders/{id} - просмотр заказа по ID",
  "findings": [
    {
      "title": "IDOR - доступ к чужому заказу через ID",
      "observation": "Числовой ID в URL, ответ содержит order details (email, amount). Нет видимой проверки владельца.",
      "test_requests": [
        {
          "method": "GET",
          "url": "http://example.com/api/orders/999",
          "headers": {},
          "purpose": "Проверить доступ к чужому заказу через подмену числового ID"
        }
      ],
      "expected_if_vulnerable": "200 OK с деталями чужого заказа",
      "expected_if_safe": "403 Forbidden или 404 Not Found",
      "effort": "low",
      "impact": "high"
    }
  ],
  "context_for_later": {
    "identified_patterns": ["Числовые ID в URLs"],
    "related_endpoints": ["/api/orders", "/api/users/{id}"],
    "user_role_detected": "user"
  }
}

Пример 2 - Сложный NoSQLi (несколько тестов):
{
  "summary": "MongoDB endpoint с потенциальным NoSQL injection",
  "findings": [
    {
      "title": "NoSQL injection в MongoDB ObjectId",
      "observation": "MongoDB ObjectId в URL: 507f1f77bcf86cd799439011. Нет валидации ID формата.",
      "test_requests": [
        {
          "method": "GET",
          "url": "http://example.com/api/shop/507f1f77bcf86cd799439012",
          "headers": {},
          "purpose": "Проверить простую подмену ID на другой валидный ObjectId"
        },
        {
          "method": "GET",
          "url": "http://example.com/api/shop/507f1f77bcf86cd799439011",
          "headers": {"Content-Type": "application/json"},
          "body": "{\"$ne\": null}",
          "purpose": "Проверить NoSQL оператор $ne (not equals) в теле запроса"
        },
        {
          "method": "GET",
          "url": "http://example.com/api/shop/507f1f77bcf86cd799439011?filter[$regex]=.*",
          "headers": {},
          "purpose": "Проверить regex injection в query параметре"
        }
      ],
      "expected_if_vulnerable": "Возвращает данные, не соответствующие ожидаемому ID",
      "expected_if_safe": "400 Bad Request или 403 Forbidden",
      "effort": "medium",
      "impact": "high"
    }
  ],
  "context_for_later": {
    "identified_patterns": ["MongoDB ObjectIds"],
    "related_endpoints": ["/api/shop/*"],
    "user_role_detected": "user"
  }
}

ОТВЕТ СТРОГО В JSON ФОРМАТЕ.
`,
		req.URL,
		req.Method,
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		req.SiteContext.Host,
		string(extractedDataJson),
		blacklist,
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
	if req.SiteContext != nil && req.SiteContext.TechStack != nil && len(req.SiteContext.TechStack.Technologies) > 0 {
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

	responsePreview := TruncateString(req.ResponseBody, 300)

	blacklist := `## ЧТО НЕ УПОМИНАТЬ (ОБЯЗАТЕЛЬНО ИГНОРИРОВАТЬ)

### Категория 1: Теоретические атаки (не уязвимости приложения)
НЕ предлагать:
- Брутфорс паролей / credential stuffing / password spraying
- Создание CSRF форм (если токен есть — это защита, не проблема)
- Перехват HTTP трафика / MITM атаки
- Социальная инженерия / фишинг
- DoS / DDoS атаки
- Timing attacks без конкретных доказательств

### Категория 2: Инфраструктурные проблемы (вне scope анализа)
НЕ предлагать:
- HTTP вместо HTTPS (норма для локального тестирования)
- Отсутствие HSTS, X-Frame-Options, CSP (если нет конкретной атаки)
- "Рекомендуется использовать..." — это не для CTF

### Категория 3: Стандартные механизмы (не проблемы)
НЕ упоминать как проблемы:
- "CSRF токен присутствует" — это защита, не интересно
- "Требуется аутентификация" — ожидаемое поведение
- "Rate limiting работает" — это защита

### Категория 4: Общие фразы без конкретики
НЕ писать:
- "Проверить на SQL Injection" (без конкретного параметра)
- "Возможна XSS атака" (без конкретного вектора)
- "Потенциальная уязвимость" (без конкретики)`

	return fmt.Sprintf(
		`Ты — ассистент по безопасности, помогающий исследователю понять приложение.

### ВХОДНЫЕ ДАННЫЕ:
%s %s
Content-Type: %s
Response preview: %s
Текущий контекст сайта: %s

%s

### ЗАДАЧА:
Проанализируй HTTP запрос/ответ и опиши ЧТО ТЫ ВИДИШЬ.
НЕ делай выводов об уязвимостях — только факты и наблюдения.

### ФОРМАТ ОТВЕТА В JSON:

{
  "interest_level": "high|medium|low",
  "endpoint_type": "auth|api|admin|crud|static|unknown",
  "observations": [
    "Конкретное наблюдение 1 (факт, не вывод)",
    "Конкретное наблюдение 2"
  ],
  "suggested_checks": [
    {
      "what": "Что проверить (конкретно)",
      "how": "Как проверить (конкретный запрос)",
      "why": "Почему это интересно"
    }
  ],
  "detected_tech": {
    "database": "PostgreSQL|MySQL|MongoDB|unknown",
    "backend": "Express|Django|Spring|unknown",
    "evidence": "Почему так решил"
  },
  "tags": ["auth", "user-data", "admin", "file-upload", etc],
  "url_note": {
    "content": "Заметка о назначении endpoint'а с соответствующим уровнем детализации",
    "suspicious": true/false,
    "vuln_hint": "Подсказка об уязвимости (только для high/medium)",
    "confidence": 0.0-1.0
  }
}

### ПРАВИЛА INTEREST LEVEL:

HIGH — Обязательно обратить внимание:
- Admin панели, привилегированные операции
- Endpoints с пользовательскими данными (PII)
- Операции с файлами (upload, download, path в параметрах)
- Числовой ID в URL + данные в ответе (IDOR кандидат)
- Видимые признаки динамических запросов к БД

MEDIUM — Стоит посмотреть:
- Стандартные CRUD операции
- Поиск и фильтрация
- API endpoints без явных признаков проблем

LOW — Можно пропустить:
- Статические ресурсы
- Health checks, metrics
- Публичная информация без sensitive data

### ПРАВИЛА ГЕНЕРАЦИИ ЗАМЕТОК (url_note):

**Для HIGH interest** (подробная заметка):
- Опиши назначение и обнаруженные технологии
- Укажи потенциальные уязвимости
- Пример: "Админская панель управления пользователями. Обнаружен PostgreSQL, Express framework. Потенциальная уязвимость Broken Access Control."

**Для MEDIUM interest** (короткая заметка):
- Назначение endpoint'а в 1 предложении
- Пример: "API endpoint для работы с профилем пользователя"

**Для LOW interest** (минимальная заметка):
- Только назначение в самых простых терминах
- Пример: "Статический ресурс - CSS файл"

### ПРИМЕРЫ:

Пример 1 - IDOR:
{
  "interest_level": "high",
  "endpoint_type": "crud",
  "observations": [
    "GET /api/orders/42 возвращает детали заказа",
    "Числовой ID в URL",
    "Ответ содержит email заказчика и сумму платежа"
  ],
  "suggested_checks": [
    {
      "what": "Проверить доступ к чужому заказу",
      "how": "Авторизуйся как другой пользователь и запроси /api/orders/42",
      "why": "Если сервер не проверяет владельца заказа, возможен IDOR"
    }
  ],
  "detected_tech": {
    "database": "MySQL",
    "backend": "unknown",
    "evidence": "Числовые ID типичны для MySQL"
  },
  "tags": ["user-data", "financial", "idor-candidate"],
  "url_note": {
    "content": "Просмотр заказа по ID с потенциальным IDOR. Обнаружен MySQL, ответ содержит финансовые данные.",
    "suspicious": true,
    "vuln_hint": "IDOR - доступ к чужим заказам через подмену ID",
    "confidence": 0.9
  }
}`,
		req.Method,
		req.URL,
		req.ContentType,
		responsePreview,
		techStackInfo,
		blacklist,
	)
}

// BuildHypothesisPrompt создает промпт для генерации гипотез исследования
func BuildHypothesisPrompt(req *models.HypothesisRequest) string {
	contextJson := formatJSON(req.SiteContext)
	patternsJson := formatJSON(req.SuspiciousPatterns)

	// Форматируем результаты верификации если есть
	var verificationJson string
	if req.VerificationResults != nil {
		verificationJson = formatJSON(req.VerificationResults)
	} else {
		verificationJson = "{}"
	}

	// Форматируем кросс-эндпоинт паттерны
	var crossEndpointJson string
	if len(req.CrossEndpointPatterns) > 0 {
		crossEndpointJson = formatJSON(req.CrossEndpointPatterns)
	} else {
		crossEndpointJson = "[]"
	}

	return fmt.Sprintf(
		`Ты — ассистент, помогающий приоритизировать исследование на основе РЕАЛЬНЫХ результатов верификации.

### НАКОПЛЕННЫЙ КОНТЕКСТ САЙТА:
%s

### ОБНАРУЖЕННЫЕ ПАТТЕРНЫ:
%s

### РЕЗУЛЬТАТЫ ВЕРИФИКАЦИИ (ФАКТЫ):
%s

### КРОСС-ЭНДПОИНТ ПАТТЕРНЫ (ВЫСОКИЙ ПРИОРИТЕТ):
%s

### ЗАДАЧА:
На основе РЕАЛЬНЫХ РЕЗУЛЬТАТОВ верификации, предложи ЧТО ИССЛЕДОВАТЬ ДАЛЬШЕ.

ВАЖНО: Используй подтвержденные факты из VerificationResults. Если паттерн не был подтвержден — не рекомендуй его.

### ПРАВИЛА PRIORITY (с учетом верификации):

RECOMMEND — Гарантированные находки или системные проблемы:
- Кросс-эндпоинт паттерны (одна уязвимость на 3+ endpoints)
- Паттерны с Confidence > 0.9 после верификации
- Связанные endpoints с одинаковым типом уязвимости

CONSIDER — Заслуживает внимания:
- Паттерны с Confidence 0.7-0.9
- Endpoints с аналогичной структурой к подтвержденным уязвимостям
- Повторяющиеся patterns

OPTIONAL — Низкий приоритет:
- Паттерны, которые не прошли верификацию (ConfirmedSafe > 0)
- Endpoints без индикаторов уязвимости

### КРОСС-ENDPOINT АНАЛИЗ:
Если видишь один паттерн на 3+ endpoints (cross_endpoint_patterns) — это ВСЕГДА "recommend":
- /users/{id} + /orders/{id} + /profiles/{id} = системная IDOR
- /api/v1/admin/... + /api/v2/admin/... = версионированный обход

### ФОРМАТ ОТВЕТА В JSON:

{
  "investigation_suggestions": [
    {
      "title": "Название области исследования",
      "reasoning": "ПОЧЕМУ это интересно (опирайся на VerificationResults и CrossEndpointPatterns)",
      "affected_endpoints": ["/api/users/{id}", "/api/orders/{id}"],
      "what_to_check": [
        "Конкретный шаг 1",
        "Конкретный шаг 2"
      ],
      "priority": "recommend|consider|optional",
      "cross_endpoint_pattern": "Описание паттерна из CrossEndpointPatterns если есть (если нет паттерна — пустая строка '', не null)"
    }
  ],
  
  "site_understanding": {
    "likely_architecture": "Monolith/Microservices/SPA+API",
    "auth_mechanism": "JWT/Session/API Key/Unknown",
    "data_sensitivity": "Какие sensitive данные видны",
    "attack_surface_summary": "Краткое описание поверхности атаки с учетом верифицированных проблем"
  }
}

### ПРИМЕРЫ:

Пример 1 - Верифицированная IDOR на нескольких endpoints:
{
  "investigation_suggestions": [
    {
      "title": "Подтвержденная IDOR уязвимость на ВСЕХ endpoints",
      "reasoning": "Верификация показала: ConfirmedVulnerable=5 из 5 endpoints. CrossEndpointPattern указывает на системную IDOR в структуре /resource/{id}. Это не теория, это факт.",
      "affected_endpoints": ["/api/users/{id}", "/api/orders/{id}", "/api/invoices/{id}", "/api/profiles/{id}", "/api/products/{id}"],
      "what_to_check": [
        "Выполнить полный аудит всех endpoints с числовыми ID",
        "Проверить, есть ли в коде проверки владения ресурса",
        "Определить масштаб: сколько endpoints затронуто"
      ],
      "priority": "recommend",
      "cross_endpoint_pattern": "IDOR с числовыми ID на 5+ endpoints"
    }
  ],
  "site_understanding": {
    "likely_architecture": "SPA+REST API (Node.js/Express)",
    "auth_mechanism": "JWT токен в Authorization header",
    "data_sensitivity": "Email, phone, orders, financial data - ВСЕ доступны через IDOR",
    "attack_surface_summary": "Критическая IDOR уязвимость на всей API. Необходим полный рефактор проверок доступа."
  }
}

ОТВЕТ СТРОГО В JSON ФОРМАТЕ.
`,
		string(contextJson),
		string(patternsJson),
		string(verificationJson),
		string(crossEndpointJson),
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
	return fmt.Sprintf(
		`Ты - эксперт по безопасности веб-приложений. Твоя задача создать детальный план верификации гипотезы об уязвимости.

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
      "body": "Если нужно",
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

	return fmt.Sprintf(
		`Ты - эксперт по безопасности. Проанализируй результаты верификации гипотезы.

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

// BuildBatchVerificationPrompt создает промпт для батчинга верификации нескольких findings одновременно
func BuildBatchVerificationPrompt(req *models.BatchVerificationRequest) string {
	// Форматируем findings для анализа
	findingsJSON := formatJSON(req.Findings)

	return fmt.Sprintf(
		`Ты — ассистент пентестера на CTF/Bug Bounty.

### КОНТЕКСТ:
Нужно верифицировать %d findings для одного эндпоинта.

Original Request:
- URL: %s
- Method: %s
- Status Code: %d

### FINDINGS ДЛЯ ПРОВЕРКИ:
%s

### РЕЗУЛЬТАТЫ ТЕСТОВ:
%s

### ЗАДАЧА:
Проанализируй все findings и определи статус каждого на основе результатов тестов.

### ИНСТРУКЦИИ:
1. Для каждого finding сравни:
   - Original response vs Test response
   - Status codes
   - Response sizes
   - Response content

2. Определи статус:
   - "verified" - явные признаки уязвимости
   - "likely_true" - скорее уязвимо (70+ процентов уверенность)
   - "likely_false" - скорее безопасно (ответ идентичен или не изменился)
   - "inconclusive" - невозможно определить

3. Дай рассуждение для каждого finding

### ФОРМАТ ОТВЕТА В JSON:
{
  "batch_results": [
    {
      "finding_index": 0,
      "status": "verified|likely_true|likely_false|inconclusive",
      "confidence": 0.0-1.0,
      "reasoning": "Детальное обоснование"
    }
  ]
}

ОТВЕТ В JSON:`,
		len(req.Findings),
		req.OriginalRequest.URL,
		req.OriginalRequest.Method,
		req.OriginalRequest.StatusCode,
		findingsJSON,
		string(formatJSON(req.TestResults)),
	)
}
