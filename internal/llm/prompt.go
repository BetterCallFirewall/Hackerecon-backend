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
Ты — элитный специалист по кибербезопасности, специализирующийся на поиске уязвимостей в бизнес-логике и определении технологий по HTTP трафику.

### ТЕКУЩИЙ HTTP-ОБМЕН:
URL: %s
Метод: %s
Headers: %v
Content-Type: %s

Request Body (truncated):
%s

Response Body (truncated):
%s

### ИЗВЛЕЧЕННЫЕ ДАННЫЕ:
%s

### КОНТЕКСТ СЕССИИ (%s):
%s

### ТВОИ ЗАДАЧИ:

1.  **ОПРЕДЕЛЕНИЕ ТЕХНОЛОГИЙ (КРИТИЧЕСКИ ВАЖНО!):**
    *   **База данных:** Ищи следы PostgreSQL, MySQL, MongoDB, Redis в:
        - Error messages ("pq:", "mysql_", "mongo", "SQLSTATE")
        - Response headers (X-Database, X-Powered-By)
        - Query syntax в параметрах (WHERE id = $1 → PostgreSQL, WHERE id = ? → MySQL)
        - Stack traces с именами драйверов
    *   **Backend Framework:** Express.js, Django, Flask, Spring Boot, Laravel - ищи в:
        - Headers: Server, X-Powered-By, X-Framework
        - Cookies: sessionid, csrftoken, express.sid
        - Error traces и stack traces
        - URL patterns (Django: /api/v1/, Flask: /admin/, Spring: /actuator/)
    *   **Frontend:** React, Vue, Angular - ищи в JavaScript, HTML comments
    *   **Структура запросов (БД hints):**
        - JSON body с filters/where → ORM (Django, Prisma) ИЛИ NoSQL (MongoDB)
        - JSON с вложенными объектами → вероятно MongoDB/NoSQL
        - Query params ?id=123 → REST API (SQL БД)
        - GraphQL queries → GraphQL + любая БД
        - Form data → традиционный backend (SQL)
    *   **ЕСЛИ НАШЕЛ** → укажи в поле "identified_tech_stack" в формате:
        {"database": "PostgreSQL", "backend": "Express.js", "confidence": 0.9}

2.  **АНАЛИЗ СТРУКТУРЫ ЗАПРОСА (важно для понимания БД и уязвимостей):**
    *   **Формат идентификаторов:**
        - URL: /users/123 → числовой ID (SQL БД, IDOR риск!)
        - URL: /users/507f1f77bcf86cd799439011 → MongoDB ObjectId (24 hex символа)
        - URL: /users/uuid-123-456 → UUID (SQL/NoSQL, меньше риск IDOR)
        - URL: /users/@username → username в URL
    *   **Формат фильтров и тела запроса:**
        - Query params: ?filter[status]=active&filter[role]=admin → ORM (Rails, Laravel, Prisma) + SQL
        - JSON body: {"where": {"status": "active"}} → ORM (Prisma, Sequelize) + SQL
        - JSON с $operators: {"status": {"$eq": "active"}} → MongoDB (NoSQL Injection риск!)
        - JSON вложенные объекты: {"user": {"profile": {"age": 25}}} → вероятно MongoDB
        - GraphQL: {users(filter: {status: "active"})} → GraphQL + любая БД
        - SQL-like: ?q=SELECT * FROM users → ОПАСНО! SQL Injection candidate
    *   **Порядок параметров:**
        - /api/v1/users/{user_id}/orders/{order_id} → иерархия (проверить owner check!)
        - Параметры в body vs URL → где передается ID владельца?
    *   **Анализируй на IDOR:**
        - Есть ли owner_id/user_id в запросе? Или только целевой ID?
        - Можно ли подменить ID и получить чужие данные?

3.  **АНАЛИЗ БИЗНЕС-ЛОГИКИ (Рассуждай по шагам - Chain of Thought):**
    *   **Шаг 1: Каково назначение этого запроса?** Опиши бизнес-операцию ("обновление профиля", "просмотр заказа", "удаление пользователя").
    *   **Шаг 2: Сопоставь с контекстом.** Есть ли аномалии?
        - Пользователь с ролью 'user' → админский endpoint '/api/v1/users/delete'?
        - Манипуляция ID (order_id не принадлежит user)?
        - Неожиданное изменение состояния?
    *   **Шаг 3: Сформулируй гипотезы уязвимостей** (IDOR, Broken Access Control, Race Conditions, SQL/NoSQL Injection в фильтрах).

3.  **ПОИСК ТЕХНИЧЕСКИХ УЯЗВИМОСТЕЙ:**
    *   **SQL Injection** (если SQL БД: PostgreSQL, MySQL) - WHERE, ORDER BY, LIMIT
    *   **NoSQL Injection** (если MongoDB) - $operators ($eq, $ne, $gt, $regex), JSON injection
    *   XSS, CSRF, Command Injection, Path Traversal
    *   Отсутствие заголовков безопасности (CSP, HSTS, X-Frame-Options)
    *   Критичность найденных секретов и API keys

4.  **ОБОГАЩЕНИЕ КОНТЕКСТА:**
    *   **identified_user_role**: роль пользователя ('guest', 'user', 'admin', 'service')
    *   **identified_data_objects**: объекты данных с полями (например: [{"name": "order", "fields": ["id", "user_id", "total"]}])
    *   **identified_tech_stack**: обнаруженные технологии ({"database": "PostgreSQL", "backend": "Express", "confidence": 0.8})

5.  **ИТОГОВЫЙ ВЕРДИКТ (Строго в формате JSON):**
    *   **risk_level**: СТРОГО одно из: "low", "medium", "high", "critical" (маленькими буквами)
    *   **ai_comment**: Объясни ход мыслей (на русском) - что нашел, почему это уязвимость, как эксплуатировать
    *   **security_checklist**: 3-5 способов проверки уязвимости. Формат:
        [{"action": "Подмена user_id", "description": "GET /api/orders/123 → GET /api/orders/456", "expected": "403 Forbidden если защита есть, 200 OK если IDOR"}]
    *   **recommendations**: конкретные рекомендации по исправлению

ПРИОРИТЕТЫ:
✅ Бизнес-логика > технические уязвимости
✅ Определение БД и технологий - критически важно для контекста!
⚠️  Понижай риск если нужен brute-force ключей
⚠️  HTTP вместо HTTPS - не критично

ОТВЕТ СТРОГО В JSON согласно схеме (все текстовые поля на русском).
`,
		req.URL,
		req.Method,
		req.Headers,
		req.ContentType,
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
func BuildURLAnalysisPrompt(req *models.URLAnalysisRequest) string {
	techStackInfo := "не определен"
	if req.SiteContext.TechStack != nil {
		techStackInfo = formatTechStackCompact(req.SiteContext.TechStack)
	}

	// Подготовка короткого фрагмента ответа для анализа
	responsePreview := TruncateString(req.ResponseBody, 300)

	return fmt.Sprintf(
		`
Ты - эксперт по веб-безопасности и анализу технологий. Быстро оцени этот эндпоинт.

### ЗАПРОС:
%s %s
Content-Type: %s
Response preview (300 символов): %s

### ТЕКУЩИЙ СТЕК ТЕХНОЛОГИЙ:
%s

### ТВОИ ЗАДАЧИ:

1. **ОПРЕДЕЛИ ТЕХНОЛОГИИ** (критически важно для контекста):
   - База данных: ищи PostgreSQL, MySQL, MongoDB, Redis в headers, error messages, query syntax ($1/$2 → PostgreSQL, ? → MySQL)
   - Backend: Node.js/Express, Django, Flask, Spring, Laravel - headers, cookies, error traces
   - Frontend: React, Vue, Angular - HTML, JavaScript bundles
   - **Структура запроса (БД hints):**
     * JSON filters: {"where": {...}} → ORM + SQL (Prisma, Sequelize)
     * JSON с $operators: {"$eq": ...} → MongoDB (NoSQL)
     * MongoDB ObjectId (24 hex): 507f1f77bcf86cd799439011 → точно MongoDB
     * Query params: ?filter[status]=active → Rails/Laravel + SQL
     * GraphQL queries → GraphQL + любая БД
   - Если нашел - укажи в "context": "MongoDB (ObjectId + $operators), Express. NoSQL Injection риск!"

2. **ОЦЕНИ НАЗНАЧЕНИЕ ЭНДПОИНТА**:
   - Бизнес-логика (авторизация, CRUD операции, платежи) → should_analyze: true, priority: high
   - API эндпоинты с данными → should_analyze: true
   - Статика, аналитика, health checks → should_analyze: false, priority: low

3. **ПРОВЕРЬ ПОДОЗРИТЕЛЬНОСТЬ**:
   - Админские эндпоинты без защиты
   - IDOR паттерны (/users/{id}, /orders/{id}) - особенно числовые ID!
   - Необычные параметры или методы
   - **Структура ID:** числовой (SQL, IDOR риск!) vs MongoDB ObjectId (24 hex) vs UUID
   - **Фильтры:** SQL-like → SQL Injection риск! JSON с $operators → NoSQL Injection!

ПРИМЕРЫ ХОРОШИХ ОТВЕТОВ:

Пример 1 - Админский endpoint:
{
    "url_note": {
        "content": "Управление пользователями (admin)",
        "suspicious": true,
        "vuln_hint": "Возможен Broken Access Control",
        "confidence": 0.9,
        "context": "Обнаружено: PostgreSQL (X-DB header), Express (cookies). Админская операция."
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 2 - IDOR кандидат с числовым ID:
{
    "url_note": {
        "content": "Просмотр заказа по ID",
        "suspicious": true,
        "vuln_hint": "IDOR - числовой ID, нет owner check",
        "confidence": 0.9,
        "context": "Обнаружено: MySQL (error message). Числовой {id} - высокий риск IDOR!"
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 3 - MongoDB с операторами:
{
    "url_note": {
        "content": "Поиск пользователей с фильтрами",
        "suspicious": true,
        "vuln_hint": "NoSQL Injection - MongoDB $operators",
        "confidence": 0.85,
        "context": "MongoDB (ObjectId 507f..., JSON body: {\"status\": {\"$eq\": \"active\"}}). NoSQL Injection риск!"
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 4 - SQL фильтры:
{
    "url_note": {
        "content": "Список пользователей с фильтрами",
        "suspicious": true,
        "vuln_hint": "SQL Injection в filter параметрах",
        "confidence": 0.75,
        "context": "PostgreSQL (headers). Query params: ?filter[status]=active - ORM style. Проверить экранирование."
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 4 - Статика:
{
    "url_note": {
        "content": "JavaScript bundle",
        "suspicious": false,
        "confidence": 1.0,
        "context": "Статический ресурс"
    },
    "should_analyze": false,
    "priority": "low"
}

**КРИТИЧЕСКИ ВАЖНО:** В поле "context" ОБЯЗАТЕЛЬНО укажи НАЙДЕННЫЕ ТЕХНОЛОГИИ (БД, framework), если обнаружил!

ОТВЕТ СТРОГО В JSON (все текстовые поля на русском):
`,
		req.Method,
		req.NormalizedURL,
		req.ContentType,
		responsePreview,
		techStackInfo,
	)
}

// BuildFullSecurityAnalysisPrompt создает промпт для полного анализа (с заметкой)
func BuildFullSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest, urlNote *models.URLNote) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	extractedDataJson, _ := json.MarshalIndent(req.ExtractedData, "", "  ")

	urlNoteJson, _ := json.MarshalIndent(urlNote, "", "  ")

	return fmt.Sprintf(
		`
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

	previousHypothesisText := "Нет предыдущей гипотезы"
	if req.PreviousHypothesis != nil {
		phJson, _ := json.MarshalIndent(req.PreviousHypothesis, "", "  ")
		previousHypothesisText = string(phJson)
	}

	// Форматируем стек технологий
	techStackDesc := "Стек технологий не определен"
	if req.SiteContext.TechStack != nil {
		techStackDesc = fmt.Sprintf(
			"Frontend: %s, Backend: %s, Database: %s",
			formatTechList(req.SiteContext.TechStack.Frontend),
			formatTechList(req.SiteContext.TechStack.Backend),
			formatTechList(req.SiteContext.TechStack.Database),
		)
	}

	return fmt.Sprintf(
		`
ГЕНЕРАЦИЯ ГЛАВНОЙ ГИПОТЕЗЫ УЯЗВИМОСТИ

Ты - эксперт по пентесту с опытом анализа сложных бизнес-логик. На основе накопленных данных сформируй ГЛАВНУЮ гипотезу уязвимости.

### ОБНАРУЖЕННЫЙ СТЕК ТЕХНОЛОГИЙ:
%s

### ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ (%d найдено):
%s

### ИЗВЕСТНЫЕ УЯЗВИМОСТИ ТЕХНОЛОГИЙ:
%v

### КОНТЕКСТ САЙТА (URL patterns, заметки):
%s

### ПРЕДЫДУЩАЯ ГИПОТЕЗА:
%s

### ТВОЯ ЗАДАЧА:
Сформируй НАИБОЛЕЕ ВЕРОЯТНУЮ гипотезу уязвимости, которую можно протестировать.

АНАЛИЗ (рассуждай по шагам):
1. **Определи паттерн атаки:** 
   - IDOR (разные {id} в URL без проверки владения)
   - Broken Access Control (admin endpoints доступны user)
   - SQL Injection (если нашли БД и подозрительные параметры)
   - Business Logic flaws (sequence bypass, race conditions)

2. **Учитывай технологии:**
   - PostgreSQL/MySQL → SQLi возможна
   - MongoDB → NoSQL injection
   - Express/Node.js → prototype pollution
   - Django → ORM injection

3. **Найди связи между эндпоинтами:**
   - Есть ли CRUD операции над одним объектом?
   - Видны ли admin и user endpoints для одних данных?
   - Есть ли последовательности (create → view → delete)?

4. **Сравни с предыдущей гипотезой:**
   - Подтверждается или опровергается?
   - Нужно изменить вектор атаки?

ПРИМЕР ХОРОШЕЙ ГИПОТЕЗЫ:
{
    "hypothesis": {
        "id": "idor_orders_001",
        "title": "IDOR в просмотре заказов",
        "description": "Endpoint /api/orders/{id} позволяет получить любой заказ, подменив {id}. Проверка владения отсутствует.",
        "attack_vector": "IDOR (Insecure Direct Object Reference)",
        "target_urls": ["/api/orders/{id}", "/api/orders/{id}/details"],
        "attack_sequence": [
            {"step": 1, "action": "Авторизация как user_123", "description": "POST /api/login с user_123 credentials", "expected": "Получить JWT токен"},
            {"step": 2, "action": "Получить свой заказ", "description": "GET /api/orders/100 (свой order_id)", "expected": "200 OK, данные своего заказа"},
            {"step": 3, "action": "IDOR атака", "description": "GET /api/orders/101 (чужой order_id)", "expected": "Если уязвимость: 200 OK + чужие данные. Если защита: 403 Forbidden"}
        ],
        "required_role": "user",
        "prereqs": ["аутентификация", "известные order_id"],
        "confidence": 0.85,
        "impact": "high",
        "effort": "low",
        "status": "active"
    },
    "reasoning": "Найдены 2 эндпоинта с {id} параметром для orders. В Notes указано 'просмотр заказа' без упоминания проверки владения. Стандартный паттерн IDOR. База данных: PostgreSQL, скорее всего проверка на уровне app, а не БД. Confidence 0.85 потому что видели успешные запросы к обоим эндпоинтам."
}

ОТВЕТ СТРОГО В JSON (все текстовые поля на русском):
`,
		techStackDesc,
		len(req.SuspiciousPatterns),
		string(suspiciousJson),
		req.TechVulnerabilities,
		string(contextJson),
		previousHypothesisText,
	)
}

// Вспомогательные функции

func formatTechList(techs []models.Technology) string {
	if len(techs) == 0 {
		return "не определено"
	}

	names := make([]string, 0, len(techs))
	for _, tech := range techs {
		if tech.Version != "" {
			names = append(names, fmt.Sprintf("%s v%s", tech.Name, tech.Version))
		} else {
			names = append(names, tech.Name)
		}
	}

	return strings.Join(names, ", ")
}

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
