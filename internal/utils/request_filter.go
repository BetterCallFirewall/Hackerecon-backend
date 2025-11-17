package utils

import (
	"net/http"
	"strings"
	"time"
)

// RequestFilter фильтрует мусорные запросы, которые не нужно анализировать
type RequestFilter struct {
	// Списки исключений
	staticExtensions     []string
	analyticsPaths       []string
	staticPaths          []string
	contentTypeBlacklist []string

	// Паттерны для определения бизнес-логики
	businessLogicPatterns []string

	// Кэш для производительности
	filterCache map[string]bool
	cacheExpiry time.Duration
	lastCleanup time.Time
}

// NewRequestFilter создает новый фильтр запросов
func NewRequestFilter() *RequestFilter {
	return &RequestFilter{
		staticExtensions: []string{
			"css", "js", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2", "ttf", "eot",
			"pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "tar", "gz",
			"mp3", "mp4", "avi", "mov", "wmv", "flv",
		},
		analyticsPaths: []string{
			"/analytics", "/metrics", "/ga.js", "/gtag.js", "/pixel",
			"/tracking", "/beacon", "/stats", "/counter",
		},
		staticPaths: []string{
			"/static/", "/assets/", "/public/", "/img/", "/images/", "/css/", "/js/",
			"/fonts/", "/media/", "/uploads/", "/files/", "/downloads/",
		},
		contentTypeBlacklist: []string{
			"application/octet-stream",
			"image/", "video/", "audio/",
			"font/", "application/font",
		},
		businessLogicPatterns: []string{
			"/api/", "/v1/", "/v2/", "/v3/", "/admin/", "/user/", "/users/",
			"/profile/", "/order/", "/orders/", "/cart/", "/payment/", "/billing/",
			"/auth/", "/login/", "/register/", "/logout/", "/signup/", "/signin/",
			"/settings/", "/account/", "/dashboard/", "/panel/", "/manage/",
			"/create/", "/edit/", "/update/", "/delete/", "/remove/",
		},
		filterCache: make(map[string]bool),
		cacheExpiry: 5 * time.Minute,
		lastCleanup: time.Now(),
	}
}

// ShouldSkipRequestWithReason определяет, нужно ли пропустить анализ и возвращает причину
func (rf *RequestFilter) ShouldSkipRequestWithReason(req *http.Request, resp *http.Response, contentType string) (
	bool, string,
) {
	url := req.URL.String()

	// Проверяем кэш
	cacheKey := rf.getCacheKey(req.Method, url, contentType)
	if cached, exists := rf.filterCache[cacheKey]; exists {
		return cached, "cached decision"
	}

	shouldSkip, reason := rf.evaluateSkipRulesWithReason(req, resp, contentType)

	// Кэшируем результат
	rf.filterCache[cacheKey] = shouldSkip

	// Периодическая очистка кэша
	if time.Since(rf.lastCleanup) > rf.cacheExpiry {
		rf.cleanupCache()
		rf.lastCleanup = time.Now()
	}

	return shouldSkip, reason
}

// evaluateSkipRulesWithReason применяет правила фильтрации и возвращает причину
func (rf *RequestFilter) evaluateSkipRulesWithReason(req *http.Request, resp *http.Response, contentType string) (
	bool, string,
) {
	url := req.URL.String()
	method := req.Method

	// 1. Статические файлы по расширению
	for _, ext := range rf.staticExtensions {
		if strings.HasSuffix(strings.ToLower(url), "."+ext) {
			return true, "static file extension: ." + ext
		}
	}

	// 2. Пути аналитики и отслеживания
	for _, path := range rf.analyticsPaths {
		if strings.Contains(url, path) {
			return true, "analytics/tracking path: " + path
		}
	}

	// 3. Статические директории
	for _, path := range rf.staticPaths {
		if strings.HasPrefix(url, path) {
			return true, "static directory: " + path
		}
	}

	// 4. Фильтрация по Content-Type
	for _, ct := range rf.contentTypeBlacklist {
		if strings.Contains(contentType, ct) {
			return true, "blacklisted content-type: " + ct
		}
	}

	// 6. robots.txt, sitemap.xml, favicon.ico
	if rf.isKnownStaticFile(url) {
		return true, "known static file"
	}

	// 7. HEAD/OPTIONS запросы (обычно технические)
	if method == "HEAD" || method == "OPTIONS" {
		return true, "technical method: " + method
	}

	// 8. Если запрос похож на бизнес-логику - не пропускаем
	if rf.isLikelyBusinessLogicEndpoint(url, method) {
		return false, "business logic endpoint"
	}

	// 9. POST/PUT/DELETE запросы почти всегда важны
	if rf.isDataModifyingMethod(method) {
		return false, "data modifying method: " + method
	}

	// 10. GET запросы с JSON/XML/HTML ответами важны
	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "text/html") {
		return false, "important content-type: " + contentType
	}

	// 11. По умолчанию для GET запросов с текстовыми ответами не пропускаем
	if method == "GET" && (strings.Contains(contentType, "text/") || contentType == "") {
		return false, "text or empty content-type"
	}

	// Если дошли сюда - вероятно, это статика, пропускаем
	return true, "default skip (likely static)"
}

// IsLikelyBusinessLogicEndpoint проверяет, является ли эндпоинт бизнес-логикой
func (rf *RequestFilter) isLikelyBusinessLogicEndpoint(url, method string) bool {
	for _, pattern := range rf.businessLogicPatterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}

	// POST/PUT/DELETE почти всегда бизнес-логика
	if rf.isDataModifyingMethod(method) {
		return true
	}

	// API эндпоинты
	if strings.Contains(url, "/api/") || strings.Contains(url, "/v1/") || strings.Contains(url, "/v2/") {
		return true
	}

	return false
}

// isKnownStaticFile проверяет известные статические файлы
func (rf *RequestFilter) isKnownStaticFile(url string) bool {
	staticFiles := []string{
		"/robots.txt", "/sitemap.xml", "/favicon.ico", "/sitemap_index.xml",
		"/browserconfig.xml", "/manifest.json", "/.well-known/",
	}

	for _, file := range staticFiles {
		if strings.Contains(url, file) {
			return true
		}
	}

	return false
}

// isDataModifyingMethod проверяет модифицирует ли метод данные
func (rf *RequestFilter) isDataModifyingMethod(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
}

// GetFilterStats возвращает статистику фильтрации
func (rf *RequestFilter) GetFilterStats() map[string]interface{} {
	total := len(rf.filterCache)
	skipped := 0

	for _, shouldSkip := range rf.filterCache {
		if shouldSkip {
			skipped++
		}
	}

	return map[string]interface{}{
		"total_cached": total,
		"skipped":      skipped,
		"analyzed":     total - skipped,
		"skip_rate":    float64(skipped) / float64(total),
		"cache_size":   len(rf.filterCache),
	}
}

// getCacheKey создает ключ для кэша
func (rf *RequestFilter) getCacheKey(method, url, contentType string) string {
	// Нормализуем URL для кэша (убираем query параметры)
	parts := strings.Split(url, "?")
	baseURL := parts[0]

	// Нормализуем contentType
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}

	return method + ":" + baseURL + ":" + contentType
}

// cleanupCache очищает устаревшие записи кэша
func (rf *RequestFilter) cleanupCache() {
	// Простая реализация - очищаем половину кэша
	if len(rf.filterCache) > 1000 {
		newCache := make(map[string]bool)
		count := 0

		// Оставляем последние записи
		for key, value := range rf.filterCache {
			if count < 500 {
				newCache[key] = value
				count++
			}
		}

		rf.filterCache = newCache
	}
}

// ClearCache очищает кэш фильтрации
func (rf *RequestFilter) ClearCache() {
	rf.filterCache = make(map[string]bool)
	rf.lastCleanup = time.Now()
}
