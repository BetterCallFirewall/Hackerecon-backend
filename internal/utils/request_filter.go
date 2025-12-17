package utils

import (
	"net/http"
	"strings"
)

// RequestFilter фильтрует мусорные запросы, которые не нужно анализировать
type RequestFilter struct {
	// Maps для O(1) lookup (оптимизация)
	staticExtensions     map[string]struct{}
	analyticsPaths       []string
	staticPaths          []string
	contentTypeBlacklist []string

	// Паттерны для определения бизнес-логики
	businessLogicPatterns []string
}

// NewRequestFilter создает новый фильтр запросов
func NewRequestFilter() *RequestFilter {
	// OPTIMIZATION: Use map for O(1) extension lookup instead of O(n) slice iteration
	extensionsMap := make(map[string]struct{})
	extensions := []string{
		"css", "js", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2", "ttf", "eot",
		"pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "tar", "gz",
		"mp3", "mp4", "avi", "mov", "wmv", "flv",
	}
	for _, ext := range extensions {
		extensionsMap[ext] = struct{}{}
	}

	return &RequestFilter{
		staticExtensions: extensionsMap,
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
	}
}

// ShouldSkipRequestWithReason определяет, нужно ли пропустить анализ и возвращает причину
func (rf *RequestFilter) ShouldSkipRequestWithReason(req *http.Request, resp *http.Response, contentType string) (bool, string) {
	return rf.evaluateSkipRulesWithReason(req, resp, contentType)
}

// evaluateSkipRulesWithReason применяет правила фильтрации и возвращает причину
func (rf *RequestFilter) evaluateSkipRulesWithReason(req *http.Request, resp *http.Response, contentType string) (bool, string) {
	url := req.URL.String()
	method := req.Method

	// 1. Статические файлы по расширению - OPTIMIZED: O(1) map lookup
	urlLower := strings.ToLower(url)
	if lastDot := strings.LastIndex(urlLower, "."); lastDot != -1 {
		ext := urlLower[lastDot+1:]
		if _, isStatic := rf.staticExtensions[ext]; isStatic {
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
