package utils

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// TechDetector обнаруживает технологии на основе HTTP ответов
type TechDetector struct {
	// Правила для различных технологий
	techRules map[string][]TechRule
}

// TechRule определяет правило обнаружения технологии
type TechRule struct {
	Name        string
	Category    string
	Patterns    []TechPattern
	Confidence  float64
}

// TechPattern представляет паттерн для обнаружения
type TechPattern struct {
	Type       string   // "header", "html", "js", "cookie", "url"
	Search     string   // что искать
	Regex      *regexp.Regexp // или регулярное выражение
	Version    string   // как извлечь версию
	Confidence float64  // уверенность этого паттерна
}

// NewTechDetector создает новый детектор технологий
func NewTechDetector() *TechDetector {
	return &TechDetector{
		techRules: buildTechRules(),
	}
}

// DetectFromRequest обнаруживает технологии из HTTP запроса/ответа
func (td *TechDetector) DetectFromRequest(req *http.Request, resp *http.Response, body string) *models.TechStack {
	techStack := &models.TechStack{
		Frontend: make([]models.Technology, 0),
		Backend:  make([]models.Technology, 0),
		Database: make([]models.Technology, 0),
		Frameworks: make([]models.Technology, 0),
		Servers:  make([]models.Technology, 0),
		Other:    make([]models.Technology, 0),
	}

	detectedTechs := make(map[string]*models.Technology)

	// Проверяем все правила
	for techName, rules := range td.techRules {
		for _, rule := range rules {
			if tech := td.checkRule(rule, req, resp, body); tech != nil {
				// Объединяем с уже обнаруженной технологией
				if existing, exists := detectedTechs[techName]; exists {
					td.mergeTechnology(existing, tech)
				} else {
					detectedTechs[techName] = tech
				}
			}
		}
	}

	// Распределяем по категориям
	for _, tech := range detectedTechs {
		switch tech.Category {
		case "frontend":
			techStack.Frontend = append(techStack.Frontend, *tech)
		case "backend":
			techStack.Backend = append(techStack.Backend, *tech)
		case "database":
			techStack.Database = append(techStack.Database, *tech)
		case "framework":
			techStack.Frameworks = append(techStack.Frameworks, *tech)
		case "server":
			techStack.Servers = append(techStack.Servers, *tech)
		default:
			techStack.Other = append(techStack.Other, *tech)
		}
	}

	// Вычисляем общую уверенность
	techStack.Confidence = td.calculateOverallConfidence(techStack)

	return techStack
}

// checkRule проверяет одно правило обнаружения
func (td *TechDetector) checkRule(rule TechRule, req *http.Request, resp *http.Response, body string) *models.Technology {
	evidence := make([]models.Evidence, 0)
	totalConfidence := 0.0

	for _, pattern := range rule.Patterns {
		if ev, conf := td.checkPattern(pattern, req, resp, body); ev != nil {
			evidence = append(evidence, *ev)
			totalConfidence += conf
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	// Усредняем уверенность по всем паттернам
	avgConfidence := totalConfidence / float64(len(evidence))
	if avgConfidence < 0.3 { // Минимальный порог уверенности
		return nil
	}

	technology := &models.Technology{
		Name:       rule.Name,
		Category:   rule.Category,
		Confidence: avgConfidence,
		Evidence:   evidence,
	}

	// Пытаемся извлечь версию
	technology.Version = td.extractVersion(evidence)

	return technology
}

// checkPattern проверяет один паттерн
func (td *TechDetector) checkPattern(pattern TechPattern, req *http.Request, resp *http.Response, body string) (*models.Evidence, float64) {
	switch pattern.Type {
	case "header":
		return td.checkHeaderPattern(pattern, resp)
	case "html":
		return td.checkHTMLPattern(pattern, body)
	case "js":
		return td.checkJavaScriptPattern(pattern, body)
	case "cookie":
		return td.checkCookiePattern(pattern, resp)
	case "url":
		return td.checkURLPattern(pattern, req.URL.String())
	}

	return nil, 0
}

// checkHeaderPattern проверяет паттерны в HTTP заголовках
func (td *TechDetector) checkHeaderPattern(pattern TechPattern, resp *http.Response) (*models.Evidence, float64) {
	if resp == nil {
		return nil, 0
	}

	var headers []string
	for name, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, name+": "+value)
		}
	}

	for _, header := range headers {
		if td.matchesPattern(pattern.Search, header) {
			return &models.Evidence{
				Type:       "header",
				Location:   header,
				Content:    pattern.Search,
				Confidence: pattern.Confidence,
			}, pattern.Confidence
		}
	}

	return nil, 0
}

// checkHTMLPattern проверяет паттерны в HTML контенте
func (td *TechDetector) checkHTMLPattern(pattern TechPattern, body string) (*models.Evidence, float64) {
	if body == "" {
		return nil, 0
	}

	if td.matchesPattern(pattern.Search, body) {
		return &models.Evidence{
			Type:       "html",
			Location:   "HTML body",
			Content:    pattern.Search,
			Confidence: pattern.Confidence,
		}, pattern.Confidence
	}

	return nil, 0
}

// checkJavaScriptPattern проверяет паттерны в JavaScript
func (td *TechDetector) checkJavaScriptPattern(pattern TechPattern, body string) (*models.Evidence, float64) {
	if body == "" {
		return nil, 0
	}

	if td.matchesPattern(pattern.Search, body) {
		return &models.Evidence{
			Type:       "js",
			Location:   "JavaScript code",
			Content:    pattern.Search,
			Confidence: pattern.Confidence,
		}, pattern.Confidence
	}

	return nil, 0
}

// checkCookiePattern проверяет паттерны в cookies
func (td *TechDetector) checkCookiePattern(pattern TechPattern, resp *http.Response) (*models.Evidence, float64) {
	if resp == nil {
		return nil, 0
	}

	cookies := resp.Header.Get("Set-Cookie")
	if cookies == "" {
		return nil, 0
	}

	if td.matchesPattern(pattern.Search, cookies) {
		return &models.Evidence{
			Type:       "cookie",
			Location:   "Set-Cookie header",
			Content:    pattern.Search,
			Confidence: pattern.Confidence,
		}, pattern.Confidence
	}

	return nil, 0
}

// checkURLPattern проверяет паттерны в URL
func (td *TechDetector) checkURLPattern(pattern TechPattern, url string) (*models.Evidence, float64) {
	if td.matchesPattern(pattern.Search, url) {
		return &models.Evidence{
			Type:       "url",
			Location:   "URL path",
			Content:    pattern.Search,
			Confidence: pattern.Confidence,
		}, pattern.Confidence
	}

	return nil, 0
}

// matchesPattern проверяет соответствует ли текст паттерну
func (td *TechDetector) matchesPattern(pattern string, text string) bool {
	if strings.Contains(pattern, "regex:") {
		// Регулярное выражение
		regexStr := strings.TrimPrefix(pattern, "regex:")
		re := regexp.MustCompile(regexStr)
		return re.MatchString(text)
	} else {
		// Простая строка
		return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
	}
}

// mergeTechnology объединяет информацию о технологии
func (td *TechDetector) mergeTechnology(existing, new *models.Technology) {
	// Объединяем доказательства
	existing.Evidence = append(existing.Evidence, new.Evidence...)

	// Усредняем уверенность
	if new.Confidence > existing.Confidence {
		existing.Confidence = (existing.Confidence + new.Confidence) / 2
	}

	// Обновляем версию если найдена более точная
	if new.Version != "" && (existing.Version == "" || len(new.Version) > len(existing.Version)) {
		existing.Version = new.Version
	}
}

// extractVersion пытается извлечь версию из доказательств
func (td *TechDetector) extractVersion(evidence []models.Evidence) string {
	for _, ev := range evidence {
		// Ищем паттерны версий в содержимом
		versionRegexes := []*regexp.Regexp{
			regexp.MustCompile(`(\d+\.\d+\.\d+)`),
			regexp.MustCompile(`(\d+\.\d+)`),
			regexp.MustCompile(`v(\d+\.\d+\.\d+)`),
		}

		for _, re := range versionRegexes {
			if matches := re.FindStringSubmatch(ev.Content); len(matches) > 1 {
				return matches[1]
			}
		}
	}

	return ""
}

// calculateOverallConfidence вычисляет общую уверенность
func (td *TechDetector) calculateOverallConfidence(techStack *models.TechStack) float64 {
	total := 0.0
	count := 0

	allTechs := [][]models.Technology{
		techStack.Frontend,
		techStack.Backend,
		techStack.Database,
		techStack.Frameworks,
		techStack.Servers,
		techStack.Other,
	}

	for _, techList := range allTechs {
		for _, tech := range techList {
			total += tech.Confidence
			count++
		}
	}

	if count == 0 {
		return 0.0
	}

	return total / float64(count)
}

// buildTechRules строит правила для обнаружения технологий
func buildTechRules() map[string][]TechRule {
	rules := make(map[string][]TechRule)

	// Frontend технологии
	rules["React"] = []TechRule{{
		Name:     "React",
		Category: "frontend",
		Patterns: []TechPattern{
			{Type: "html", Search: "react-dom", Confidence: 0.8},
			{Type: "html", Search: "data-reactroot", Confidence: 0.9},
			{Type: "js", Search: "React.createElement", Confidence: 0.9},
			{Type: "js", Search: "useState", Confidence: 0.7},
		},
	}}

	rules["Vue.js"] = []TechRule{{
		Name:     "Vue.js",
		Category: "frontend",
		Patterns: []TechPattern{
			{Type: "html", Search: "data-v-", Confidence: 0.8},
			{Type: "js", Search: "Vue.createApp", Confidence: 0.9},
			{Type: "js", Search: "new Vue", Confidence: 0.8},
		},
	}}

	rules["Angular"] = []TechRule{{
		Name:     "Angular",
		Category: "frontend",
		Patterns: []TechPattern{
			{Type: "html", Search: "ng-app", Confidence: 0.9},
			{Type: "js", Search: "ngModule", Confidence: 0.9},
			{Type: "html", Search: "_ngcontent", Confidence: 0.8},
		},
	}}

	// Backend технологии
	rules["Node.js"] = []TechRule{{
		Name:     "Node.js",
		Category: "backend",
		Patterns: []TechPattern{
			{Type: "header", Search: "X-Powered-By: Express", Confidence: 0.9},
			{Type: "header", Search: "X-Powered-By: Node.js", Confidence: 0.9},
		},
	}}

	rules["Express.js"] = []TechRule{{
		Name:     "Express.js",
		Category: "framework",
		Patterns: []TechPattern{
			{Type: "header", Search: "X-Powered-By: Express", Confidence: 0.95},
			{Type: "html", Search: "Cannot GET", Confidence: 0.6},
		},
	}}

	rules["Django"] = []TechRule{{
		Name:     "Django",
		Category: "framework",
		Patterns: []TechPattern{
			{Type: "header", Search: "Server: gunicorn", Confidence: 0.7},
			{Type: "html", Search: "csrfmiddlewaretoken", Confidence: 0.8},
			{Type: "cookie", Search: "csrftoken", Confidence: 0.7},
		},
	}}

	rules["Flask"] = []TechRule{{
		Name:     "Flask",
		Category: "framework",
		Patterns: []TechPattern{
			{Type: "cookie", Search: "session", Confidence: 0.5},
			{Type: "html", Search: "Flask", Confidence: 0.6},
		},
	}}

	// Базы данных
	rules["PostgreSQL"] = []TechRule{{
		Name:     "PostgreSQL",
		Category: "database",
		Patterns: []TechPattern{
			{Type: "html", Search: "postgresql", Confidence: 0.7},
			{Type: "html", Search: "PG::", Confidence: 0.8},
		},
	}}

	rules["MySQL"] = []TechRule{{
		Name:     "MySQL",
		Category: "database",
		Patterns: []TechPattern{
			{Type: "html", Search: "mysql", Confidence: 0.6},
			{Type: "html", Search: "mysqli", Confidence: 0.7},
		},
	}}

	rules["MongoDB"] = []TechRule{{
		Name:     "MongoDB",
		Category: "database",
		Patterns: []TechPattern{
			{Type: "html", Search: "mongodb", Confidence: 0.7},
			{Type: "html", Search: "_id", Confidence: 0.5},
		},
	}}

	// Веб-серверы
	rules["Nginx"] = []TechRule{{
		Name:     "Nginx",
		Category: "server",
		Patterns: []TechPattern{
			{Type: "header", Search: "Server: nginx", Confidence: 0.95},
			{Type: "header", Search: "nginx", Confidence: 0.8},
		},
	}}

	rules["Apache"] = []TechRule{{
		Name:     "Apache",
		Category: "server",
		Patterns: []TechPattern{
			{Type: "header", Search: "Server: Apache", Confidence: 0.95},
			{Type: "header", Search: "Apache", Confidence: 0.8},
		},
	}}

	// PHP
	rules["PHP"] = []TechRule{{
		Name:     "PHP",
		Category: "backend",
		Patterns: []TechPattern{
			{Type: "header", Search: "X-Powered-By: PHP", Confidence: 0.9},
			{Type: "header", Search: "PHP", Confidence: 0.7},
			{Type: "html", Search: ".php", Confidence: 0.6},
		},
	}}

	return rules
}