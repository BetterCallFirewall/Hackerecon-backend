package driven

import (
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/PuerkitoBio/goquery"
)

// DataExtractor извлекает данные из HTTP контента
type DataExtractor struct {
	secretPatterns []*regexp.Regexp
}

// NewDataExtractor создает новый экстрактор данных
func NewDataExtractor(secretPatterns []*regexp.Regexp) *DataExtractor {
	return &DataExtractor{
		secretPatterns: secretPatterns,
	}
}

// ExtractFromContent извлекает данные из HTTP контента
func (e *DataExtractor) ExtractFromContent(reqBody, respBody, contentType string) *models.ExtractedData {
	extractedData := &models.ExtractedData{
		URLs:          make([]string, 0),
		APIKeys:       make([]models.ExtractedSecret, 0),
		Secrets:       make([]models.ExtractedSecret, 0),
		JSFunctions:   make([]models.JSFunction, 0),
		FormActions:   make([]string, 0),
		Comments:      make([]string, 0),
		ExternalHosts: make([]string, 0),
	}

	contents := []string{reqBody, respBody}
	locations := []string{"request", "response"}

	for i, content := range contents {
		if content == "" {
			continue
		}

		location := locations[i]

		// Извлекаем секреты
		secrets := e.extractSecrets(content, location)
		extractedData.APIKeys = append(extractedData.APIKeys, secrets...)

		// Анализируем JavaScript контент
		if e.isJavaScriptContent(content, contentType) {
			jsFunctions := e.extractJavaScriptFunctions(content)
			extractedData.JSFunctions = append(extractedData.JSFunctions, jsFunctions...)

			urls := e.extractURLsFromJS(content)
			extractedData.URLs = append(extractedData.URLs, urls...)
		}

		// Анализируем HTML контент
		if e.isHTMLContent(content, contentType) {
			htmlData := e.extractHTMLData(content)
			extractedData.FormActions = append(extractedData.FormActions, htmlData.FormActions...)
			extractedData.Comments = append(extractedData.Comments, htmlData.Comments...)
			extractedData.URLs = append(extractedData.URLs, htmlData.URLs...)
		}
	}

	return extractedData
}

// isJavaScriptContent проверяет является ли контент JavaScript
func (e *DataExtractor) isJavaScriptContent(content, contentType string) bool {
	return strings.Contains(contentType, "javascript") ||
		strings.Contains(content, "function") ||
		strings.Contains(content, "const ") ||
		strings.Contains(content, "var ")
}

// isHTMLContent проверяет является ли контент HTML
func (e *DataExtractor) isHTMLContent(content, contentType string) bool {
	return strings.Contains(contentType, "html") ||
		strings.Contains(content, "<html") ||
		strings.Contains(content, "<!DOCTYPE")
}

// extractSecrets извлекает секреты с помощью regex
func (e *DataExtractor) extractSecrets(content, location string) []models.ExtractedSecret {
	secrets := make([]models.ExtractedSecret, 0)

	for _, pattern := range e.secretPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				secretValue := strings.Trim(match[2], `"'`)

				if len(secretValue) < minSecretLength {
					continue
				}

				// Передаем сырые данные, LLM сам определит тип и важность
				secrets = append(secrets, models.ExtractedSecret{
					Type:       "potential_secret", // LLM определит конкретный тип
					Value:      truncateSecret(secretValue),
					Context:    truncateString(match[0], maxContextLength),
					Confidence: 0.5, // Базовая уверенность, LLM уточнит
					Location:   location,
				})
			}
		}
	}

	return secrets
}

// extractJavaScriptFunctions извлекает JavaScript функции
func (e *DataExtractor) extractJavaScriptFunctions(content string) []models.JSFunction {
	functions := make([]models.JSFunction, 0)

	funcRegex := regexp.MustCompile(`function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)`)
	matches := funcRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			funcName := match[1]
			params := e.parseParameters(match[2])

			// Передаем сырые данные, LLM сам определит подозрительность
			functions = append(functions, models.JSFunction{
				Name:       funcName,
				Parameters: params,
				Context:    truncateString(match[0], maxFunctionContextLength),
				Suspicious: false, // LLM определит
				Reason:     "",    // LLM определит
			})
		}
	}

	return functions
}

// parseParameters разбирает параметры функции
func (e *DataExtractor) parseParameters(paramsStr string) []string {
	if paramsStr == "" {
		return []string{}
	}

	params := strings.Split(strings.TrimSpace(paramsStr), ",")
	for i, param := range params {
		params[i] = strings.TrimSpace(param)
	}

	return params
}

// extractURLsFromJS извлекает URL'ы из JavaScript
func (e *DataExtractor) extractURLsFromJS(content string) []string {
	urls := make([]string, 0)

	for _, regex := range urlRegexes {
		matches := regex.FindAllString(content, -1)
		urls = append(urls, matches...)
	}

	return removeDuplicates(urls)
}

// extractHTMLData извлекает данные из HTML с помощью goquery
func (e *DataExtractor) extractHTMLData(content string) *models.HTMLData {
	data := &models.HTMLData{
		FormActions: make([]string, 0),
		Comments:    make([]string, 0),
		URLs:        make([]string, 0),
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return data
	}

	e.extractFormActions(doc, data)
	e.extractLinks(doc, data)
	e.extractComments(content, data)

	return data
}

// extractFormActions извлекает form actions из HTML
func (e *DataExtractor) extractFormActions(doc *goquery.Document, data *models.HTMLData) {
	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		if action, exists := s.Attr("action"); exists && action != "#" {
			data.FormActions = append(data.FormActions, action)
		}
	})
}

// extractLinks извлекает все ссылки из HTML
func (e *DataExtractor) extractLinks(doc *goquery.Document, data *models.HTMLData) {
	doc.Find("a[href], script[src], img[src], iframe[src]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && href != "#" {
			data.URLs = append(data.URLs, href)
		}
		if src, exists := s.Attr("src"); exists {
			data.URLs = append(data.URLs, src)
		}
	})
}

// extractComments извлекает комментарии из HTML
func (e *DataExtractor) extractComments(content string, data *models.HTMLData) {
	commentRegex := regexp.MustCompile(`<!--(.*?)-->`)
	comments := commentRegex.FindAllStringSubmatch(content, -1)

	for _, match := range comments {
		if len(match) >= 2 {
			comment := strings.TrimSpace(match[1])
			if len(comment) > 5 && !strings.HasPrefix(comment, "<!") {
				data.Comments = append(data.Comments, truncateString(comment, maxCommentLength))
			}
		}
	}
}
