package driven

import (
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/PuerkitoBio/goquery"
)

// Пакет-уровневые паттерны для оптимизации hot path
// Компилируются один раз при запуске программы
var (
	// commentRegex - паттерн для извлечения HTML комментариев
	commentRegex = regexp.MustCompile(`<!--(.*?)-->`)
)

// DataExtractor извлекает только критически важные данные из HTTP контента
// Упрощенная версия после рефакторинга - убраны избыточные regex, LLM справляется лучше
type DataExtractor struct{}

// NewDataExtractor создает новый экстрактор данных
func NewDataExtractor() *DataExtractor {
	return &DataExtractor{}
}

// ExtractFromContent извлекает только критически важные данные из HTTP контента
// LLM справляется с поиском секретов, URL и JS функций лучше, чем regex
func (e *DataExtractor) ExtractFromContent(reqBody, respBody, contentType string) models.ExtractedData {
	extractedData := models.ExtractedData{
		FormActions: make([]string, 0),
		Comments:    make([]string, 0),
	}

	contents := []string{reqBody, respBody}

	for _, content := range contents {
		if content == "" {
			continue
		}

		// Анализируем только HTML контент для form actions и комментариев
		if e.isHTMLContent(content, contentType) {
			e.extractHTMLData(content, &extractedData)
		}
	}

	return extractedData
}

// isHTMLContent проверяет является ли контент HTML
func (e *DataExtractor) isHTMLContent(content, contentType string) bool {
	return strings.Contains(contentType, "html") ||
		strings.Contains(content, "<html") ||
		strings.Contains(content, "<!DOCTYPE")
}

// extractHTMLData извлекает данные из HTML напрямую в extractedData
func (e *DataExtractor) extractHTMLData(content string, data *models.ExtractedData) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return
	}

	// Извлекаем form actions
	doc.Find("form[action]").Each(
		func(i int, s *goquery.Selection) {
			if action, exists := s.Attr("action"); exists && action != "#" {
				data.FormActions = append(data.FormActions, action)
			}
		},
	)

	// Извлекаем комментарии
	comments := commentRegex.FindAllStringSubmatch(content, -1)
	for _, match := range comments {
		if len(match) >= 2 {
			comment := strings.TrimSpace(match[1])
			if len(comment) > 5 && !strings.HasPrefix(comment, "<!") {
				data.Comments = append(data.Comments, llm.TruncateString(comment, maxCommentLength))
			}
		}
	}
}
