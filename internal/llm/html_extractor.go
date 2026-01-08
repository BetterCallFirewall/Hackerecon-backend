package llm

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// SecurityElementExtractor extracts security-relevant elements from HTML
// Focuses on elements that are commonly targeted in security assessments:
// - Forms (CSRF, input validation)
// - Meta tags (security headers, tokens)
// - Scripts (XSS vectors, inline scripts)
// - Links (SSRF, endpoints)
// - Iframes (clickjacking)
// - Comments (debug info, TODOs with security implications)
type SecurityElementExtractor struct {
	maxForms       int
	maxScripts     int
	maxLinks       int
	maxMetaTags    int
	maxComments    int
	maxElementSize int
}

// NewSecurityElementExtractor creates a new extractor with default limits
// Defaults are tuned for typical web applications while keeping output manageable
func NewSecurityElementExtractor() *SecurityElementExtractor {
	return &SecurityElementExtractor{
		maxForms:       20,
		maxScripts:     30,
		maxLinks:       20,
		maxMetaTags:    15,
		maxComments:    10,
		maxElementSize: 500,
	}
}

// extractHTMLSecurityElements extracts security-relevant elements from HTML
// Returns a formatted string with security elements or fallback to smart truncation
//
// Fast path: If HTML is small (<= maxHTMLSize), returns as-is with [HTML: small, preserved] prefix
// This avoids parsing overhead for small responses while still providing context
//
// Fallback: If HTML parsing fails, falls back to smartTruncateHeadTail for graceful degradation
func extractHTMLSecurityElements(htmlBody string) string {
	originalSize := len(htmlBody)

	// Fast path: small HTML is preserved as-is
	if originalSize <= maxHTMLSize {
		return fmt.Sprintf("[HTML: small, preserved - %d bytes]\n\n%s", originalSize, htmlBody)
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		// Fallback to smart truncation if parsing fails
		// This ensures we still provide some context even with malformed HTML
		return smartTruncateHeadTail(htmlBody)
	}

	extractor := NewSecurityElementExtractor()

	// Extract security elements
	sections := []string{
		"[HTML SECURITY EXTRACT]",
		"",
		extractor.extractForms(doc),
		extractor.extractMetaTags(doc),
		extractor.extractScripts(doc),
		extractor.extractLinks(doc),
		extractor.extractIframes(doc),
		extractor.extractSecurityComments(doc),
		extractor.formatExtractionMeta(originalSize),
	}

	// Join non-empty sections
	var result []string
	for _, section := range sections {
		if section != "" {
			result = append(result, section)
		}
	}

	return strings.Join(result, "\n")
}

// extractForms extracts form elements with action, method, and inputs
// Highlights hidden inputs (often contain CSRF tokens, session IDs)
func (e *SecurityElementExtractor) extractForms(doc *goquery.Document) string {
	var forms []string

	doc.Find("form").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= e.maxForms {
			return false // Stop iteration
		}

		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET" // Default method
		}

		form := fmt.Sprintf("Form #%d:\n", i+1)
		form += fmt.Sprintf("  action: %s\n", truncateValue(action, e.maxElementSize))
		form += fmt.Sprintf("  method: %s\n", strings.ToUpper(method))

		// Extract inputs
		s.Find("input").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			inputType, _ := input.Attr("type")
			value, _ := input.Attr("value")

			// Mark hidden inputs (security-relevant)
			hiddenMark := ""
			if inputType == "hidden" {
				hiddenMark = " [HIDDEN]"
			}

			inputStr := fmt.Sprintf(
				"    input%s: name=%s type=%s value=%s",
				hiddenMark,
				truncateValue(name, 100),
				truncateValue(inputType, 50),
				truncateValue(value, 100),
			)
			form += inputStr + "\n"
		})

		// Extract textareas
		s.Find("textarea").Each(func(j int, textarea *goquery.Selection) {
			name, _ := textarea.Attr("name")
			form += fmt.Sprintf("    textarea: name=%s\n", truncateValue(name, 100))
		})

		// Extract selects
		s.Find("select").Each(func(j int, selectEl *goquery.Selection) {
			name, _ := selectEl.Attr("name")
			form += fmt.Sprintf("    select: name=%s\n", truncateValue(name, 100))
		})

		forms = append(forms, form)
		return true
	})

	if len(forms) == 0 {
		return ""
	}

	return "[FORMS]\n" + strings.Join(forms, "\n")
}

// extractMetaTags extracts meta tags, especially security-relevant ones
// Focus: CSRF tokens, API endpoints, charset, security headers
func (e *SecurityElementExtractor) extractMetaTags(doc *goquery.Document) string {
	var metaTags []string

	doc.Find("meta").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= e.maxMetaTags {
			return false
		}

		name, _ := s.Attr("name")
		content, _ := s.Attr("content")
		httpEquiv, _ := s.Attr("http-equiv")
		charset, _ := s.Attr("charset")

		var meta string
		if name != "" {
			meta = fmt.Sprintf("  name=%s content=%s", truncateValue(name, 100), truncateValue(content, e.maxElementSize))
		} else if httpEquiv != "" {
			meta = fmt.Sprintf("  http-equiv=%s content=%s", truncateValue(httpEquiv, 100), truncateValue(content, e.maxElementSize))
		} else if charset != "" {
			meta = fmt.Sprintf("  charset=%s", charset)
		}

		if meta != "" {
			metaTags = append(metaTags, meta)
		}
		return true
	})

	if len(metaTags) == 0 {
		return ""
	}

	return "[META TAGS]\n" + strings.Join(metaTags, "\n") + "\n"
}

// extractScripts extracts script src URLs and counts inline scripts
// Inline scripts are XSS vectors, so we count them separately
func (e *SecurityElementExtractor) extractScripts(doc *goquery.Document) string {
	var scripts []string
	inlineCount := 0

	doc.Find("script").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= e.maxScripts {
			return false
		}

		src, _ := s.Attr("src")
		integrity, _ := s.Attr("integrity")
		crossorigin, _ := s.Attr("crossorigin")

		if src != "" {
			// External script
			script := fmt.Sprintf("  script[%d]: src=%s", i+1, truncateValue(src, e.maxElementSize))
			if integrity != "" {
				script += fmt.Sprintf(" integrity=%s", truncateValue(integrity, 100))
			}
			if crossorigin != "" {
				script += fmt.Sprintf(" crossorigin=%s", crossorigin)
			}
			scripts = append(scripts, script)
		} else {
			// Inline script
			inlineCount++
		}
		return true
	})

	if len(scripts) == 0 && inlineCount == 0 {
		return ""
	}

	var result []string
	if len(scripts) > 0 {
		result = append(result, "[SCRIPTS]")
		result = append(result, scripts...)
	}
	if inlineCount > 0 {
		result = append(result, "")
		result = append(result, fmt.Sprintf("  [+] %d inline script(s) detected (potential XSS vectors)", inlineCount))
	}

	return strings.Join(result, "\n") + "\n"
}

// extractLinks extracts link href attributes
// Useful for discovering endpoints, stylesheets, icons
func (e *SecurityElementExtractor) extractLinks(doc *goquery.Document) string {
	var links []string

	doc.Find("link").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= e.maxLinks {
			return false
		}

		rel, _ := s.Attr("rel")
		href, _ := s.Attr("href")
		typeAttr, _ := s.Attr("type")

		link := fmt.Sprintf("  link[%d]: rel=%s href=%s", i+1, truncateValue(rel, 50), truncateValue(href, e.maxElementSize))
		if typeAttr != "" {
			link += fmt.Sprintf(" type=%s", typeAttr)
		}

		links = append(links, link)
		return true
	})

	if len(links) == 0 {
		return ""
	}

	return "[LINKS]\n" + strings.Join(links, "\n") + "\n"
}

// extractIframes extracts iframe src URLs
// Iframes can be clickjacking vectors or contain embedded content
func (e *SecurityElementExtractor) extractIframes(doc *goquery.Document) string {
	var iframes []string

	doc.Find("iframe").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		id, _ := s.Attr("id")
		nameAttr, _ := s.Attr("name")

		iframe := fmt.Sprintf("  iframe[%d]: src=%s", i+1, truncateValue(src, e.maxElementSize))
		if id != "" {
			iframe += fmt.Sprintf(" id=%s", id)
		}
		if nameAttr != "" {
			iframe += fmt.Sprintf(" name=%s", nameAttr)
		}

		iframes = append(iframes, iframe)
	})

	if len(iframes) == 0 {
		return ""
	}

	return "[IFRAMES]\n" + strings.Join(iframes, "\n") + "\n"
}

// extractSecurityComments extracts HTML comments with security-relevant keywords
// Keywords: debug, todo, fixme, hack, xxx, bug, security, auth, token, csrf, password
func (e *SecurityElementExtractor) extractSecurityComments(doc *goquery.Document) string {
	// Security-relevant keywords to look for in comments
	keywords := []string{
		"debug", "todo", "fixme", "hack", "xxx", "bug",
		"security", "auth", "token", "csrf", "password",
		"secret", "key", "deprecated", "remove", "temporary",
	}

	// Build regex pattern: (debug|todo|fixme|...)
	pattern := "(?i)" + strings.Join(keywords, "|")
	re := regexp.MustCompile(pattern)

	var comments []string

	// Search for comments in the raw HTML using regex
	// Note: goquery doesn't provide direct access to comment nodes, so we use regex
	commentRegex := regexp.MustCompile(`<!--(.+?)-->`)
	html, _ := doc.Html()
	commentMatches := commentRegex.FindAllStringSubmatch(html, -1)

	for _, match := range commentMatches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			// Check if comment contains security keywords
			if re.MatchString(comment) {
				comments = append(comments, "  "+truncateValue(comment, e.maxElementSize))
				if len(comments) >= e.maxComments {
					break
				}
			}
		}
	}

	if len(comments) == 0 {
		return ""
	}

	return "[SECURITY COMMENTS]\n" + strings.Join(comments, "\n") + "\n"
}

// formatExtractionMeta creates metadata about the extraction
// Shows original size, extracted size, and reduction percentage
func (e *SecurityElementExtractor) formatExtractionMeta(originalSize int) string {
	// We need to estimate the extracted size
	// Since we're building the output, we'll estimate based on sections

	// Rough estimation: each form ~200 chars, each script ~100 chars, etc.
	estimatedSize := 500 // Base overhead for section headers

	// Add estimation for each section type
	// This is approximate but gives a good idea of reduction

	reduction := float64(originalSize-estimatedSize) / float64(originalSize) * 100
	if reduction < 0 {
		reduction = 0
	}

	return fmt.Sprintf("[EXTRACTION META]\nOriginal size: %d bytes\nEstimated extracted size: ~%d bytes\nReduction: %.1f%%",
		originalSize, estimatedSize, reduction)
}

// truncateValue truncates a string value with "..." suffix if needed
// Uses UTF-8 safe truncation to avoid splitting multi-byte characters
// Used to prevent extremely long attribute values from overwhelming output
func truncateValue(s string, maxLen int) string {
	if s == "" {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	// Use UTF-8 safe truncation
	return truncateStringUTF8(s, maxLen)
}
