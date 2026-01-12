package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/compat_oai"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Genkit Initialization
// ═══════════════════════════════════════════════════════════════════════════════

// InitGenkitApp initializes a Genkit app with the appropriate LLM provider
// Supports: gemini, openai, ollama, localai, lm-studio
func InitGenkitApp(ctx context.Context, cfg config.LLMConfig) (*genkit.Genkit, error) {
	switch cfg.Provider {
	case "gemini":
		return genkit.Init(
			ctx, genkit.WithPlugins(
				&googlegenai.GoogleAI{
					APIKey: cfg.ApiKey,
				},
			),
		), nil

	case "openai", "ollama", "localai", "lm-studio":
		return genkit.Init(
			ctx, genkit.WithPlugins(
				&compat_oai.OpenAICompatible{
					Provider: cfg.Provider,
					APIKey:   cfg.ApiKey,
					BaseURL:  cfg.BaseURL,
				},
			),
		), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Utility Functions for Detective Flow
// ═══════════════════════════════════════════════════════════════════════════════

// getMiddlewares returns middleware for Genkit LLM calls
// Includes JSON extraction middleware to handle models that return conversational text
func getMiddlewares() []ai.ModelMiddleware {
	return []ai.ModelMiddleware{
		JSONExtractionMiddleware(),
	}
}

// ExtractJSON extracts valid JSON from LLM response
// Handles cases where model adds conversational text before/after JSON
//
// Examples:
//   - "Here's the result: {"key": "value"}" → {"key": "value"}
//   - "```\n{"key": "value"}\n```" → {"key": "value"}
//   - "Sure! ```json\n{"key": "value"}\n```" → {"key": "value"}
//   - "{"key": "value"}" → {"key": "value"} (no change)
//
// Algorithm:
// 1. Try to extract JSON from markdown code blocks (```json...```, ```...```)
// 2. If no markdown, try to find all valid JSON objects using brace matching
// 3. Validate that the extracted string is valid JSON
// 4. If invalid JSON found, return original string
//
// Returns the extracted JSON string, or the original string if no valid JSON is found
func ExtractJSON(rawResponse string) string {
	if rawResponse == "" {
		return rawResponse
	}

	// Strategy 1: Try to extract from markdown code blocks first
	// This handles cases like: ```json\n{...}\n``` or ```\n{...}\n```
	markdownJSON := extractJSONFromMarkdown(rawResponse)
	if markdownJSON != "" && isValidJSONObject(markdownJSON) {
		return markdownJSON
	}

	// Strategy 2: Find all valid JSON objects and return the largest one
	// This handles cases like: "Text {invalid} and then {\"valid\": \"json\"}"
	jsonCandidate := extractAllValidJSON(rawResponse)
	if jsonCandidate != "" {
		return jsonCandidate
	}

	// If no valid JSON found, return original string
	return rawResponse
}

// extractJSONFromMarkdown extracts JSON from markdown code blocks
// Supports: ```json...``` and ```...``` formats
func extractJSONFromMarkdown(text string) string {
	// Try pattern 1: ```json ... ``` (case-insensitive)
	// This handles: ```json, ```JSON, ```Json, etc.
	if idx := findSubstringIndex(text, "```json"); idx != -1 {
		// Find the closing ```
		startIdx := idx + 7 // Skip "```json" (or similar case)
		// Skip whitespace after ```json
		for startIdx < len(text) && (text[startIdx] == ' ' || text[startIdx] == '\t') {
			startIdx++
		}
		// Skip newlines after ```json
		for startIdx < len(text) && (text[startIdx] == '\n' || text[startIdx] == '\r') {
			startIdx++
		}

		// Find the closing ```
		endIdx := strings.Index(text[startIdx:], "```")
		if endIdx != -1 {
			candidate := strings.TrimSpace(text[startIdx : startIdx+endIdx])
			if candidate != "" {
				return candidate
			}
		}
	}

	// Try pattern 2: ``` ... ``` (without language identifier)
	// Find the first occurrence of ``` that's not followed by "json"
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "```") {
			// Skip if it's a json block (already handled above)
			lowerLine := strings.ToLower(trimmedLine)
			if strings.HasPrefix(lowerLine, "```json") {
				continue
			}

			// Found a generic code block, extract content until closing ```
			var contentBuilder strings.Builder
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == "```" {
					candidate := strings.TrimSpace(contentBuilder.String())
					if candidate != "" {
						return candidate
					}
					break
				}
				if contentBuilder.Len() > 0 {
					contentBuilder.WriteString("\n")
				}
				contentBuilder.WriteString(lines[j])
			}
		}
	}

	return ""
}

// extractAllValidJSON finds all valid JSON objects in text and returns the largest one
// Uses a stack-based approach to handle nested objects/arrays
func extractAllValidJSON(text string) string {
	// Find all brace-enclosed candidates
	candidates := []string{}

	// Use a stack to find all complete JSON objects
	stack := 0
	firstBrace := -1

	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '{':
			if stack == 0 {
				firstBrace = i
			}
			stack++
		case '}':
			if stack > 0 {
				stack--
				if stack == 0 && firstBrace != -1 {
					// Found a complete brace-enclosed section
					candidate := text[firstBrace : i+1]
					// Validate it's actual JSON
					if isValidJSONObject(candidate) {
						candidates = append(candidates, candidate)
					}
					firstBrace = -1
				}
			}
		}
	}

	// Return the largest valid JSON object
	if len(candidates) == 0 {
		return ""
	}

	// Find the longest candidate
	longest := candidates[0]
	for _, c := range candidates[1:] {
		if len(c) > len(longest) {
			longest = c
		}
	}

	return longest
}

// extractJSONBraces finds the first '{' and matching last '}'
// Uses a stack-based approach to handle nested objects/arrays
// Deprecated: Use extractAllValidJSON instead
func extractJSONBraces(text string) string {
	firstBrace := strings.Index(text, "{")
	if firstBrace == -1 {
		return ""
	}

	// Use a stack to find the matching closing brace
	stack := 0
	for i := firstBrace; i < len(text); i++ {
		switch text[i] {
		case '{':
			stack++
		case '}':
			stack--
			if stack == 0 {
				// Found the matching closing brace
				candidate := text[firstBrace : i+1]
				return candidate
			}
		}
	}

	// No matching closing brace found
	return ""
}

// isValidJSONObject checks if a string is valid JSON
func isValidJSONObject(s string) bool {
	if s == "" {
		return false
	}
	// Simple check: must start with '{' or '[' and end with '}' or ']'
	trimmed := strings.TrimSpace(s)
	if len(trimmed) == 0 {
		return false
	}

	firstChar := trimmed[0]
	lastChar := trimmed[len(trimmed)-1]

	if (firstChar == '{' && lastChar == '}') || (firstChar == '[' && lastChar == ']') {
		// Try to parse it
		var js any
		return json.Unmarshal([]byte(trimmed), &js) == nil
	}

	return false
}

// findSubstringIndex finds the index of a substring, case-insensitive
func findSubstringIndex(s, substr string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(substr))
}

// JSONExtractionMiddleware wraps Genkit middleware to extract JSON from model responses
// This is needed because some LLM models return conversational text along with JSON,
// which causes JSON parsing errors in GenerateData[T]
//
// Example problematic responses:
//   - "Here's the analysis result: {"observations": [...]}"
//   - "Sure! Let me analyze that for you.\n\n```json\n{"key": "value"}\n```"
//
// This middleware intercepts the response and extracts only the valid JSON part
// before the response is parsed into the target struct.
//
// IMPORTANT: This middleware modifies the ModelResponse.Message.Content in-place.
// It only processes text parts, leaving tool requests and other part types intact.
func JSONExtractionMiddleware() ai.ModelMiddleware {
	return func(next ai.ModelFunc) ai.ModelFunc {
		return func(ctx context.Context, input *ai.ModelRequest, cb ai.ModelStreamCallback) (*ai.ModelResponse, error) {
			// Call the next middleware/model in the chain
			resp, err := next(ctx, input, cb)
			if err != nil {
				return nil, err
			}

			// Extract JSON from the response text
			if resp != nil && resp.Message != nil && len(resp.Message.Content) > 0 {
				for i, part := range resp.Message.Content {
					// Only process text parts
					if part.IsText() && part.Text != "" {
						extracted := ExtractJSON(part.Text)
						// Update the part text if we successfully extracted JSON
						if extracted != "" && extracted != part.Text {
							resp.Message.Content[i].Text = extracted
						}
					}
				}
			}

			return resp, nil
		}
	}
}

// getContentType safely extracts Content-Type header, handling nil maps
func getContentType(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	return headers["Content-Type"]
}

// formatHeaders formats headers map to plain text (NOT JSON to avoid LLM confusion)
// Returns "Key: Value\nKey2: Value2" format instead of JSON
// This prevents LLM from copying header names into observation JSON fields
func formatHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return "(none)"
	}

	var result string
	for k, v := range headers {
		if result != "" {
			result += "\n  "
		}
		result += fmt.Sprintf("%s: %s", k, v)
	}
	return result
}

// truncateStringUTF8 safely truncates a string to maxLen, respecting UTF-8 boundaries
// This prevents splitting multi-byte characters (e.g., emojis, non-Latin scripts)
func truncateStringUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Find the last UTF-8 boundary before maxLen
	for i := maxLen; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i] + "..."
		}
	}

	// If we can't find a boundary, return first character only
	return string([]rune(s)[:1]) + "..."
}

// TruncateString truncates a string to maxLen with "..." suffix if needed
// Deprecated: Use truncateStringUTF8 for UTF-8 safe truncation
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TruncateBody truncates body to maxLen with truncation marker showing bytes omitted
// Uses UTF-8 safe truncation to avoid splitting multi-byte characters
func TruncateBody(body string, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}
	// Use UTF-8 safe truncation
	truncated := truncateStringUTF8(body, maxLen)
	omitted := len(body) - len(truncated) + 3 // +3 for "..."
	return truncated + fmt.Sprintf("\n\n[TRUNCATED: %d bytes omitted]", omitted)
}

const (
	// MaxBodySizeForLLM is the maximum body size for LLM analysis (10KB)
	// This prevents sending large binary data (images, videos, etc.) to the LLM
	MaxBodySizeForLLM = 10_000

	// Smart truncation thresholds
	minThreshold  = 5_000  // Don't truncate if smaller than this
	maxHTMLSize   = 50_000 // HTML parsing threshold
	binaryMaxSize = 1_000  // Binary content limit
)

// contentTypeInfo holds parsed content-type information for smart truncation
type contentTypeInfo struct {
	mimeType     string
	isBinary     bool
	isHTML       bool
	isStructured bool // JSON, XML
}

// parseContentType extracts mime type and detects content characteristics
func parseContentType(ctHeader string) contentTypeInfo {
	info := contentTypeInfo{}

	// Extract mime type (before semicolon)
	if ctHeader == "" {
		return info
	}

	parts := strings.Split(ctHeader, ";")
	if len(parts) == 0 {
		return info
	}

	info.mimeType = strings.TrimSpace(strings.ToLower(parts[0]))

	// Detect binary types
	binaryPrefixes := []string{
		"image/", "video/", "audio/",
		"application/pdf", "application/octet-stream",
	}
	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(info.mimeType, prefix) {
			info.isBinary = true
			break
		}
	}

	// Detect HTML
	if info.mimeType == "text/html" {
		info.isHTML = true
	}

	// Detect structured formats (JSON, XML)
	structuredTypes := []string{
		"application/json", "text/json",
		"application/xml", "text/xml",
	}
	for _, st := range structuredTypes {
		if info.mimeType == st {
			info.isStructured = true
			break
		}
	}

	return info
}

// smartTruncateHeadTail keeps first 60% and last 40% of max size
// Preserves both headers and footers of content (useful for HTML forms, etc.)
// Uses UTF-8 safe truncation to avoid splitting multi-byte characters
func smartTruncateHeadTail(body string) string {
	if len(body) <= MaxBodySizeForLLM {
		return body
	}

	headSize := int(float64(MaxBodySizeForLLM) * 0.6) // First 60%
	tailSize := MaxBodySizeForLLM - headSize          // Last 40%
	tailStart := len(body) - tailSize

	omitted := len(body) - MaxBodySizeForLLM
	// Use UTF-8 safe truncation for head
	head := truncateStringUTF8(body, headSize)
	// Adjust tail start position based on actual head length
	tailStart = len(body) - tailSize

	return head + fmt.Sprintf("\n\n[TRUNCATED: %d bytes omitted] ...\n\n", omitted) + body[tailStart:]
}

// prepareBodyForLLM applies content-type-aware truncation to reduce LLM context usage
// while preserving security-relevant information
func prepareBodyForLLM(body, contentType string, isRequest bool) string {
	// Fast path: skip small bodies
	if len(body) <= minThreshold {
		return body
	}

	ct := parseContentType(contentType)

	var result string

	switch {
	case ct.isBinary:
		result = truncateBinaryAggressively(body, ct.mimeType)
	case ct.isHTML:
		// Phase 2: Extract security-relevant elements from HTML
		// This preserves forms, scripts, meta tags, etc. while reducing context by 85-90%
		result = extractHTMLSecurityElements(body)
	case ct.isStructured:
		// Phase 3: Structure-preserving truncation for JSON
		if strings.Contains(ct.mimeType, "json") {
			result = truncateJSONPreservingStructure(body)
		}
		// XML: use smart truncation for now (full XML support not implemented)
		if result == "" {
			result = smartTruncateHeadTail(body)
		}
	default:
		// Unknown content type - use head/tail truncation
		result = smartTruncateHeadTail(body)
	}

	// Phase 3: Apply base64 masking as additional optimization
	// This runs after content-type-specific truncation to catch any remaining base64
	result = applyBase64MaskingIfLarge(result)

	return result
}

// PrepareExchangeForLLM creates a copy of exchange with truncated bodies for LLM analysis
// Uses content-type-aware smart truncation to reduce context usage while preserving
// security-relevant information
func PrepareExchangeForLLM(exchange models.HTTPExchange) models.HTTPExchange {
	result := exchange
	result.Request.Body = prepareBodyForLLM(
		exchange.Request.Body,
		getContentType(exchange.Request.Headers),
		true,
	)
	result.Response.Body = prepareBodyForLLM(
		exchange.Response.Body,
		getContentType(exchange.Response.Headers),
		false,
	)
	return result
}

// FormatObservations formats observations as a numbered list
// If includeHint is true, adds the Hint field when present
func FormatObservations(obs []models.Observation, includeHint bool) string {
	result := ""
	for i, o := range obs {
		hint := ""
		if includeHint && o.Hint != nil {
			hint = fmt.Sprintf("\n   Hint: %s", *o.Hint)
		}
		// Format ExchangeIDs for display
		exchangeIDs := ""
		if len(o.ExchangeIDs) > 0 {
			exchangeIDs = fmt.Sprintf("\n   Exchanges: %v", o.ExchangeIDs)
		}
		result += fmt.Sprintf(
			"%d. %s\n   Where: %s\n   Why: %s%s%s\n\n", i+1, o.What, o.Where, o.Why, exchangeIDs, hint,
		)
	}
	return result
}

// summarizeRequest analyzes a request and returns summary tags
// Checks for query parameters in URL and JSON content type in body
func summarizeRequest(req models.RequestPart) string {
	var tags []string

	// Check for query parameters in URL
	if strings.Contains(req.URL, "?") {
		tags = append(tags, "[Params in URL]")
	}

	// Check for JSON content-type header
	if req.Headers != nil {
		contentType := req.Headers["Content-Type"]
		if strings.Contains(strings.ToLower(contentType), "application/json") ||
			strings.Contains(strings.ToLower(contentType), "text/json") {
			tags = append(tags, "[JSON Body]")
		}
	}

	return strings.Join(tags, " ")
}

// analyzeURL performs heuristic analysis on URL patterns
// Detects JSON in URLs and MongoDB ObjectID patterns
func analyzeURL(url string) string {
	// Check for JSON in URL (contains both { and })
	if strings.Contains(url, "{") && strings.Contains(url, "}") {
		return "[JSON in URL detected!]"
	}

	// Check for MongoDB ObjectID pattern (24 hex characters in URL path)
	// MongoDB ObjectIDs are 24-character hex strings
	// We look for this pattern in the URL path (not in query parameters)
	pathOnly := url
	if idx := strings.Index(url, "?"); idx != -1 {
		pathOnly = url[:idx]
	}

	// Split path by / and look for 24-char hex strings
	segments := strings.Split(pathOnly, "/")
	for _, segment := range segments {
		// Check if segment is exactly 24 hex characters
		if len(segment) == 24 {
			isHex := true
			for _, c := range segment {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					isHex = false
					break
				}
			}
			if isHex {
				return "[MongoDB ObjectID]"
			}
		}
	}

	return ""
}

// FormatSiteMap formats site map entries as a bulleted list with heuristic analysis
// NOTE: Updated for new architecture - no longer has direct access to Request/Response
// Uses TrafficDigest if available, otherwise falls back to URL-based analysis only
func FormatSiteMap(entries []models.SiteMapEntry) string {
	result := ""
	for _, e := range entries {
		var tags []string

		// If TrafficDigest is available, use its architectural info
		if e.Digest != nil {
			// Add route signature if available
			if e.Digest.RouteSignature != "" {
				tags = append(tags, fmt.Sprintf("[%s]", e.Digest.RouteSignature))
			}
			// Add tech stack hints
			if len(e.Digest.TechStackHints) > 0 {
				tags = append(tags, fmt.Sprintf("[%s]", strings.Join(e.Digest.TechStackHints, ", ")))
			}
		}

		// Fall back to URL-based heuristics if no digest
		urlTags := analyzeURL(e.URL)
		if urlTags != "" {
			tags = append(tags, urlTags)
		}

		// Format the entry
		entry := fmt.Sprintf("- ID: %s | %s %s", e.ExchangeID, e.Method, e.URL)
		if len(tags) > 0 {
			entry += fmt.Sprintf(" %s", strings.Join(tags, " "))
		}
		entry += "\n"

		result += entry
	}
	return result
}

// FormatDigestsForArchitect turns TrafficDigest array into formatted text for Architect
// Formats traffic analysis data with route signatures, logic summaries, and I/O types
func FormatDigestsForArchitect(digests []models.TrafficDigest) string {
	var sb strings.Builder

	sb.WriteString("=== TRAFFIC ANALYSIS LOG (Data Flow & Types) ===\n\n")

	for i, digest := range digests {
		// Header: [1] GET /api/users/{id}
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, digest.RouteSignature))

		// Summary
		sb.WriteString(fmt.Sprintf("    Logic: %s\n", digest.Summary))

		// Inputs (with types)
		if len(digest.Inputs) > 0 {
			sb.WriteString("    In:  ")
			var ins []string
			for _, in := range digest.Inputs {
				// Example: id (mongo_object_id)
				ins = append(ins, fmt.Sprintf("%s (%s)", in.Name, in.DataType))
			}
			sb.WriteString(strings.Join(ins, ", ") + "\n")
		}

		// Outputs (with types)
		if len(digest.Outputs) > 0 {
			sb.WriteString("    Out: ")
			var outs []string
			for _, out := range digest.Outputs {
				outs = append(outs, fmt.Sprintf("%s (%s)", out.Name, out.DataType))
			}
			sb.WriteString(strings.Join(outs, ", ") + "\n")
		}

		// Tech stack
		if len(digest.TechStackHints) > 0 {
			sb.WriteString(fmt.Sprintf("    Tech: %s\n", strings.Join(digest.TechStackHints, ", ")))
		}

		sb.WriteString("\n")
	}

	return sb.String()
}
