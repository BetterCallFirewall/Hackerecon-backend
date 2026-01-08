package llm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Structure-Preserving Truncation for JSON and Base64 Detection (Phase 3)
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// maxJSONValueLen is the maximum length for JSON string values after truncation
	maxJSONValueLen = 200

	// base64Pattern matches potential base64 encoded data (100+ chars)
	// Base64 strings are typically long and contain only [A-Za-z0-9+/=]
	base64Pattern = `[A-Za-z0-9+/]{100,}={0,2}`
)

var (
	// base64Regex is compiled once for efficiency
	base64Regex = regexp.MustCompile(base64Pattern)
)

// truncateJSONPreservingStructure parses JSON and truncates string values while
// preserving the overall structure (keys, array nesting, object nesting).
//
// Strategy:
// 1. If body is small enough, return as-is
// 2. Parse JSON into generic interface{}
// 3. Recursively truncate string values to maxJSONValueLen
// 4. Marshal back to JSON and return
//
// If parsing fails, falls back to smartTruncateHeadTail for graceful degradation.
func truncateJSONPreservingStructure(body string) string {
	// Fast path: already small enough
	if len(body) <= MaxBodySizeForLLM {
		return body
	}

	// Parse JSON into generic structure
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Invalid JSON - fall back to smart truncation
		return smartTruncateHeadTail(body)
	}

	// Truncate values recursively
	truncated := truncateJSONValues(data, maxJSONValueLen)

	// Marshal back to JSON
	result, err := json.Marshal(truncated)
	if err != nil {
		// Marshal failed - fall back to smart truncation
		return smartTruncateHeadTail(body)
	}

	return string(result)
}

// truncateJSONValues recursively truncates string values in JSON data structure.
//
// Handles:
// - map[string]interface{} (JSON objects)
// - []interface{} (JSON arrays)
// - string (JSON strings) - truncated to maxLen with marker
// - other types (numbers, booleans, null) - returned as-is
//
// Truncation format: "value... [TRUNCATED: N chars]"
func truncateJSONValues(data interface{}, maxLen int) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// JSON object - recursively process values
		result := make(map[string]interface{})
		for key, value := range v {
			result[key] = truncateJSONValues(value, maxLen)
		}
		return result

	case []interface{}:
		// JSON array - recursively process elements
		result := make([]interface{}, len(v))
		for i, elem := range v {
			result[i] = truncateJSONValues(elem, maxLen)
		}
		return result

	case string:
		// String value - truncate if needed (UTF-8 safe)
		if len(v) <= maxLen {
			return v
		}
		truncated := truncateStringUTF8(v, maxLen)
		omitted := len(v) - len(truncated) + 3 // +3 for "..."
		return truncated + fmt.Sprintf(" [TRUNCATED: %d chars]", omitted)

	default:
		// Number, boolean, null - return as-is
		return v
	}
}

// hasBase64Patterns checks if the body contains potential base64 encoded data.
// Uses regex to detect long base64-like strings (100+ chars).
func hasBase64Patterns(body string) bool {
	return base64Regex.MatchString(body)
}

// truncateWithBase64Masking replaces base64 patterns with placeholders.
// This reduces context usage by masking large base64 blobs that are typically
// not useful for security analysis (images, encoded files, etc.).
//
// Placeholder format: [BASE64_DATA_NN_BYTES]
func truncateWithBase64Masking(body string) string {
	// Replace each base64 pattern with a placeholder
	result := base64Regex.ReplaceAllStringFunc(body, func(match string) string {
		// Calculate the approximate decoded size
		// Base64 encoding increases size by ~33%
		decodedSize := len(match) * 3 / 4

		// Verify it's actually valid base64
		if _, err := base64.StdEncoding.DecodeString(match); err != nil {
			// Not valid base64 - return original
			return match
		}

		// Return placeholder with size information
		return fmt.Sprintf("[BASE64_DATA_%d_BYTES]", decodedSize)
	})

	return result
}

// applyBase64MaskingIfLarge applies base64 masking if the body is large
// and contains base64 patterns. This is an optimization step that runs
// after content-type-specific truncation.
func applyBase64MaskingIfLarge(body string) string {
	// Only apply to large bodies (already truncated but still large)
	if len(body) < MaxBodySizeForLLM {
		return body
	}

	// Check for base64 patterns
	if !hasBase64Patterns(body) {
		return body
	}

	// Apply base64 masking
	return truncateWithBase64Masking(body)
}

// truncateBinaryAggressively keeps only a small sample of binary content.
// Most binary data is useless for security analysis, so we truncate aggressively.
// Uses UTF-8 safe truncation to avoid splitting multi-byte characters.
//
// Returns: first 1KB + metadata about omitted content and mime type
func truncateBinaryAggressively(body string, mimeType string) string {
	if len(body) <= binaryMaxSize {
		return body
	}

	head := truncateStringUTF8(body, binaryMaxSize)
	omitted := len(body) - len(head)

	return head + fmt.Sprintf("\n\n[TRUNCATED BINARY: %d bytes omitted - Content-Type: %s]", omitted, mimeType)
}
