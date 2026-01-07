package llm

import (
	"context"
	"fmt"

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
// Currently returns empty slice - can be extended with retry middleware if needed
func getMiddlewares() []ai.ModelMiddleware {
	// No middleware in detective flow
	// Old retry middleware was removed as part of simplification
	return []ai.ModelMiddleware{}
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

// TruncateString truncates a string to maxLen with "..." suffix if needed
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TruncateBody truncates body to maxLen with truncation marker showing bytes omitted
func TruncateBody(body string, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}
	omitted := len(body) - maxLen
	return body[:maxLen] + fmt.Sprintf("\n\n... [TRUNCATED: %d bytes omitted]", omitted)
}

const (
	// MaxBodySizeForLLM is the maximum body size for LLM analysis (10KB)
	// This prevents sending large binary data (images, videos, etc.) to the LLM
	MaxBodySizeForLLM = 10_000
)

// PrepareExchangeForLLM creates a copy of exchange with truncated bodies for LLM analysis
// This prevents sending large binary data (images, videos, etc.) to the LLM
func PrepareExchangeForLLM(exchange models.HTTPExchange) models.HTTPExchange {
	result := exchange

	// Truncate request body if needed
	if len(exchange.Request.Body) > MaxBodySizeForLLM {
		result.Request.Body = TruncateBody(exchange.Request.Body, MaxBodySizeForLLM)
	}

	// Truncate response body if needed
	if len(exchange.Response.Body) > MaxBodySizeForLLM {
		result.Response.Body = TruncateBody(exchange.Response.Body, MaxBodySizeForLLM)
	}

	return result
}

// FormatObservations formats observations as a numbered list
// If includeHint is true, adds the Hint field when present
func FormatObservations(obs []models.Observation, includeHint bool) string {
	result := ""
	for i, o := range obs {
		hint := ""
		if includeHint && o.Hint != "" {
			hint = fmt.Sprintf("\n   Hint: %s", o.Hint)
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

// FormatSiteMap formats site map entries as a bulleted list
func FormatSiteMap(entries []models.SiteMapEntry) string {
	result := ""
	for _, e := range entries {
		result += fmt.Sprintf("- %s %s. ID - %s\n", e.Method, e.URL, e.ExchangeID)
	}
	return result
}
