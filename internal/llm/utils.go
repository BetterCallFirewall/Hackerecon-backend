package llm

import (
	"context"
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
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
