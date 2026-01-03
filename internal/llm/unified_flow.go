package llm

import (
	"context"
	"fmt"
	"log"

	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Unified Analysis Flow - Atomic Genkit Flow
// ═══════════════════════════════════════════════════════════════════════════════

// DefineUnifiedAnalysisFlow creates an atomic Genkit flow for unified analysis
// This flow replaces Phases 2+3+4 (Reasoning + Planning + Acting) with a single LLM call
func DefineUnifiedAnalysisFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*UnifiedAnalysisRequest, *UnifiedAnalysisResponse, struct{}] {
	return genkit.DefineFlow(
		g,
		"unifiedAnalysisFlow",
		func(ctx context.Context, req *UnifiedAnalysisRequest) (*UnifiedAnalysisResponse, error) {
			log.Printf("🔍 Starting unified analysis for %s %s", req.Exchange.Request.Method, req.Exchange.Request.URL)

			// Build prompt
			prompt := BuildUnifiedAnalysisPrompt(req)

			// Execute LLM call using genkit.GenerateData
			log.Printf("🤖 Calling LLM for unified analysis")
			result, _, err := genkit.GenerateData[UnifiedAnalysisResponse](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("LLM generation failed: %w", err)
			}

			log.Printf("✅ Unified analysis complete: comment=%s, has_observation=%v, has_connections=%v",
				result.Comment, result.Observation != nil, len(result.Connections) > 0)

			return result, nil
		},
	)
}
