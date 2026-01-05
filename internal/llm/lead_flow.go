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
// Lead Generation Flow - Atomic Genkit Flow
// ═══════════════════════════════════════════════════════════════════════════════

// DefineLeadGenerationFlow creates an atomic Genkit flow for lead generation
// This flow is called separately after unified analysis completes
func DefineLeadGenerationFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*LeadGenerationRequest, *LeadGenerationResponse, struct{}] {
	return genkit.DefineFlow(
		g,
		"leadGenerationFlow",
		func(ctx context.Context, req *LeadGenerationRequest) (*LeadGenerationResponse, error) {
			log.Printf("💡 Starting lead generation for observation: %s", req.Observation.What)

			// Build prompt
			prompt := BuildLeadGenerationPrompt(req)

			// Execute LLM call using genkit.GenerateData
			log.Printf("🤖 Calling LLM for lead generation")
			result, _, err := genkit.GenerateData[LeadGenerationResponse](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("LLM generation failed: %w", err)
			}

			log.Printf("✅ Lead generation complete: leads_count=%d", len(result.Leads))
			for i, lead := range result.Leads {
				log.Printf("   Lead %d: is_actionable=%v, title=%s, pocs_count=%d",
					i, lead.IsActionable, lead.Title, len(lead.PoCs))
			}

			return result, nil
		},
	)
}
