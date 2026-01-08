package llm

import (
	"context"
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ArchitectRequest - input for Architect flow
type ArchitectRequest struct {
	RawObservations []models.Observation  `json:"raw_observations"`
	SiteMap         []models.SiteMapEntry `json:"site_map"`
}

// ArchitectResult - output from Architect flow
type ArchitectResult struct {
	SystemArchitecture models.SystemArchitecture `json:"system_architecture"`
}

// DefineArchitectFlow creates the Architect Genkit flow
func DefineArchitectFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*ArchitectRequest, *ArchitectResult, struct{}] {
	return genkit.DefineFlow(
		g,
		"architectFlow",
		func(ctx context.Context, req *ArchitectRequest) (*ArchitectResult, error) {
			// Check context early
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled before architect analysis: %w", err)
			}

			log.Printf("🟣 Architect analyzing %d observations with %d routes",
				len(req.RawObservations), len(req.SiteMap))

			prompt := BuildArchitectPrompt(req)

			// Check again after prompt building
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled during architect prompt building: %w", err)
			}

			result, _, err := genkit.GenerateData[ArchitectResult](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("architect LLM failed: %w", err)
			}

			log.Printf("✅ Architect complete: TechStack='%s', %d data flows",
				result.SystemArchitecture.TechStack,
				len(result.SystemArchitecture.DataFlows))
			return result, nil
		},
	)
}
