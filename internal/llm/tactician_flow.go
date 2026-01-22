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

// TacticianRequest - input for Tactician flow
type TacticianRequest struct {
	Task       models.TacticianTask       `json:"task"`
	BigPicture *models.BigPicture         `json:"big_picture"`
	SiteMap    []models.SiteMapEntry      `json:"site_map"`
	Graph      *models.InMemoryGraph      `json:"-"`                             // For tool access
	SystemArch *models.SystemArchitecture `json:"system_architecture,omitempty"` // From Architect
}

// TacticianResult - output from Tactician flow
type TacticianResult struct {
	Leads []models.Lead `json:"leads"`
}

// DefineTacticianFlow creates the Tactician Genkit flow
func DefineTacticianFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*TacticianRequest, *TacticianResult, struct{}] {
	return genkit.DefineFlow(
		g,
		"tacticianFlow",
		func(ctx context.Context, req *TacticianRequest) (*TacticianResult, error) {
			// Check context early
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled before tactician analysis: %w", err)
			}

			log.Printf("🟡 Tactician analyzing task: %s", req.Task.Description)

			// Build prompt with tool support
			prompt := BuildTacticianPrompt(req)

			// Check again after prompt building
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled during tactician prompt building: %w", err)
			}

			result, _, err := genkit.GenerateData[TacticianResult](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithTools(GetExchangeTool), // Provide getExchange tool
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("tactician LLM failed: %w", err)
			}

			log.Printf("✅ Tactician complete: %d leads", len(result.Leads))
			return result, nil
		},
	)
}
