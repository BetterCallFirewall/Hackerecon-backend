package llm

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// StrategistRequest - input for Strategist flow
type StrategistRequest struct {
	RawObservations    []models.Observation       `json:"raw_observations"`
	SiteMap            []models.SiteMapEntry      `json:"site_map"`
	BigPicture         *models.BigPicture         `json:"big_picture"`
	SystemArchitecture *models.SystemArchitecture `json:"system_architecture"` // NEW
}

// StrategistResult - output from Strategist flow
type StrategistResult struct {
	Observations     []models.Observation     `json:"observations"`
	Connections      []models.Connection      `json:"connections"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty"`
	TacticianTasks   []models.TacticianTask   `json:"tactician_tasks"`
	// REMOVED: TechnicalProfile - now in SystemArchitecture
}

// DefineStrategistFlow creates the Strategist Genkit flow
func DefineStrategistFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*StrategistRequest, *StrategistResult, struct{}] {
	return genkit.DefineFlow(
		g,
		"strategistFlow",
		func(ctx context.Context, req *StrategistRequest) (*StrategistResult, error) {
			// Check context early
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled before strategist analysis: %w", err)
			}

			log.Printf("🟢 Strategist analyzing %d raw observations", len(req.RawObservations))

			prompt := BuildStrategistPrompt(req)

			// Check again after prompt building
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled during strategist prompt building: %w", err)
			}

			result, _, err := genkit.GenerateData[StrategistResult](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("strategist LLM failed: %w", err)
			}

			// Set timestamps on connections
			for i := range result.Connections {
				if result.Connections[i].CreatedAt.IsZero() {
					result.Connections[i].CreatedAt = time.Now()
				}
			}

			log.Printf("✅ Strategist complete: %d aggregated obs, %d tasks",
				len(result.Observations), len(result.TacticianTasks))
			return result, nil
		},
	)
}
