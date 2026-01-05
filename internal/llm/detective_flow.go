package llm

import (
	"context"
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Detective AI Flow - Orchestrates Unified Analysis + Lead Generation
// ═══════════════════════════════════════════════════════════════════════════════

// DetectiveAIRequest represents input for the detective AI orchestration flow
type DetectiveAIRequest struct {
	Exchange           models.HTTPExchange  `json:"exchange"`
	BigPicture         *models.BigPicture   `json:"big_picture,omitempty"`
	RecentObservations []models.Observation `json:"recent_observations,omitempty"`
}

// DetectiveAIResult represents the complete output from detective AI analysis
type DetectiveAIResult struct {
	// Unified analysis results
	Comment          string                   `json:"comment"`
	Observations     []models.Observation     `json:"observations,omitempty"`
	Connections      []models.Connection      `json:"connections,omitempty"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty"`
	SiteMapComment   string                   `json:"site_map_comment,omitempty"`

	// Lead generation results (optional, one lead per observation)
	Leads []*LeadGenerationResponse `json:"leads,omitempty"`
}

// DefineDetectiveAIFlow creates the orchestration flow that coordinates:
// 1. Unified Analysis (atomic flow)
// 2. Lead Generation (optional, conditional on observation)
func DefineDetectiveAIFlow(
	g *genkit.Genkit,
	unifiedFlow func(context.Context, *UnifiedAnalysisRequest) (*UnifiedAnalysisResponse, error),
	leadFlow func(context.Context, *LeadGenerationRequest) (*LeadGenerationResponse, error),
) *genkitcore.Flow[*DetectiveAIRequest, *DetectiveAIResult, struct{}] {
	return genkit.DefineFlow(
		g,
		"detectiveAIFlow",
		func(ctx context.Context, req *DetectiveAIRequest) (*DetectiveAIResult, error) {
			log.Printf("🕵️ Starting Detective AI flow for %s %s", req.Exchange.Request.Method, req.Exchange.Request.URL)

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 1: Unified Analysis (atomic flow)
			// ═══════════════════════════════════════════════════════════════════════════════

			unifiedReq := &UnifiedAnalysisRequest{
				Exchange:           req.Exchange,
				BigPicture:         req.BigPicture,
				RecentObservations: req.RecentObservations,
			}

			unifiedResp, err := genkit.Run(
				ctx, "unifiedAnalysis",
				func() (*UnifiedAnalysisResponse, error) {
					return unifiedFlow(ctx, unifiedReq)
				},
			)
			if err != nil {
				return nil, fmt.Errorf("unified analysis failed: %w", err)
			}

			log.Printf("✅ Unified analysis complete: comment=%s, observations_count=%d",
				unifiedResp.Comment, len(unifiedResp.Observations))

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 2: Lead Generation (optional, conditional - for each observation)
			// NOTE: Each observation can generate 0, 1, or multiple leads
			// ═══════════════════════════════════════════════════════════════════════════════

			var allLeads []*LeadGenerationResponse

			if len(unifiedResp.Observations) > 0 {
				log.Printf("💡 Found %d observation(s), generating leads...", len(unifiedResp.Observations))

				for i, obs := range unifiedResp.Observations {
					leadReq := &LeadGenerationRequest{
						Observation: obs,
						BigPicture:  req.BigPicture,
					}

					leadResult, err := genkit.Run(
						ctx, fmt.Sprintf("leadGeneration_%d", i),
						func() (*LeadGenerationResponse, error) {
							return leadFlow(ctx, leadReq)
						},
					)
					if err != nil {
						// Lead generation is optional, don't fail entire flow
						log.Printf("⚠️ Lead generation failed for observation %d (non-critical): %v", i, err)
					} else {
						allLeads = append(allLeads, leadResult)
						log.Printf("✅ Lead generation complete for observation %d: leads_count=%d",
							i, len(leadResult.Leads))
					}
				}
			} else {
				log.Printf("ℹ️ No observations found, skipping lead generation")
			}

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 3: Combine results
			// ═══════════════════════════════════════════════════════════════════════════════

			result := &DetectiveAIResult{
				Comment:          unifiedResp.Comment,
				Observations:     unifiedResp.Observations,
				Connections:      unifiedResp.Connections,
				BigPictureImpact: unifiedResp.BigPictureImpact,
				SiteMapComment:   unifiedResp.SiteMapComment,
				Leads:            allLeads,
			}

			log.Printf("🎯 Detective AI flow complete: observations_count=%d, leads_count=%d",
				len(result.Observations), len(result.Leads))

			return result, nil
		},
	)
}
