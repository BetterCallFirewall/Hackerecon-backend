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
	Observation      *models.Observation      `json:"observation,omitempty"`
	Connections      []models.Connection      `json:"connections,omitempty"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty"`
	SiteMapComment   string                   `json:"site_map_comment,omitempty"`

	// Lead generation results (optional, only if observation exists)
	Lead *LeadGenerationResponse `json:"lead,omitempty"`
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

			log.Printf("✅ Unified analysis complete: comment=%s, has_observation=%v",
				unifiedResp.Comment, unifiedResp.Observation != nil)

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 2: Lead Generation (optional, conditional)
			// ═══════════════════════════════════════════════════════════════════════════════

			var leadResp *LeadGenerationResponse

			if unifiedResp.Observation != nil {
				log.Printf("💡 Observation found, generating lead...")

				leadReq := &LeadGenerationRequest{
					Observation: *unifiedResp.Observation,
					BigPicture:  req.BigPicture,
				}

				leadResult, err := genkit.Run(
					ctx, "leadGeneration",
					func() (*LeadGenerationResponse, error) {
						return leadFlow(ctx, leadReq)
					},
				)
				if err != nil {
					// Lead generation is optional, don't fail entire flow
					log.Printf("⚠️ Lead generation failed (non-critical): %v", err)
					leadResp = nil
				} else {
					leadResp = leadResult
					log.Printf("✅ Lead generation complete: is_actionable=%v, title=%s",
						leadResp.IsActionable, leadResp.Title)
				}
			} else {
				log.Printf("ℹ️ No observation found, skipping lead generation")
				leadResp = nil
			}

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 3: Combine results
			// ═══════════════════════════════════════════════════════════════════════════════

			result := &DetectiveAIResult{
				Comment:          unifiedResp.Comment,
				Observation:      unifiedResp.Observation,
				Connections:      unifiedResp.Connections,
				BigPictureImpact: unifiedResp.BigPictureImpact,
				SiteMapComment:   unifiedResp.SiteMapComment,
				Lead:             leadResp,
			}

			log.Printf("🎯 Detective AI flow complete: has_observation=%v, has_lead=%v",
				result.Observation != nil, result.Lead != nil && result.Lead.IsActionable)

			return result, nil
		},
	)
}
