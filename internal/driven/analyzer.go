package driven

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// GenkitSecurityAnalyzer implements the new detective flow
// Simplified from ~1470 lines to ~300 lines by replacing 5-phase ReAct with 2-phase detective
type GenkitSecurityAnalyzer struct {
	// Single orchestration flow for all AI operations
	detectiveAIFlow *genkitcore.Flow[*llm.DetectiveAIRequest, *llm.DetectiveAIResult, struct{}]

	// Storage (NOT part of Genkit flow)
	graph *models.InMemoryGraph

	// WebSocket
	wsHub *websocket.WebsocketManager
}

// NewGenkitSecurityAnalyzer creates a new analyzer with the detective flow
func NewGenkitSecurityAnalyzer(
	genkitApp *genkit.Genkit,
	modelName string,
	wsHub *websocket.WebsocketManager,
) *GenkitSecurityAnalyzer {
	// Create atomic flows
	unifiedFlow := llm.DefineUnifiedAnalysisFlow(genkitApp, modelName)
	leadFlow := llm.DefineLeadGenerationFlow(genkitApp, modelName)

	// Create orchestration flow with function wrappers
	detectiveFlow := llm.DefineDetectiveAIFlow(
		genkitApp,
		func(ctx context.Context, req *llm.UnifiedAnalysisRequest) (*llm.UnifiedAnalysisResponse, error) {
			return unifiedFlow.Run(ctx, req)
		},
		func(ctx context.Context, req *llm.LeadGenerationRequest) (*llm.LeadGenerationResponse, error) {
			return leadFlow.Run(ctx, req)
		},
	)

	return &GenkitSecurityAnalyzer{
		detectiveAIFlow: detectiveFlow,
		graph:           models.NewInMemoryGraph(),
		wsHub:           wsHub,
	}
}

// AnalyzeHTTPTraffic analyzes HTTP traffic using the detective flow
// This is the MAIN entry point - simplifies the old 5-phase flow to 2-phase
func (a *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context,
	method, url string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
) error {
	// STEP 1: Request Filter (heuristic, NO LLM)
	// This gives us 60-70% reduction in LLM calls by skipping static assets, health checks, etc.
	// IMPORTANT: Filter BEFORE storage to avoid storing 60-70% of traffic that will be skipped
	skipReason := a.shouldSkipRequest(method, url, statusCode, respHeaders, respBody)
	if skipReason != "" {
		// Store in site map only (not main exchange store)
		a.storeInSiteMap(method, url, reqHeaders, respHeaders, reqBody, respBody, statusCode, skipReason)
		log.Printf("⚪ Skipping %s %s: %s", method, url, skipReason)
		return nil
	}

	// STEP 2: Store exchange (only for requests that pass filter)
	exchange := models.HTTPExchange{
		Request: models.RequestPart{
			Method:  method,
			URL:     url,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: models.ResponsePart{
			StatusCode: statusCode,
			Headers:    respHeaders,
			Body:       respBody,
		},
		Timestamp: time.Now(),
	}
	exchangeID := a.graph.StoreExchange(&exchange)

	log.Printf("🔍 Analyzing %s %s", method, url)
	log.Printf("💾 Stored exchange %s", exchangeID)

	// STEP 3: SINGLE AI orchestration flow (unified + lead)
	// This replaces the old 5-phase pipeline
	aiResult, err := a.detectiveAIFlow.Run(ctx, &llm.DetectiveAIRequest{
		Exchange:           exchange,
		BigPicture:         a.graph.GetBigPicture(),
		RecentObservations: a.getRecentObservations(10),
	})
	if err != nil {
		return fmt.Errorf("detective AI failed: %w", err)
	}

	// STEP 4: Apply results to storage (OUTSIDE Genkit flow)
	// Storage operations are separate from LLM operations
	observationID := a.applyAIResult(exchangeID, exchange, aiResult)

	// STEP 5: SINGLE WebSocket message
	// Replaces multiple broadcasts from old flow
	a.wsHub.Broadcast(websocket.DetectiveDTO{
		ExchangeID:  exchangeID,
		Method:      method,
		URL:         url,
		StatusCode:  statusCode,
		Comment:     aiResult.Comment,
		Observation: aiResult.Observation,
		Connections: aiResult.Connections,
		BigPicture:  a.graph.GetBigPicture(),
		Lead:        a.leadFromResponse(observationID, aiResult.Lead),
	})

	log.Printf("✅ Analysis complete for %s %s", method, url)
	return nil
}

// applyAIResult stores AI results (storage operations separate from LLM)
func (a *GenkitSecurityAnalyzer) applyAIResult(
	exchangeID string,
	exchange models.HTTPExchange,
	aiResult *llm.DetectiveAIResult,
) string {
	var observationID string

	// Store observation
	if aiResult.Observation != nil {
		aiResult.Observation.ExchangeID = exchangeID
		observationID = a.graph.AddObservation(aiResult.Observation)

		log.Printf("💡 Added observation %s", observationID)
		log.Printf("   - What: %s", aiResult.Observation.What)
		log.Printf("   - Where: %s", aiResult.Observation.Where)
		log.Printf("   - Why: %s", aiResult.Observation.Why)

		// Store connections
		for _, conn := range aiResult.Connections {
			a.graph.AddConnection(observationID, conn.ID2, conn.Reason)
			log.Printf("🔗 Connection: %s -> %s", observationID, conn.ID2)
			log.Printf("   Reason: %s", conn.Reason)
		}
	}

	// Update BigPicture
	if aiResult.BigPictureImpact != nil {
		if err := a.graph.UpdateBigPictureWithImpact(aiResult.BigPictureImpact); err != nil {
			log.Printf("⚠️ Failed to update BigPicture: %v", err)
		} else {
			log.Printf("🖼️ Updated BigPicture: %s = %s", aiResult.BigPictureImpact.Field, aiResult.BigPictureImpact.Value)
		}
	}

	// Store site map entry
	a.storeInSiteMap(
		exchange.Request.Method,
		exchange.Request.URL,
		exchange.Request.Headers,
		exchange.Response.Headers,
		exchange.Request.Body,
		exchange.Response.Body,
		exchange.Response.StatusCode,
		aiResult.SiteMapComment,
	)

	// Store lead
	if aiResult.Lead != nil && observationID != "" {
		lead := models.Lead{
			ObservationID:  observationID,
			Title:          aiResult.Lead.Title,
			ActionableStep: aiResult.Lead.ActionableStep,
			PoCs:           aiResult.Lead.PoCs,
			CreatedAt:      time.Now(),
		}
		leadID := a.graph.AddLead(&lead)
		log.Printf("🎯 Added lead %s", leadID)
		log.Printf("   - Title: %s", lead.Title)
		log.Printf("   - Step: %s", lead.ActionableStep)
		log.Printf("   - PoCs: %d", len(lead.PoCs))
	}

	return observationID
}

// shouldSkipRequest checks if a request should be skipped using heuristic filtering
// Accepts individual parameters to avoid creating HTTPExchange object for filtered requests
func (a *GenkitSecurityAnalyzer) shouldSkipRequest(method, url string, statusCode int, respHeaders map[string]string, respBody string) string {
	// Skip static assets
	if isStaticAsset(url) {
		return "static asset"
	}

	// Skip health checks
	if isHealthCheck(url) {
		return "health check"
	}

	// Skip based on status code
	if statusCode >= 400 && statusCode < 500 {
		return fmt.Sprintf("client error %d", statusCode)
	}

	// Skip large responses
	if len(respBody) > 1000000 { // 1MB
		return "large response"
	}

	// Skip common non-interesting content types
	contentType := respHeaders["Content-Type"]
	if isSkippableContentType(contentType) {
		return fmt.Sprintf("content-type: %s", contentType)
	}

	return ""
}

// isStaticAsset checks if URL is a static asset
func isStaticAsset(url string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
	}
	for _, ext := range staticExtensions {
		if strings.Contains(strings.ToLower(url), ext) {
			return true
		}
	}
	return false
}

// isHealthCheck checks if URL is a health check endpoint
func isHealthCheck(url string) bool {
	urlLower := strings.ToLower(url)
	healthPatterns := []string{"/health", "/ping", "/status", "/ready", "/live"}
	for _, pattern := range healthPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}
	return false
}

// isSkippableContentType checks if content-type should be skipped
func isSkippableContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	skippable := []string{"image/", "video/", "audio/", "font/", "application/wasm"}
	for _, s := range skippable {
		if strings.Contains(ct, s) {
			return true
		}
	}
	return false
}

// leadFromResponse creates Lead entity from response
func (a *GenkitSecurityAnalyzer) leadFromResponse(
	observationID string,
	resp *llm.LeadGenerationResponse,
) *models.Lead {
	if resp == nil || observationID == "" {
		return nil
	}

	return &models.Lead{
		ObservationID:  observationID,
		Title:          resp.Title,
		ActionableStep: resp.ActionableStep,
		PoCs:           resp.PoCs,
		CreatedAt:      time.Now(),
	}
}

// getRecentObservations gets the last N observations for context
func (a *GenkitSecurityAnalyzer) getRecentObservations(n int) []models.Observation {
	obsPointers := a.graph.GetRecentObservations(n)
	observations := make([]models.Observation, len(obsPointers))
	for i, obs := range obsPointers {
		observations[i] = *obs
	}
	return observations
}

// storeInSiteMap stores an entry in the site map
func (a *GenkitSecurityAnalyzer) storeInSiteMap(
	method, url string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
	comment string,
) {
	entry := models.SiteMapEntry{
		ID:      fmt.Sprintf("sitemap-%s:%s", method, url),
		Method:  method,
		URL:     url,
		Comment: comment,
		Request: models.RequestPart{
			Method:  method,
			URL:     url,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: models.ResponsePart{
			StatusCode: statusCode,
			Headers:    respHeaders,
			Body:       respBody,
		},
	}

	a.graph.AddOrUpdateSiteMapEntry(&entry)
}

// Close closes the analyzer and cleans up resources
func (a *GenkitSecurityAnalyzer) Close() error {
	// No async workers to clean up in new flow
	log.Printf("🧹 Analyzer closed")
	return nil
}

// GetGraph returns the in-memory graph (for testing/debugging)
func (a *GenkitSecurityAnalyzer) GetGraph() *models.InMemoryGraph {
	return a.graph
}

// GetWsHub returns the WebSocket manager (for API server)
func (a *GenkitSecurityAnalyzer) GetWsHub() *websocket.WebsocketManager {
	return a.wsHub
}
