package driven

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"golang.org/x/sync/errgroup"
)

// GenkitSecurityAnalyzer implements the new 4-phase agent flow
// Analyst → Architect → Strategist → Tactician
type GenkitSecurityAnalyzer struct {
	// Individual agent flows (replaces detectiveAIFlow)
	analystFlow    *genkitcore.Flow[*llm.AnalystRequest, *llm.AnalystResponse, struct{}]
	architectFlow  *genkitcore.Flow[*llm.ArchitectRequest, *llm.ArchitectResult, struct{}]
	strategistFlow *genkitcore.Flow[*llm.StrategistRequest, *llm.StrategistResult, struct{}]
	tacticianFlow  *genkitcore.Flow[*llm.TacticianRequest, *llm.TacticianResult, struct{}]

	// Storage
	graph *models.InMemoryGraph

	// WebSocket
	wsHub *websocket.WebsocketManager
}

// NewGenkitSecurityAnalyzer creates a new analyzer with the 4-phase agent flow
func NewGenkitSecurityAnalyzer(
	genkitApp *genkit.Genkit,
	modelNameFast string,
	modelNameSmart string,
	wsHub *websocket.WebsocketManager,
) *GenkitSecurityAnalyzer {
	// Define tools FIRST
	llm.DefineGetExchangeTool(genkitApp)

	// Create agent flows with different models
	analystFlow := llm.DefineAnalystFlow(genkitApp, modelNameFast)
	architectFlow := llm.DefineArchitectFlow(genkitApp, modelNameSmart)
	strategistFlow := llm.DefineStrategistFlow(genkitApp, modelNameSmart)
	tacticianFlow := llm.DefineTacticianFlow(genkitApp, modelNameSmart)

	// Create in-memory graph
	graph := models.NewInMemoryGraph()
	models.SetGlobalInMemoryGraph(graph)
	log.Printf("✅ Global InMemoryGraph reference set for tool access")

	return &GenkitSecurityAnalyzer{
		analystFlow:    analystFlow,
		architectFlow:  architectFlow,
		strategistFlow: strategistFlow,
		tacticianFlow:  tacticianFlow,
		graph:          graph,
		wsHub:          wsHub,
	}
}

// AnalyzeHTTPTraffic analyzes HTTP traffic using the analyst flow (Phase 1)
// This is the MAIN entry point - processes each request through Analyst only
func (a *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context,
	method, url string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
) error {
	// STEP 1: Request Filter (heuristic, NO LLM)
	skipReason := a.shouldSkipRequest(method, url, statusCode, respHeaders, respBody)
	if skipReason != "" {
		log.Printf("⚪ Skipping %s %s: %s", method, url, skipReason)
		return nil
	}

	// STEP 2: Store exchange
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

	// STEP 3: Store in site map
	_ = a.storeInSiteMap(
		method, url, exchangeID,
		reqHeaders, respHeaders,
		reqBody, respBody,
		statusCode,
		"",
	)

	// STEP 4: Prepare exchange for LLM (truncated)
	exchangeForLLM := a.prepareExchangeForLLM(exchange)

	// STEP 5: AnalystFlow (Phase 1 only)
	analystResult, err := a.analystFlow.Run(
		ctx, &llm.AnalystRequest{
			Exchange: exchangeForLLM,
		},
	)
	if err != nil {
		log.Printf("⚠️ Analyst failed for %s: %v", url, err)
		// Don't block - continue with empty observations
		analystResult = &llm.AnalystResponse{Observations: []models.Observation{}}
	}

	// STEP 6: Store raw observations
	for i := range analystResult.Observations {
		analystResult.Observations[i].ExchangeIDs = []string{exchangeID}
		obsID := a.graph.AddRawObservation(&analystResult.Observations[i])
		log.Printf("💡 Raw observation %s: %s", obsID, analystResult.Observations[i].What)
	}

	// STEP 6.5: Store TrafficDigest in SiteMap
	if analystResult.TrafficDigest != nil {
		// Validate required fields
		if analystResult.TrafficDigest.RouteSignature == "" {
			log.Printf("⚠️ TrafficDigest missing RouteSignature, skipping storage")
		} else if err := a.graph.UpdateSiteMapDigest(exchangeID, analystResult.TrafficDigest); err != nil {
			log.Printf("⚠️ Failed to update SiteMap with digest: %v", err)
		} else {
			log.Printf("📋 Stored TrafficDigest for %s", exchangeID)
		}
	}

	// STEP 7: WebSocket with FULL exchange (not truncated)
	a.wsHub.Broadcast(
		websocket.AnalystDTO{
			ExchangeID:    exchangeID,
			Method:        method,
			URL:           url,
			StatusCode:    statusCode,
			Exchange:      exchange, // FULL exchange, not exchangeForLLM
			Observations:  analystResult.Observations,
			TrafficDigest: analystResult.TrafficDigest,
		},
	)

	log.Printf("✅ Analyst complete for %s %s", method, url)
	return nil
}

// RunDeepAnalysis runs the Architect, Strategist and Tactician phases (Phases 2-4)
// This is called separately (not per-request) to aggregate and analyze raw observations
func (a *GenkitSecurityAnalyzer) RunDeepAnalysis(ctx context.Context) error {
	log.Printf("🚀 Starting deep analysis")

	// STEP 1: Get and clear raw buffer atomically
	rawBuffer := a.graph.GetAndClearRawBuffer()
	if len(rawBuffer) == 0 {
		log.Printf("⚠️ No raw observations to analyze")
		return nil
	}
	log.Printf("📊 Processing %d raw observations", len(rawBuffer))

	// STEP 2: Architect (reconstruct system architecture and data flows)
	siteMapEntries := a.graph.GetAllSiteMapEntries()
	architectResult, err := a.architectFlow.Run(
		ctx, &llm.ArchitectRequest{
			RawObservations: rawBuffer,
			SiteMap:         convertSiteMapEntries(siteMapEntries),
		},
	)
	if err != nil {
		// Restore raw buffer on failure
		for i := range rawBuffer {
			a.graph.AddRawObservation(&rawBuffer[i])
		}
		log.Printf("⚠️ Architect failed, restored %d raw observations to buffer", len(rawBuffer))
		return fmt.Errorf("architect failed: %w", err)
	}

	log.Printf(
		"🏗️  System Architecture: %s, %d data flows",
		architectResult.SystemArchitecture.TechStack,
		len(architectResult.SystemArchitecture.DataFlows),
	)

	// STEP 3: Strategist (with SystemArchitecture from Architect)
	strategistResult, err := a.strategistFlow.Run(
		ctx, &llm.StrategistRequest{
			RawObservations:    rawBuffer,
			SiteMap:            convertSiteMapEntries(siteMapEntries),
			BigPicture:         a.graph.GetBigPicture(),
			SystemArchitecture: &architectResult.SystemArchitecture,
		},
	)
	if err != nil {
		// Restore raw buffer on failure
		for i := range rawBuffer {
			a.graph.AddRawObservation(&rawBuffer[i])
		}
		log.Printf("⚠️ Strategist failed, restored %d raw observations to buffer", len(rawBuffer))
		return fmt.Errorf("strategist failed: %w", err)
	}

	// STEP 4: Store aggregated observations
	for i := range strategistResult.Observations {
		obsID := a.graph.AddObservation(&strategistResult.Observations[i])
		log.Printf(
			"💡 Aggregated observation %s\n  - What: %v\n  - Why: %v", obsID, strategistResult.Observations[i].What,
			strategistResult.Observations[i].Why,
		)
	}

	// STEP 5: Store connections
	for _, conn := range strategistResult.Connections {
		a.graph.AddConnection(conn.From, conn.To, conn.Reason)
		log.Printf("🔗 Connection: %s <-> %s", conn.From, conn.To)
	}

	// STEP 6: Update BigPicture
	if strategistResult.BigPictureImpact != nil {
		if err := a.graph.UpdateBigPictureWithImpact(strategistResult.BigPictureImpact); err != nil {
			log.Printf("⚠️ Failed to update BigPicture: %v", err)
		}
	}

	// STEP 7: Tactician for each task (parallel execution with errgroup)
	allLeads := []models.Lead{}
	leadsMu := sync.Mutex{} // For safe appends to allLeads slice

	if len(strategistResult.TacticianTasks) > 0 {
		log.Printf("🔧 Starting %d tactician tasks in parallel", len(strategistResult.TacticianTasks))

		g, gCtx := errgroup.WithContext(ctx)

		for taskIdx, task := range strategistResult.TacticianTasks {
			// Capture loop variables for goroutine
			taskIdx, task := taskIdx, task

			g.Go(func() error {
				log.Printf("🟡 [Task %d/%d] Tactician analyzing: %s",
					taskIdx+1, len(strategistResult.TacticianTasks), task.Description)

				tacticianResult, err := a.tacticianFlow.Run(
					gCtx, &llm.TacticianRequest{
						Task:       task,
						BigPicture: a.graph.GetBigPicture(),
						SiteMap:    convertSiteMapEntries(siteMapEntries),
						Graph:      a.graph,                             // For getExchange tool
						SystemArch: &architectResult.SystemArchitecture, // For stack-specific context
					},
				)
				if err != nil {
					log.Printf("⚠️ [Task %d/%d] Tactician failed: %v",
						taskIdx+1, len(strategistResult.TacticianTasks), err)
					// Don't fail entire group - return nil to continue with other tasks
					return nil
				}

				// Store leads with mutex protection for allLeads slice
				leadsMu.Lock()
				for _, lead := range tacticianResult.Leads {
					leadID := a.graph.AddLead(&lead)
					log.Printf("🎯 [Task %d/%d] Lead %s: %s",
						taskIdx+1, len(strategistResult.TacticianTasks), leadID, lead.Title)
					allLeads = append(allLeads, lead)
				}
				leadsMu.Unlock()

				log.Printf("✅ [Task %d/%d] Complete: %d leads",
					taskIdx+1, len(strategistResult.TacticianTasks), len(tacticianResult.Leads))
				return nil
			})
		}

		// Wait for all tasks to complete
		if err := g.Wait(); err != nil {
			log.Printf("⚠️ Tactician group completed with error: %v", err)
		}

		log.Printf("✅ All tactician tasks complete: %d leads generated", len(allLeads))
	}

	// STEP 8: WebSocket with final results
	a.wsHub.Broadcast(
		websocket.DeepAnalysisDTO{
			Observations:       strategistResult.Observations,
			Connections:        strategistResult.Connections,
			Leads:              allLeads,
			BigPicture:         a.graph.GetBigPicture(),
			SystemArchitecture: &architectResult.SystemArchitecture,
			TacticianTasks:     strategistResult.TacticianTasks,
			SiteMap:            convertSiteMapEntries(siteMapEntries),
		},
	)

	log.Printf(
		"✅ Deep analysis complete: %d obs, %d leads",
		len(strategistResult.Observations), len(allLeads),
	)
	return nil
}

// shouldSkipRequest checks if a request should be skipped using heuristic filtering
// Accepts individual parameters to avoid creating HTTPExchange object for filtered requests
func (a *GenkitSecurityAnalyzer) shouldSkipRequest(method, url string, statusCode int, respHeaders map[string]string,
	respBody string) string {
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
	if len(respBody) > maxResponseSize {
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
	// Note: .css is EXCLUDED - CSS files can contain sensitive paths/comments
	staticExtensions := []string{
		".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
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

// storeInSiteMap stores an entry in the site map
// NOTE: ID is generated by AddOrUpdateSiteMapEntry (not set here)
// New architecture: Only stores ExchangeID reference + optional TrafficDigest
// Raw HTTP data is accessed via InMemoryGraph.getExchange(ExchangeID)
func (a *GenkitSecurityAnalyzer) storeInSiteMap(
	method, url, id string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
	comment string,
) string {
	entry := models.SiteMapEntry{
		// ID is auto-generated by AddOrUpdateSiteMapEntry
		ExchangeID: id,
		Method:     method,
		URL:        url,
		// Note: Comment field removed in new architecture
		// Note: Request/Response fields removed - use ExchangeID to access from InMemoryGraph
		// Note: Digest field is set separately by Architect agent
	}

	return a.graph.AddOrUpdateSiteMapEntry(&entry)
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

const (
	maxResponseSize = 1_000_000 // 1MB max response size
)

// prepareExchangeForLLM creates a copy of exchange with truncated bodies for LLM analysis
// This prevents sending large binary data (images, videos, etc.) to the LLM
// Delegates to llm.PrepareExchangeForLLM for consistency with tool handler
func (a *GenkitSecurityAnalyzer) prepareExchangeForLLM(exchange models.HTTPExchange) models.HTTPExchange {
	return llm.PrepareExchangeForLLM(exchange)
}

// convertSiteMapEntries converts []*models.SiteMapEntry to []models.SiteMapEntry
// This is needed because GetAllSiteMapEntries returns pointers, but the LLM prompt expects values
func convertSiteMapEntries(entries []*models.SiteMapEntry) []models.SiteMapEntry {
	result := make([]models.SiteMapEntry, len(entries))
	for i, entry := range entries {
		result[i] = *entry
	}
	return result
}
