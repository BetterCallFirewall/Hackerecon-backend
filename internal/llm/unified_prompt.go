package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Unified Analysis Prompt - Replaces Phases 2+3+4 (Reasoning + Planning + Acting)
// ═══════════════════════════════════════════════════════════════════════════════

// UnifiedAnalysisRequest represents input for unified analysis
type UnifiedAnalysisRequest struct {
	Exchange           models.HTTPExchange  `json:"exchange" jsonschema:"description=HTTP request/response pair to analyze"`
	BigPicture         *models.BigPicture   `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application"`
	RecentObservations []models.Observation `json:"recent_observations,omitempty" jsonschema:"description=Recent observations for context"`
}

// UnifiedAnalysisResponse represents output from unified analysis
type UnifiedAnalysisResponse struct {
	Comment          string                   `json:"comment" jsonschema:"description=Brief description of what this request does"`
	Observation      *models.Observation      `json:"observation,omitempty" jsonschema:"description=Security-relevant observation, if any"`
	Connections      []models.Connection      `json:"connections,omitempty" jsonschema:"description=Links to related observations"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty" jsonschema:"description=Suggested update to big picture"`
	SiteMapComment   string                   `json:"site_map_comment,omitempty" jsonschema:"description=Comment for site map entry"`
}

// BuildUnifiedAnalysisPrompt creates a single prompt that replaces 3 phases
// Uses simple string concatenation (not strings.Builder)
func BuildUnifiedAnalysisPrompt(req *UnifiedAnalysisRequest) string {
	prompt := "You are a security detective analyzing HTTP traffic. Your task is to identify interesting patterns and observations.\n\n"

	// Input section
	prompt += "## Input\n\n"
	prompt += "**Request:**\n"
	prompt += fmt.Sprintf("- Method: %s\n", req.Exchange.Request.Method)
	prompt += fmt.Sprintf("- URL: %s\n", req.Exchange.Request.URL)
	prompt += fmt.Sprintf("- Headers: %s\n", formatHeaders(req.Exchange.Request.Headers))
	prompt += fmt.Sprintf("- Body: %s\n", TruncateString(req.Exchange.Request.Body, 500))

	prompt += "\n**Response:**\n"
	prompt += fmt.Sprintf("- Status: %d\n", req.Exchange.Response.StatusCode)
	prompt += fmt.Sprintf("- Headers: %s\n", formatHeaders(req.Exchange.Response.Headers))
	prompt += fmt.Sprintf("- Body: %s\n", TruncateString(req.Exchange.Response.Body, 1000))

	// BigPicture context (optional)
	prompt += "\n**Site Context (BigPicture):**\n"
	if req.BigPicture != nil {
		prompt += fmt.Sprintf("- Description: %s\n", req.BigPicture.Description)
		prompt += fmt.Sprintf("- Functionalities: %s\n", req.BigPicture.Functionalities)
		prompt += fmt.Sprintf("- Technologies: %s\n", req.BigPicture.Technologies)
	} else {
		prompt += "No context yet (first request)\n"
	}

	// Recent observations (optional)
	if len(req.RecentObservations) > 0 {
		prompt += "\n**Recent Observations:**\n"
		for i, obs := range req.RecentObservations {
			if i >= 5 {
				break // Limit to 5 most recent
			}
			prompt += fmt.Sprintf("- %s: %s\n", obs.ID, obs.What)
		}
	}

	// Output format
	prompt += "\n## Output Format (JSON):\n\n"
	prompt += `{
  "comment": "Brief description of what this request does (always required)",

  "observation": null OR {
    "what": "What interesting pattern did you find?",
    "where": "Where exactly (URL/header/body)?",
    "why": "Why is this interesting?"
  },

  "connections": [] OR [
    {"id1": "obs-XXX", "id2": "obs-YYY", "reason": "why they are related"}
  ],

  "big_picture_impact": null OR {
    "field": "description|functionalities|technologies",
    "value": "what to add/change",
    "reason": "why this matters for understanding the site"
  },

  "site_map_comment": "More detailed comment for site map"
}`

	// Rules section
	prompt += "\n\n## Rules\n\n"
	prompt += "1. **Be specific** - not \"interesting parameter\" but \"MD5 hash in ticket_id parameter\"\n"
	prompt += "2. **Actionable observations** - should lead to something testable\n"
	prompt += "3. **Connections** - only if you see clear relationship to previous observations\n"
	prompt += "4. **Big picture** - only if this significantly changes understanding\n"
	prompt += "5. **Comment is REQUIRED** - always describe what this endpoint does\n"

	// Examples section
	prompt += "\n## Examples\n\n"
	prompt += "GOOD observation:\n"
	prompt += "{\n"
	prompt += `  "what": "MD5 hash in URL parameter",` + "\n"
	prompt += `  "where": "GET /api/ticket/5d41402abc4b2a76b9719d911017c592",` + "\n"
	prompt += `  "why": "MD5 suggests encrypted ID, possible IDOR vulnerability"` + "\n"
	prompt += "}\n\n"

	prompt += "BAD observation:\n"
	prompt += "{\n"
	prompt += `  "what": "Interesting parameter",` + "\n"
	prompt += `  "where": "URL has id parameter",` + "\n"
	prompt += `  "why": "Might be vulnerable"` + "\n"
	prompt += "}\n\n"

	prompt += "IMPORTANT: Response must be ONLY valid JSON, no additional text."

	return prompt
}
