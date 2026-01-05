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
	BigPicture         *models.BigPicture   `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application,nullable"`
	RecentObservations []models.Observation `json:"recent_observations,omitempty" jsonschema:"description=Recent observations for context"`
}

// UnifiedAnalysisResponse represents output from unified analysis
type UnifiedAnalysisResponse struct {
	Comment          string                   `json:"comment" jsonschema:"description=Brief description of what this request does"`
	Observations     []models.Observation     `json:"observations,omitempty" jsonschema:"description=Security-relevant observations (0, 1, or multiple)"`
	Connections      []models.Connection      `json:"connections,omitempty" jsonschema:"description=Links to related observations"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty" jsonschema:"description=Suggested update to big picture,nullable"`
	SiteMapComment   string                   `json:"site_map_comment,omitempty" jsonschema:"description=Comment for site map entry"`
}

// BuildUnifiedAnalysisPrompt creates a single prompt that replaces 3 phases
// Uses simple string concatenation (not strings.Builder)
func BuildUnifiedAnalysisPrompt(req *UnifiedAnalysisRequest) string {
	prompt := "You are a security detective analyzing HTTP traffic. Your task is to identify patterns that reveal information about server architecture, technologies, or potential vulnerabilities.\n\n"

	// Input section
	prompt += "## Input\n\n"
	prompt += "**Request:**\n"
	prompt += fmt.Sprintf("- Method: %s\n", req.Exchange.Request.Method)
	prompt += fmt.Sprintf("- URL: %s\n", req.Exchange.Request.URL)
	headers := formatHeaders(req.Exchange.Request.Headers)
	if headers != "(none)" {
		prompt += fmt.Sprintf("- Headers:\n  %s\n", headers)
	}
	prompt += fmt.Sprintf("- Body: %s\n", TruncateString(req.Exchange.Request.Body, 500))

	prompt += "\n**Response:**\n"
	prompt += fmt.Sprintf("- Status: %d\n", req.Exchange.Response.StatusCode)
	headers = formatHeaders(req.Exchange.Response.Headers)
	if headers != "(none)" {
		prompt += fmt.Sprintf("- Headers:\n  %s\n", headers)
	}
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

	// All previous observations (for deduplication)
	if len(req.RecentObservations) > 0 {
		prompt += fmt.Sprintf(
			"\n**Previous Observations (%d total)** - MUST check for duplicates before creating new observations:\n",
			len(req.RecentObservations),
		)
		for _, obs := range req.RecentObservations {
			prompt += fmt.Sprintf("- [%s] What: %s\n", obs.ID, obs.What)
			prompt += fmt.Sprintf("        Where: %s\n", TruncateString(obs.Where, 150))
		}
		prompt += "\n"
	} else {
		prompt += "\n**Previous Observations:** None (first request)\n\n"
	}

	// Pre-creation validation (CRITICAL: before output format)
	prompt += "\n\n## ⚠️ CRITICAL: Pre-Creation Validation\n\n"
	prompt += "Before creating ANY observation, you MUST answer this question:\n\n"
	prompt += "**Question**: Does this observation reveal SERVER ARCHITECTURE or BACKEND LOGIC?\n\n"
	prompt += "If your answer is NO, DO NOT create the observation.\n\n"
	prompt += "Examples of observations that FAIL this test (DO NOT CREATE):\n"
	prompt += "- CSS properties (fonts, colors, animations, layouts)\n"
	prompt += "- HTML structure (divs, classes, semantic tags)\n"
	prompt += "- Frontend frameworks (React, Vue, Angular usage)\n"
	prompt += "- JavaScript UI libraries (Bootstrap, Tailwind, Material UI)\n"
	prompt += "- Visual design (themes, styling, responsive design)\n\n"
	prompt += "Examples that PASS this test (CREATE these):\n"
	prompt += "- Server-side technologies (PHP, Python, Node.js indicators)\n"
	prompt += "- Authentication/authorization mechanisms\n"
	prompt += "- Database schemas or query patterns\n"
	prompt += "- API endpoints and their parameters\n"
	prompt += "- Custom encryption or hashing implementations\n"
	prompt += "- Business logic vulnerabilities\n\n"
	prompt += "💡 If unsure: Ask yourself 'Would a backend developer care about this?'\n"
	prompt += "   If the answer is 'no, this is frontend work' - SKIP IT.\n\n"
	prompt += "  ## 🤔 Thinking Step (DO NOT OUTPUT - think silently)\n\n  Before creating observations, trace the DATA FLOW:\n\n  1. **Input → Output Mapping**:\n     URL: /api/shop/eab3d383-...\n     Request body: {}\n     Headers: Cookie: token=...\n\n     Response: {\"_id\": \"eab3d383-...\", ...}\n\n     ASK YOURSELF:\n     - Which request data appears in response?\n     - Is it echoed exactly? Transformed?\n     - What does this reveal about server logic?\n\n  2. **Server Behavior Inference**:\n     - If URL parameter appears in DB field → Server uses it as identifier\n     - If POST body is {} → Endpoint might accept structured input\n     - If special chars appear → What parsing happened?\n\n  3. **Exploration Vectors**:\n     - What could I modify in request to see behavior change?\n     - Are there injection points? (URL, body, headers, query)\n     - What formats might the server accept? (JSON, operators, special chars)\n\n  Use these insights to create observations that HIGHLIGHT testing opportunities"

	// Output format
	prompt += "\n## Output Format (JSON):\n\n"
	prompt += `{
  "comment": "Brief description of what this request does (always required)",

  "observations": [] OR [
    {
      "what": "What interesting pattern did you find?",
      "where": "Where exactly (URL/header/body)?",
      "why": "Why is this interesting?"

      ⚠️ CRITICAL: If this is about CSS, fonts, colors, animations,
      or ANY frontend styling - DO NOT create this observation!

      NOTE: DO NOT include id, exchange_id, created_at - these are auto-generated
    }
    NOTE: Can be 0, 1, or multiple observations if you find several distinct patterns
  ],

  "connections": [] OR [
    {
      "id2": "obs-5",
      "reason": "why they are related"
    }
    NOTE: id1 is auto-populated (current observation), id2 must be from Previous Observations list above
  ],

  "big_picture_impact": null OR {
    "field": "description|functionalities|technologies",
    "value": "what to add/change",
    "reason": "why this matters for understanding the site"
  },

  "site_map_comment": "More detailed comment for site map"
}`

	// Rules section
	prompt += "\n\n## Critical: Deduplication (MUST COMPLETE FIRST)\n\n"
	prompt += "BEFORE creating any observations, you MUST check for duplicates in the Previous Observations list above.\n\n"
	prompt += "**Deduplication Criteria:** Two observations are duplicates if they describe the SAME pattern:\n"
	prompt += "- Same WHAT (the pattern type) + Same WHERE (the location component) = DUPLICATE\n"
	prompt += "- Examples of duplicates:\n"
	prompt += "  * \"JWT token in Authorization header\" (at /api/login) AND \"JWT in Authorization header\" (at /api/user) → DUPLICATE\n"
	prompt += "  * \"MD5 hash in ticket_id parameter\" AND \"MD5 hash in ticket_id\" → DUPLICATE (same pattern)\n"
	prompt += "  * \"SQL error in response\" AND \"Database error message\" (same endpoint) → DUPLICATE\n\n"
	prompt += "**Distinct (NOT duplicates) - Different patterns:**\n"
	prompt += "- Different WHAT: \"JWT token\" vs \"XSS vulnerable parameter\" → DISTINCT\n"
	prompt += "- Different WHERE (different components): \"JWT in Authorization\" vs \"JWT in cookie\" → DISTINCT\n"
	prompt += "- Different vulnerability type: \"SQL injection in id\" vs \"XSS in name\" → DISTINCT\n\n"
	prompt += "**If duplicate found:** DO NOT create a new observation. Skip it or create a connection instead.\n"
	prompt += "**If distinct:** Proceed to create the observation.\n\n"

	prompt += "## Other Rules\n\n"
	prompt += "1. **Be specific** - not \"interesting parameter\" but \"MD5 hash in ticket_id parameter\"\n"
	prompt += "2. **Server-revealing observations** - should reveal information about:\n"
	prompt += "   - Server architecture (frameworks, languages, technologies)\n"
	prompt += "   - Authentication/authorization mechanisms\n"
	prompt += "   - Potential vulnerabilities (injection points, crypto weaknesses, etc.)\n"
	prompt += "   - Business logic or data flow\n"
	prompt += "3. **Multiple observations allowed** - if you find several DISTINCT patterns, create multiple observations\n"
	prompt += "4. **Connections** - only if you see clear relationship to previous observations\n"
	prompt += "5. **Big picture** - only if this significantly changes understanding\n"
	prompt += "6. **Comment is REQUIRED** - always describe what this endpoint does\n"

	// Baseline technologies section
	prompt += "\n\n## ⚠️⚠️⚠️ BASELINE TECHNOLOGIES (DO NOT CREATE OBSERVATIONS)\n\n"

	prompt += "🚨 **TOP PRIORITY: CSS/Frontend Styling - ABSOLUTELY FORBIDDEN** 🚨\n"
	prompt += "NEVER create observations about:\n"
	prompt += "- Fonts (Google Fonts, custom fonts like Orbitron, font families)\n"
	prompt += "- CSS properties (colors, animations, transitions, layouts)\n"
	prompt += "- Visual themes (neon glow, dark mode, futuristic styling)\n"
	prompt += "- UI libraries (Bootstrap, Tailwind, Material UI, Bulma)\n"
	prompt += "- Responsive design patterns (media queries, mobile layouts)\n\n"
	prompt += "These are PRESENTATION LAYER - they do NOT reveal server architecture.\n\n"

	prompt += "🚨 **ALSO FORBIDDEN** (do not create observations):\n"
	prompt += "- HTML structure (divs, classes, IDs, semantic tags)\n"
	prompt += "- JavaScript frameworks (React, Vue, Angular usage in frontend)\n"
	prompt += "- External CDNs (jQuery, React from cdnjs, unpkg, jsdelivr)\n"
	prompt += "- Standard HTTP headers (Accept-Language, User-Agent, Cache-Control)\n"
	prompt += "- Analytics/Tracking (Google Analytics, Facebook Pixel)\n\n"

	prompt += "**Other baseline technologies** (also do not create observations):\n"
	prompt += "- External Resources: Google Fonts, Font Awesome, Adobe Fonts\n"
	prompt += "- CDN-hosted libraries (jQuery, React, Vue from cdnjs, unpkg, jsdelivr)\n"
	prompt += "- CSS frameworks (Bootstrap, Tailwind, Foundation via CDN)\n"
	prompt += "- Static asset hosting (AWS S3, CloudFront, Cloudflare, Akamai)\n"
	prompt += "- Common Security Headers: X-Frame-Options, X-Content-Type-Options, CSP\n"
	prompt += "- Standard HTML Patterns: meta tags, link rel=\"stylesheet\", script src\n"
	prompt += "- favicon.ico, robots.txt, sitemap.xml\n"

	prompt += "\n💡 Key principle: If it's a widely-used standard library, browser behavior, or presentation layer - it's BASELINE.\n"
	prompt += "    Focus on patterns that reveal SERVER ARCHITECTURE and APPLICATION LOGIC.\n"

	// Examples section
	prompt += "\n## Examples\n\n"

	// Deduplication example
	prompt += "✅ GOOD - Deduplication in action:\n"
	prompt += "Given Previous Observations:\n"
	prompt += "  [obs-1] What: JWT token in Authorization header\n"
	prompt += "          Where: Authorization: Bearer eyJhbGciOiJub25l...\n\n"
	prompt += "Current request shows: Authorization: Bearer eyJhbGciOiJub25lLW90aGVy...\n\n"
	prompt += "Response: observations: [] (DUPLICATE - skip creating new observation)\n\n"

	prompt += "Response alternative (if distinct): connections: [{\"id2\": \"obs-1\", \"reason\": \"Same JWT pattern found at another endpoint\"}]\n\n"

	// Single observation example
	prompt += "✅ GOOD - Single observation:\n"
	prompt += "{\n"
	prompt += `  "comment": "User profile API endpoint",` + "\n"
	prompt += `  "observations": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "what": "MD5 hash in URL parameter",` + "\n"
	prompt += `      "where": "GET /api/ticket/5d41402abc4b2a76b9719d911017c592",` + "\n"
	prompt += `      "why": "MD5 suggests encrypted ID, possible IDOR vulnerability"` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	// Multiple observations example
	prompt += "✅ GOOD - Multiple observations (distinct patterns in one request):\n"
	prompt += "{\n"
	prompt += `  "comment": "Login endpoint with custom crypto and timing leak",` + "\n"
	prompt += `  "observations": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "what": "JWT token with 'none' algorithm in header",` + "\n"
	prompt += `      "where": "Authorization: Bearer eyJhbGciOiJub25l...",` + "\n"
	prompt += `      "why": "'none' algorithm allows token forgery if signature verification is bypassed"` + "\n"
	prompt += `    },` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "what": "Different error messages for valid vs invalid usernames",` + "\n"
	prompt += `      "where": "Response body: 'User not found' vs 'Invalid password'",` + "\n"
	prompt += `      "why": "Allows username enumeration via timing or response analysis"` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	// Empty observations example
	prompt += "✅ GOOD - No interesting patterns (empty observations):\n"
	prompt += "{\n"
	prompt += `  "comment": "Static CSS file",` + "\n"
	prompt += `  "observations": []` + "\n"
	prompt += "}\n\n"

	// Bad examples
	prompt += "❌ BAD - Vague observation:\n"
	prompt += "{\n"
	prompt += `  "what": "Interesting parameter",` + "\n"
	prompt += `  "where": "URL has id parameter",` + "\n"
	prompt += `  "why": "Might be vulnerable"` + "\n"
	prompt += "}\n\n"

	prompt += "❌ BAD - Baseline technology (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "Google Fonts imported from external domain",` + "\n"
	prompt += `  "where": "CSS @import url('fonts.googleapis.com')",` + "\n"
	prompt += `  "why": "External CSS injection risk"` + "\n"
	prompt += "}\n"
	prompt += "REASON: Google Fonts is a BASELINE technology used by millions of sites.\n"
	prompt += "        Not application-specific, not interesting.\n\n"

	prompt += "❌ BAD - Baseline CDN (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "jQuery loaded from cdnjs.cloudflare.com",` + "\n"
	prompt += `  "where": "script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js'",` + "\n"
	prompt += `  "why": "External JavaScript dependency"` + "\n"
	prompt += "}\n"
	prompt += "REASON: jQuery on CDN is BASELINE infrastructure.\n"
	prompt += "        Focus on application-specific code, not standard libraries.\n\n"

	prompt += "❌ BAD - Standard HTTP header (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "Russian Accept-Language header",` + "\n"
	prompt += `  "where": "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8",` + "\n"
	prompt += `  "why": "Primary language preference is Russian, indicating target audience"` + "\n"
	prompt += "}\n"
	prompt += "REASON: Accept-Language is a BASELINE browser header sent automatically.\n"
	prompt += "        Does not reveal server architecture or application logic.\n\n"

	prompt += "❌ BAD - CSS styling (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "Hard-coded CSS user-select:none and scrollbar-width:none",` + "\n"
	prompt += `  "where": "CSS body rule: user-select: none; scrollbar-width: none !important;",` + "\n"
	prompt += `  "why": "Attempts to disable text selection and scrolling, possibly to hinder inspection"` + "\n"
	prompt += "}\n"
	prompt += "REASON: CSS styling is BASELINE presentation layer.\n"
	prompt += "        Does not reveal server architecture. Focus on backend logic.\n\n"

	prompt += "❌ BAD - Font observation (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "Custom futuristic CSS theme with Orbitron font and neon glow",` + "\n"
	prompt += `  "where": "CSS body rule: font-family: 'Orbitron', monospace, sans-serif; text-shadow: 0 0 10px #4fffe9;",` + "\n"
	prompt += `  "why": "Unique visual signature suggests a custom-designed admin or user dashboard"` + "\n"
	prompt += "}\n"
	prompt += "REASON: Fonts and visual themes are BASELINE presentation.\n"
	prompt += "        Do not reveal server architecture or backend logic.\n\n"

	prompt += "❌ BAD - Animation observation (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "CSS keyframe animation for pulsing button effect",` + "\n"
	prompt += `  "where": "CSS @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.1); } }",` + "\n"
	prompt += `  "why": "Custom animation suggests custom-built UI component"` + "\n"
	prompt += "}\n"
	prompt += "REASON: Animations are BASELINE frontend visual effects.\n"
	prompt += "        Do not reveal server architecture.\n\n"

	prompt += "❌ BAD - Russian language UI (IGNORE):\n"
	prompt += "{\n"
	prompt += `  "what": "Russian-language HTML with hard-coded cyberpunk styling",` + "\n"
	prompt += `  "where": "Response body: lang=\"ru\" and CSS font-family 'Orbitron', monospace",` + "\n"
	prompt += `  "why": "Reveals the site targets Russian users and uses custom inline styling"` + "\n"
	prompt += "}\n"
	prompt += "REASON: HTML lang attribute is a BASELINE browser feature.\n"
	prompt += "        Does not reveal server architecture.\n\n"

	prompt += "IMPORTANT: Response must be ONLY valid JSON, no additional text."

	return prompt
}
