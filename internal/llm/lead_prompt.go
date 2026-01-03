package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Lead Generation Prompt - Async, separate call with human-readable PoCs
// ═══════════════════════════════════════════════════════════════════════════════

// LeadGenerationRequest represents input for lead generation
type LeadGenerationRequest struct {
	Observation models.Observation `json:"observation" jsonschema:"description=Observation to generate lead from"`
	BigPicture  *models.BigPicture `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application"`
}

// LeadGenerationResponse represents output from lead generation
// NOTE: Does NOT include CanAutoVerify field (per user requirements)
type LeadGenerationResponse struct {
	IsActionable   bool              `json:"is_actionable" jsonschema:"description=Whether this observation leads to actionable test"`
	Title          string            `json:"title" jsonschema:"description=Short title"`
	ActionableStep string            `json:"actionable_step" jsonschema:"description=Concrete testing step"`
	PoCs           []models.PoCEntry `json:"pocs" jsonschema:"description=Human-readable PoC instructions"`
}

// BuildLeadGenerationPrompt creates prompt for generating leads from observations
// Uses simple string concatenation (not strings.Builder)
// Emphasis on human-readable PoC instructions
func BuildLeadGenerationPrompt(req *LeadGenerationRequest) string {
	prompt := "You are generating actionable leads from security observations.\n\n"

	// Input section
	prompt += "## Input\n\n"
	prompt += "**Observation:**\n"
	prompt += fmt.Sprintf("- What: %s\n", req.Observation.What)
	prompt += fmt.Sprintf("- Where: %s\n", req.Observation.Where)
	prompt += fmt.Sprintf("- Why: %s\n", req.Observation.Why)

	// BigPicture context (optional)
	if req.BigPicture != nil {
		prompt += "\n**Site Context:**\n"
		prompt += fmt.Sprintf("- Description: %s\n", req.BigPicture.Description)
		prompt += fmt.Sprintf("- Functionalities: %s\n", req.BigPicture.Functionalities)
		prompt += fmt.Sprintf("- Technologies: %s\n", req.BigPicture.Technologies)
	}

	// Task description
	prompt += "\n## Task\n\n"
	prompt += "Determine if there is an ACTIONABLE next step.\n\n"
	prompt += "If NO - return is_actionable: false\n\n"
	prompt += "If YES - return complete lead information.\n"

	// Output format
	prompt += "\n## Output Format (JSON):\n\n"
	prompt += `{
  "is_actionable": true/false,
  "title": "Short title (max 10 words)",
  "actionable_step": "Specific what to try",
  "pocs": [
    {
      "payload": "Testing instruction (curl command, description, or steps)",
      "comment": "Explanation of what this PoC tests"
    }
  ]
}`

	// Rules section - emphasis on human-readable PoCs
	prompt += "\n\n## Rules\n\n"
	prompt += "1. **Must be actionable** - specific step, not generic advice\n"
	prompt += "2. **Human-readable PoCs** - provide clear instructions, NOT raw JSON payloads\n"
	prompt += "3. **Multiple PoC formats** - use curl commands, step-by-step instructions, or descriptions\n"
	prompt += "4. **Each PoC must have a comment** - explain what it tests\n"
	prompt += "5. **Be concrete** - exact changes to make or commands to run\n"

	// Examples section - emphasis on human-readable format
	prompt += "\n## Examples\n\n"

	prompt += "GOOD lead (human-readable PoCs):\n"
	prompt += "{\n"
	prompt += `  "is_actionable": true,` + "\n"
	prompt += `  "title": "Try MD5 substitution",` + "\n"
	prompt += `  "actionable_step": "Replace MD5 hash with another value and check response",` + "\n"
	prompt += `  "pocs": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "payload": "curl -X GET 'http://target/api/ticket/098f6bcd4621d373cade4e832627b4f6' -H 'Cookie: session=...'",` + "\n"
	prompt += `      "comment": "Try another MD5 hash to test if you can access different tickets"` + "\n"
	prompt += `    },` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "payload": "Steps: 1) Copy original MD5 hash from URL 2) Generate new MD5 from '1' 3) Replace in URL 4) Check if response shows different ticket",` + "\n"
	prompt += `      "comment": "Manual testing approach with step-by-step instructions"` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "BAD lead (raw JSON, not human-readable):\n"
	prompt += "{\n"
	prompt += `  "is_actionable": true,` + "\n"
	prompt += `  "title": "Test IDOR",` + "\n"
	prompt += `  "actionable_step": "Change ID parameter",` + "\n"
	prompt += `  "pocs": [` + "\n"
	prompt += `    {"payload": "{\"id\": \"1\"}", "comment": "test"},` + "\n"
	prompt += `    {"payload": "{\"id\": \"2\"}", "comment": "test"}` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "NOT actionable:\n"
	prompt += "{\n"
	prompt += `  "is_actionable": false` + "\n"
	prompt += `  "title": "",` + "\n"
	prompt += `  "actionable_step": "",` + "\n"
	prompt += `  "pocs": []` + "\n"
	prompt += "}\n\n"

	prompt += "IMPORTANT: Focus on HUMAN-READABLE instructions that a security researcher can understand and execute."

	return prompt
}
