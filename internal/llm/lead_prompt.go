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
	BigPicture  *models.BigPicture `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application,nullable"`
}

// LeadData represents a single lead with all its details
type LeadData struct {
	IsActionable   bool              `json:"is_actionable" jsonschema:"description=Whether this lead is actionable"`
	Title          string            `json:"title" jsonschema:"description=Short title (max 10 words)"`
	ActionableStep string            `json:"actionable_step" jsonschema:"description=Concrete testing step"`
	PoCs           []models.PoCEntry `json:"pocs" jsonschema:"description=Human-readable PoC instructions"`
}

// LeadGenerationResponse represents output from lead generation
// Returns 0, 1, or MULTIPLE leads from a single observation
// NOTE: Does NOT include CanAutoVerify field (per user requirements)
type LeadGenerationResponse struct {
	Leads []LeadData `json:"leads" jsonschema:"description=Array of leads generated from this observation (0, 1, or many)"`
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
	prompt += "Generate 0, 1, or MULTIPLE actionable leads from this observation.\n\n"
	prompt += "A single observation can lead to different testing approaches.\n"
	prompt += "Return ALL relevant leads in the leads array.\n\n"
	prompt += "If NO actionable leads - return empty leads array: {\"leads\": []}\n"

	// Output format
	prompt += "\n## Output Format (JSON):\n\n"
	prompt += `{
  "leads": [
    {
      "is_actionable": true,
      "title": "Short title (max 10 words)",
      "actionable_step": "Specific what to try",
      "pocs": [
        {
          "payload": "Testing instruction (curl command, description, or steps)",
          "comment": "Explanation of what this PoC tests"
        }
      ]
    },
    {
      "is_actionable": true,
      "title": "Another testing approach",
      "actionable_step": "Different specific step",
      "pocs": [...]
    }
  ]
}

If NO actionable leads:
{
  "leads": []
}`

	// Rules section - emphasis on human-readable PoCs
	prompt += "\n\n## Rules\n\n"
	prompt += "1. **0, 1, or multiple leads** - return all relevant leads in the leads array\n"
	prompt += "2. **Each lead must be actionable** - specific step, not generic advice\n"
	prompt += "3. **Human-readable PoCs** - provide clear instructions, NOT raw JSON payloads\n"
	prompt += "4. **Multiple PoC formats** - use curl commands, step-by-step instructions, or descriptions\n"
	prompt += "5. **Each PoC must have a comment** - explain what it tests\n"
	prompt += "6. **Be concrete** - exact changes to make or commands to run\n"

	// Examples section - emphasis on human-readable format
	prompt += "\n## Examples\n\n"

	prompt += "Single lead:\n"
	prompt += "{\n"
	prompt += `  "leads": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Try MD5 substitution",` + "\n"
	prompt += `      "actionable_step": "Replace MD5 hash with another value and check response",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {` + "\n"
	prompt += `          "payload": "curl -X GET 'http://target/api/ticket/098f6bcd4621d373cade4e832627b4f6' -H 'Cookie: session=...'",` + "\n"
	prompt += `          "comment": "Try another MD5 hash to test if you can access different tickets"` + "\n"
	prompt += `        }` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "Multiple leads (when different approaches exist):\n"
	prompt += "{\n"
	prompt += `  "leads": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Try MD5 hash substitution",` + "\n"
	prompt += `      "actionable_step": "Replace MD5 hash in URL with different values",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {"payload": "curl ...", "comment": "Try different MD5"}` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    },` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Try removing the hash parameter",` + "\n"
	prompt += `      "actionable_step": "Remove hash to see if server returns default ticket",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {"payload": "curl ... without hash", "comment": "Test parameter removal"}` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "No actionable leads:\n"
	prompt += "{\n"
	prompt += `  "leads": []` + "\n"
	prompt += "}\n\n"

	prompt += "IMPORTANT: Focus on HUMAN-READABLE instructions that a security researcher can understand and execute."

	return prompt
}
