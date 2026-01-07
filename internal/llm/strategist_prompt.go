package llm

import (
	"fmt"
)

// BuildStrategistPrompt creates prompt for Strategist agent
func BuildStrategistPrompt(req *StrategistRequest) string {
	return fmt.Sprintf(`You are a Strategist. Aggregate and analyze these raw observations.

Raw Observations (%d):
%s

Big Picture:
Description: %s

Site Map (%d endpoints):
%s

Your tasks:
1. MERGE: Deduplicate and consolidate similar observations
   - When merging duplicates, collect ALL exchange_ids from merged observations
   - Example: If obs-1 has [exch-1] and obs-2 has [exch-2], merged result should have exchange_ids: [exch-1, exch-2]
2. ANALYZE: Update BigPicture with new insights
3. DIRECT: For dangerous findings, write a clear Hint for the pentester
4. GROUP: Organize related findings into tasks for the pentester
5. CONNECT: Identify relationships between findings

Return JSON:
{
  "observations": [
    {
      "exchange_ids": ["exch-1", "exch-5"],  // ALL exchange IDs where this observation was found (merge duplicates)
      "what": "consolidated fact",
      "where": "location",
      "why": "why interesting",
      "hint": "how to verify/exploit (for actionable findings)"
    }
  ],
  "connections": [
    {
      "from": "obs-1",
      "to": "obs-3",
      "reason": "both relate to authentication bypass"
    }
  ],
  "big_picture_impact": {
    "field": "description|functionalities|technologies",
    "value": "updated content"
  },
  "tactician_tasks": [
    {
      "observations": [/* observation objects */],
      "description": "task description"
    }
  ]
}`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		req.BigPicture.Description,
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
	)
}
