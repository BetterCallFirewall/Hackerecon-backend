package llm

import (
	"fmt"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildArchitectPrompt creates prompt for Architect agent
func BuildArchitectPrompt(req *ArchitectRequest) string {
	return fmt.Sprintf(
		`You are a System Architect for a security team. Your job is to reconstruct the backend architecture and map DATA FLOWS from HTTP traffic observations.

=== INPUT ===

Raw Observations (%d):
%s

=== SITE MAP (%d routes) ===
%s

=== YOUR TASK ===

You must deduce the TECHNOLOGY STACK and map DATA FLOW CHAINS by connecting observations.

**IMPORTANT**: RawObservations come from security-focused Analyst, but contain VALUABLE metadata:
- ID formats detected (MongoDB ObjectID, UUID, integer)
- Response field names ("file_id", "user_id", etc.)
- Request/response patterns
- Parameter names and structures

EXTRACT THIS INFO from observations even if they mention security - the data is still valid for architecture!

STEP 1 - IDENTIFY TECH STACK:

Look for these PATTERNS in observations:

Database Indicators:
• "24-char hex string" (e.g., 507f1f77bcf86cd799439011) → MongoDB ObjectID
• "36-char UUID" (e.g., 550e8400-e29b-41d4-a716-446655440000) → PostgreSQL/UUID
• "Integer IDs" (e.g., /user/123, /shop/456) → SQL auto-increment
• Error messages: "MongoError", "PostgreSQL", "mysql_fetch"
• Response keys: "_id" → MongoDB, "id" → SQL

Backend Indicators:
• "connect.sid" cookie → Express/Node.js
• "X-Powered-By: Express" → Node.js
• "CSRF token", "sessionid" → Python/Django
• "PHPSESSID" → PHP
• Server headers, error formats

Auth Indicators:
• "Bearer" header → JWT
• "session", "sess:" cookie → Session-based
• "OAuth", "Bearer" + refresh token → OAuth

Output TechStack as: "Database, Backend/Framework, Auth method"
Example: "MongoDB, Node.js/Express, Auth via JWT"

STEP 2 - MAP DATA FLOW CHAINS:

**CRITICAL**: Your main job is to find CHAINS of routes that show how data flows.

**USE OBSERVATIONS + SITE MAP TOGETHER**:
- Observations tell you WHAT was detected (ID formats, field names, patterns)
- SiteMap tells you WHICH routes exist (with ExchangeID for reference)
- Cross-reference: If obs mentions "MongoDB ObjectID in /api/files/XXX", find matching route in SiteMap

HOW TO FIND CHAINS:
Look for CONNECTIONS between routes:

1. **By ID flow**:
   - Observation: "POST /api/upload returns MongoDB ObjectID (file_id)"
   - SiteMap: GET /api/files/:id exists
   - Connection: POST creates ID → GET uses same ID
   - Chain: POST /api/upload/ --> GET /api/files/:id

2. **By resource pattern**:
   - SiteMap: POST /api/users, GET /api/users/:id, PUT /api/users/:id, DELETE /api/users/:id
   - Observation: "Integer IDs in user endpoints"
   - Chain: POST /api/users/ --> GET /api/users/:id --> PUT /api/users/:id --> DELETE /api/users/:id

3. **By session/token**:
   - Observation: "JWT token returned from /api/login"
   - Observation: "JWT used in Authorization header for /api/profile"
   - Chain: POST /api/login --> GET /api/profile

4. **By parameter names**:
   - Observation: "Response has file_id field (MongoDB ObjectID)"
   - Observation: "Next request uses file_id in query parameter"
   - Chain shows data lineage

FOR EACH CHAIN:
- Route: "METHOD path1 --> METHOD path2 --> ..."
- InferredLogic: Describe what happens at each step
  - Where does data come FROM? (user input, database, external API)
  - How is it TRANSFORMED? (validation, storage, processing)
  - Where does it GO TO? (database, file system, client response)

EXAMPLE CHAINS:

GOOD CHAIN 1 (File Upload):
Route: "POST /api/upload --> GET /api/files/:id --> DELETE /api/files/:id"
InferredLogic: "User uploads file via POST → Server saves to MongoDB/GridFS with generated ObjectID → Server returns ID in response → Client retrieves file via GET /api/files/:id → Client can delete via DELETE /api/files/:id"

GOOD CHAIN 2 (User Management):
Route: "POST /api/users --> POST /api/login --> GET /api/users/:id --> PUT /api/users/:id"
InferredLogic: "User registration via POST /api/users → User login via POST /api/login → Server returns JWT token → Client accesses profile via GET /api/users/:id using token → Client updates profile via PUT /api/users/:id"

GOOD CHAIN 3 (Shop Flow):
Route: "POST /api/shop/ --> GET /api/shop/:id --> POST /api/shop/:id/buy"
InferredLogic: "User creates shop item via POST /api/shop/ → Server stores item with MongoDB ObjectID → User views item via GET /api/shop/:id → User purchases item via POST /api/shop/:id/buy"

STEP 3 - BUILD OUTPUT:

Return ONLY this JSON structure:
{
  "system_architecture": {
    "tech_stack": "MongoDB, Node.js/Express, Auth via JWT | PostgreSQL, Python/Django, Session-based | etc.",
    "data_flows": [
      {
        "route": "POST /api/upload --> GET /api/files/:id",
        "inferred_logic": "User uploads file → Server stores with generated ID → Server returns ID in response → Client retrieves file by ID via GET /api/files/:id"
      }
    ]
  }
}

=== RULES ===

1. Be SPECIFIC about tech stack - no "maybe", "could be"
2. Map 1-3 MOST INTERESTING data flow chains
3. Each chain must show 2+ routes connected by data flow
4. InferredLogic MUST describe ONLY the data journey (source → transformation → destination), NOT vulnerabilities or attack surface
5. Use "-->" to connect routes in the chain

== CRITICAL OUTPUT RULES ==

1. Return ONLY valid JSON - NO text before or after
2. Start DIRECTLY with "{"
3. End DIRECTLY with "}"
4. NO markdown code blocks`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		len(req.SiteMap),
		formatSiteMapForArchitect(req.SiteMap),
	)
}

// formatSiteMapForArchitect formats site map with focus on route structure
func formatSiteMapForArchitect(entries []models.SiteMapEntry) string {
	result := ""
	for _, e := range entries {
		// Skip static assets and health checks
		if isStaticAssetForArchitect(e.URL) {
			continue
		}
		result += fmt.Sprintf("- %s %s ExchangeID: %s\n", e.Method, e.URL, e.ExchangeID)
		if e.Comment != "" {
			result += fmt.Sprintf("  Comment: %s\n", e.Comment)
		}
	}
	return result
}

// isStaticAssetForArchitect checks if URL is a static asset (skip in architect analysis)
func isStaticAssetForArchitect(url string) bool {
	// Check file extensions first (these can be anywhere in the URL)
	extPatterns := []string{".css", ".js", ".png", ".jpg", ".svg"}
	for _, p := range extPatterns {
		if strings.Contains(url, p) {
			return true
		}
	}

	// Check path patterns (must be at the start to avoid substring matches)
	pathPatterns := []string{"/health", "/ping", "/static"}
	for _, p := range pathPatterns {
		if strings.HasPrefix(url, p) {
			return true
		}
	}

	return false
}
