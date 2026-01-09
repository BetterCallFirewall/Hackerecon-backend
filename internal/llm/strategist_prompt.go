package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildStrategistPrompt creates prompt for Strategist agent
func BuildStrategistPrompt(req *StrategistRequest) string {
	return fmt.Sprintf(
		`You are a Strategist. Aggregate and analyze these raw observations.

Raw Observations (%d):
%s

Big Picture:
Description: %s

=== SYSTEM ARCHITECTURE (from Architect) ===
%s

Site Map (%d endpoints):
%s

Your tasks:
1. MERGE: Deduplicate and consolidate similar observations
   - When merging duplicates, collect ALL exchange_ids from merged observations
   - Example: If obs-1 has [exch-1] and obs-2 has [exch-2], merged result should have exchange_ids: [exch-1, exch-2]
2. ANALYZE: Update BigPicture with new insights
3. DIRECT: For dangerous findings, write a clear Hint for the pentester
4. GROUP: Organize related findings into tasks for the pentester
5. CONNECT: Identify EXPLOITABLE RELATIONSHIPS between findings

CRITICAL: Your most important job is finding exploitable CONNECTIONS between observations.
CTFs are rarely about single bugs - they're about chaining findings together.

Definitions:
- "DANGEROUS": Finding that could lead to:
  * Direct flag/credential exposure
  * Authentication bypass (JWT, session, IDOR)
  * Remote code execution
  * SQL injection with sensitive data
  * Privilege escalation
  NOT: informational findings like "React detected" or "CORS misconfig on public endpoint"

CHAIN OF THOUGHT - Think step by step before outputting JSON:

STEP 1 - MERGE: Scan for duplicates
  - Same what/where/why? Merge them
  - Collect ALL exchange_ids from merged observations
  - Example: obs-1 (JWT in /api/auth, exch-1) + obs-5 (JWT in /api/auth, exch-9) → single obs with [exch-1, exch-9]

STEP 2 - THREAT MODELING (USE SYSTEM ARCHITECTURE ABOVE):

You receive SystemArchitecture from the Architect (shown in "=== SYSTEM ARCHITECTURE ===" section above).
USE IT for stack-specific threat modeling based on the TechStack and DataFlows provided.

STACK-SPECIFIC ATTACK VECTORS:

IF TechStack mentions "MongoDB":
  • NoSQLi in URL params: /api/item/507f1f... → /api/item/{"$ne":null}
  • NoSQLi in JSON body: {"user":{"$ne":null}, "pass":{"$ne":null}}
  • Regex extraction: {"password":{"$regex":".*"}}
  • Operator injection: {"$gt":""}, {"$in":[...]}

IF TechStack mentions "PostgreSQL" OR "MySQL":
  • SQLi in string params: ' OR '1'='1
  • UNION-based extraction: ' UNION SELECT username,password FROM users--
  • Boolean-based: ' AND 1=1 (true) vs ' AND 1=2 (false)

IF TechStack mentions "Python" OR "Jinja2":
  • SSTI: {{7*7}} → {{config.items()}}
  • Template injection: {{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

IF TechStack mentions "JWT":
  • alg=none attack: Remove signature, change payload
  • Weak secret: Brute force with jwt-cracker
  • Key confusion: RSA → HMAC

DATA FLOW ATTACK SURFACE:

For each DataFlow chain:
- Analyze the ROUTE CHAIN for injection points
- Look for: URL parameters, JSON bodies, query strings
- Cross-reference with InferredLogic to find vulnerabilities

EXAMPLE:
If DataFlow is "POST /api/upload --> GET /api/files/:id"
And Logic says "retrieval by ID"
And TechStack says "MongoDB"
→ TASK: Test NoSQLi in GET /api/files/{'$ne':null}

STEP 3 - PER DATAFLOW ANALYSIS:

FOR EACH DataFlow in SystemArchitecture.DataFlows:
1. Analyze THIS chain:
   - Input points: Where does user-controlled data enter?
   - Transformations: How is it processed/sanitized?
   - Sink points: Where does it end up (DB query, file system, response)?

2. Apply stack-specific attack vectors:
   IF TechStack contains "MongoDB" AND DataFlow has ID in URL
   → Create task for NoSQLi in that specific endpoint

   IF TechStack contains "PostgreSQL"/"MySQL" AND DataFlow has ID in URL
   → Create task for SQLi in that specific endpoint

   IF TechStack contains "Jinja2"/"Python" AND DataFlow has user input
   → Create task for SSTI via template injection

   IF TechStack contains "React"/"Vue"/"JavaScript"/"Angular" AND DataFlow has user input in HTML context
   → Create task for XSS via reflected or stored injection

   IF TechStack contains "requests"/"httpx"/"fetch"/"axios" AND DataFlow has URL parameter
   → Create task for SSRF via internal endpoint access (metadata APIs, internal IPs)

For other technologies in the stack, apply standard OWASP Top 10 vectors:
- IDOR (insecure direct object reference) - sequential IDs, user-controlled identifiers
- XXE (XML external entity) - XML parsing libraries
- Insecure deserialization - pickle, JSON, YAML libraries
- Command injection - shell execution, os.system, subprocess
- File inclusion - local/remote file inclusion via path traversal

3. Output ONE TacticianTask per vulnerable DataFlow with:
   - dataflow: The specific chain route (e.g., "POST /api/shop/ --> GET /api/shop/:id")
   - observation_ids: Only observations related to THIS chain
   - description: Specific to this chain's vulnerability

IMPORTANT:
- One task per DataFlow (if vulnerable)
- Not one task per vulnerability type
- Skip DataFlows that have no exploitable vulnerabilities

STEP 4 - CONNECT: Find EXPLOITABLE relationships (THIS IS CRITICAL)
  Good exploitable connections:
    ✓ "MongoDB ObjectID (obs-1) + REST API (obs-2) → Potential NoSQLi via URL Injection"
      Reason: Backend might pass URL parameter directly to find() query.
    ✓ "Jinja2 template syntax in error (obs-2) → user-controlled name parameter (obs-5)"
      Reason: SSTI via {{7*7}} → RCE through {{config.items()}}
    ✓ "MD5 hash as user ID in /users/a3f5e... (obs-3) → hash decryptable (obs-7)"
      Reason: Can decrypt MD5 via rainbow tables and impersonate other users
    ✓ "JWT authentication endpoint (obs-1) → public key endpoint /static/key.pem (obs-3)"
      Reason: Can download public key, attempt to forge JWT signature
    ✓ "IDOR on /api/users/{id} (obs-2) → no auth check on PUT /api/users/{id} (obs-7)"
      Reason: Chain IDOR with missing auth to modify any user's data

  Bad trivial connections (DO NOT MAKE):
    ✗ "React frontend (obs-1) → Node.js backend (obs-2)"
      Reason: Just technology stack, NOT an exploitable relationship
    ✗ "HTTPS used (obs-3) → has cookies (obs-5)"
      Reason: Standard web behavior, no exploit potential

STEP 5 - CREATE HINTS: For dangerous findings, give ACTIONABLE hints
  Good: "NoSQLi test: POST /api/login with {\"user\":{\"$ne\":null}}"
  Good: "SSTI test: {{7*7}} or {{config.items()}} in template parameter"
  Good: "MD5 ID: extract hash from /users/a3f5e..., decrypt via rainbow tables, substitute with admin's hash"
  Good: "Try negative IDs: /api/users/-1 might expose admin data"
  Bad: "Check JWT security" (too vague)
  Bad: "Test for SQLi" (no specific guidance)

STEP 6 - GROUP: Organize related findings into tasks
  - Group by exploit chain (e.g., "Authentication Bypass Chain")
  - Group by vulnerability type (e.g., "SQL Injection Opportunities")
  - Group by endpoint/feature (e.g., "User Management Issues")
  - Each task should have 2-5 related observations

== CRITICAL OUTPUT RULES ==

1. Return ONLY valid JSON - NO text before or after
2. Do NOT include conversational filler like:
   - "Here is the analysis:"
   - "I'll provide the findings:"
   - "Based on the observations:"
3. Start your response DIRECTLY with "{"
4. End DIRECTLY with "}"
5. NO markdown code blocks around JSON

Return JSON:
{
  "observations": [
    {
      "exchange_ids": ["exch-1", "exch-5"],  // ALL exchange IDs where this observation was found (merge duplicates)
      "what": "consolidated fact",
      "where": "location",
      "why": "why interesting",
      "hint": "specific exploit technique (for actionable findings)"
    }
  ],
  "connections": [
    {
      "from": "obs-1",
      "to": "obs-3",
      "reason": "JWT endpoint (obs-1) lacks algorithm verification + public key exposed (obs-3) = token forgery possible"
    }
  ],
  "big_picture_impact": {
    "field": "description|functionalities|technologies",
    "value": "updated content"
  },
  "tactician_tasks": [
    {
      "dataflow": "POST /api/shop/ --> GET /api/shop/:id",  // The specific route chain being analyzed
      "observation_ids": ["obs-1", "obs-3", "obs-5"],  // IDs of observations for this task (only related to THIS chain)
      "description": "NoSQLi in GET /api/shop/:id via MongoDB ObjectID injection with payload {\"$ne\":null}"
    }
  ]
}`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		req.BigPicture.Description,
		formatSystemArchitecture(req.SystemArchitecture),
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
	)
}

// formatSystemArchitecture formats SystemArchitecture for prompt display
func formatSystemArchitecture(sa *models.SystemArchitecture) string {
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
