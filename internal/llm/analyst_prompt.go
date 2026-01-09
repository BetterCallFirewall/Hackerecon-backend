package llm

import (
	"fmt"
)

const (
	maxBodySizeForAnalystPrompt = 2000 // Maximum body size for analyst prompt (2KB)
)

// BuildAnalystPrompt creates prompt for Analyst agent
// Uses smart truncation for request/response bodies to reduce LLM context usage
func BuildAnalystPrompt(req *AnalystRequest) string {
	// Apply smart truncation to bodies
	truncatedReqBody := prepareBodyForLLM(req.Exchange.Request.Body, getContentType(req.Exchange.Request.Headers), true)
	truncatedRespBody := prepareBodyForLLM(
		req.Exchange.Response.Body, getContentType(req.Exchange.Response.Headers), false,
	)

	// If still too large after smart truncation, apply additional limit
	if len(truncatedReqBody) > maxBodySizeForAnalystPrompt {
		truncatedReqBody = TruncateBody(truncatedReqBody, maxBodySizeForAnalystPrompt)
	}
	if len(truncatedRespBody) > maxBodySizeForAnalystPrompt {
		truncatedRespBody = TruncateBody(truncatedRespBody, maxBodySizeForAnalystPrompt)
	}

	return fmt.Sprintf(
		`You are an Analyst for a CTF/pentesting team. Extract ONLY exploitable facts from this HTTP exchange.

=== EXCHANGE ===
Method: %s
URL: %s
Request Headers: %s
Request Body: %s
Response Status: %d
Response Headers: %s
Response Body: %s

=== PRIORITY PATTERNS (CTF-FOCUSED) ===
HIGH PRIORITY - Logical Vulnerabilities:
1. IDOR/Broken Access Control: user_id=5 -> try 4, 6, admin
2. JWT Issues: alg=none, weak secrets, expired tokens accepted
3. Race Conditions: /withdraw, /transfer, double-spend opportunities
4. GraphQL Introspection: /graphql?query={__schema}
5. API Chaining: token leak in response -> reuse in next request
6. File Upload: webshell via .php5, .phtml, double extensions
7. SSTI: {{7*7}}, ${7*7}, #{7*7} in parameters
8. XXE: XML payloads with <!ENTITY
9. Injection in URL Path: URL segments that look like IDs (UUID, Mongo ObjectID) or JSON keys.
   CRITICAL: If backend is likely NodeJS/MongoDB, URL params might be passed directly to DB queries.

=== DATA FLOW PATTERNS (HELPFUL FOR ARCHITECT) ===

Technical Signs (helps identify tech stack and data flows):
1. ID Formats in URL/Response:
   - /api/shop/507f1f77bcf86cd799439011 → 24-char hex = MongoDB ObjectID
   - /api/shop/550e8400-e29b-41d4-a716-446655440000 → 36-char UUID
   - /api/users/123 → Integer ID = SQL auto-increment
   OBSERVE: Exact format, position in URL, parameter name

2. Response Structure:
   - {"_id": "..."} → MongoDB
   - {"id": 123} → SQL
   - {"file_id": "abc", "url": "/files/abc"} → Shows data flow

3. Request Body Structure:
   - JSON arrays → {"users": [...]} → Bulk operations
   - Nested objects → {"user": {"profile": {...}}} → Complex schema
   - File uploads → multipart/form-data → File handling

4. Parameter Names (reveal functionality):
   - user_id, profile_id, order_id → Resource identifiers
   - file_id, upload_id → File operations
   - redirect_url, next → Open redirect potential

MEDIUM PRIORITY - Classic Vulns:
1. SQLi: ', ", 1' OR '1'='1, union select
2. XSS: <script>, <img, javascript: in reflected params
3. SSRF: url=, dest=, redirect= parameters
4. Deserialization: pickle, java serialization, PHP unserialize
5. Command Injection: ; ls, 'whoami', $(cat /etc/passwd)

LOW PRIORITY (only if unique/unusual):
1. Tech stack: specific frameworks, CMS versions
2. Security mechanisms: WAF, rate limiting, CSP
3. Interesting parameters: debug=, test=, admin=

=== IGNORE (DO NOT EXTRACT) ===
1. Static assets: .css, .js, .png, .jpg, .svg, .ico, fonts
2. Standard headers: Server, Date, Content-Type, Cache-Control
3. Old library versions: jQuery 1.12, Bootstrap 3.3, etc.
4. Missing security headers: no X-Frame-Options, no CSP
5. Generic error messages: 404, 500, "internal server error"
6. Protocol: HTTP vs HTTPS - not relevant for analysis

=== EXAMPLES ===

GOOD OBSERVATIONS (exploitable):
{
  "what": "JWT with alg=none allows token forgery",
  "where": "Response header: Authorization: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
  "why": " alg=none bypasses signature verification - can craft admin tokens"
}

{
  "what": "IDOR vulnerability in /api/profile/{user_id}",
  "where": "URL: /api/profile/12347, Response body leaks other user data",
  "why": "Sequential user_id (12347) likely allows accessing any user profile"
}

{
  "what": "GraphQL introspection enabled",
  "where": "Response to POST /graphql with query {__schema {types {name}}}",
  "why": "Full schema exposed - can discover hidden queries/mutations"
}

{
  "what": "Race condition on /withdraw endpoint",
  "where": "Request: POST /withdraw with amount=100, no nonce/timestamp",
  "why": "Can send simultaneous requests to bypass balance check (double-spend)"
}

{
  "what": "PHP unserialize() in user_data cookie",
  "where": "Cookie: user_data=TzoyMDoiRGF0YUxlYWRlciI6Mjp7fQ==",
  "why": "Base64 decodes to PHP serialized object - potential object injection"
}
{
  "what": "MongoDB ObjectID format in URL parameter",
  "where": "URL: /api/shop/507f1f77bcf86cd799439011",
  "why": "24-char hex string indicates MongoDB backend - critical for NoSQLi testing"
}

BAD OBSERVATIONS (should be ignored):
❌ "jQuery 2.1.1 detected in script tag" - old library, not exploitable
❌ "Missing X-Frame-Options header" - generic issue, low impact
❌ "Server: nginx/1.18.0" - standard header, not useful
❌ "Cache-Control: no-cache" - normal cache behavior
❌ "404 Not Found for /admin" - expected, not interesting

=== INSTRUCTIONS ===
1. Extract 3-5 most exploitable facts
2. Each observation must indicate potential exploit path
3. Local context only (this single exchange)
4. Be specific: exact header names, parameter values, endpoints
5. If nothing exploitable, return empty observations array

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
      "what": "specific, actionable finding",
      "where": "precise location with actual values",
      "why": "clear exploit path or impact"
    }
  ]
}`,
		req.Exchange.Request.Method,
		req.Exchange.Request.URL,
		formatHeaders(req.Exchange.Request.Headers),
		truncatedReqBody,
		req.Exchange.Response.StatusCode,
		formatHeaders(req.Exchange.Response.Headers),
		truncatedRespBody,
	)
}
