# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Hackerecon** is an AI-powered security analysis assistant for penetration testing and bug bounty hunting. It acts as a "second pilot" for security researchers, analyzing HTTP traffic in real-time to identify potential vulnerabilities.

**Key Principle**: Human-in-the-loop approach. This is an intelligent assistant, not an automated system. The AI suggests hypotheses and observations, but humans make decisions.

**Architecture**: Fully client-side application with no centralized server. All processing happens locally on the user's machine.

### Current Architecture (Detective Flow)

The system implements a simplified 2-phase "detective game" pipeline:

```
HTTP Request → Request Filter (heuristic, NO LLM) → 60-70% skip rate
    ↓
Store Exchange → InMemoryGraph (thread-safe storage)
    ↓
Unified Analysis (single LLM call) → Comment + Observation? + Connections[] + BigPictureImpact?
    ↓
Lead Generation (optional, separate LLM call) → Lead with PoCs
    ↓
WebSocket Broadcast → Dashboard
```

**Key improvements over old 5-phase flow**:
- 60-70% reduction in LLM calls (heuristic filtering + unified analysis)
- Simplified data model (no complex SiteContext, AttackPlan, or Finding entities)
- Async lead generation doesn't block main analysis
- Thread-safe in-memory storage with `InMemoryGraph`

### Legacy Architecture (5-Phase ReAct Flow)

The old 5-phase implementation has been migrated to the detective flow. See `/docs/` for migration details.

## Common Commands

### Running the Application

```bash
# Run the main application
make run
# or
go run cmd/main.go

# Run with Genkit Dev UI (for flow inspection)
genkit start -- go run cmd/main.go
```

### Build and Development

```bash
# Build the application
go build -o hackerecon cmd/main.go

# Install/update dependencies
go mod tidy

# Run all tests
go test ./...

# Run specific package tests with verbose output
go test ./internal/utils -v
go test ./internal/llm -v

# Run specific test
go test -run TestURLNormalizer ./internal/utils
go test -run TestUnifiedAnalysisFlow ./internal/driven
```

## Code Architecture

### Directory Structure

```
cmd/                          # Application entry points
├── main.go                   # Main entry point (initialization + proxy start)
└── api.go                    # REST API server (/api/hypothesis endpoint)

internal/
├── config/                   # Configuration management
│   └── config.go             # Environment-based config (.env loading)
│
├── driven/                   # Core analysis logic (THE HEART of the system)
│   ├── analyzer.go           # Main detective flow orchestration (~400 lines, simplified from ~1470)
│   ├── burp_integration.go   # Burp Suite proxy integration
│   ├── config.go             # Configuration types
│   ├── http.go               # HTTP utilities and proxy handling
│   └── types.go              # Type definitions
│
├── llm/                      # LLM provider layer (abstraction + implementation)
│   ├── provider.go           # Provider interface
│   ├── factory.go            # Provider factory
│   ├── middleware.go         # LLM middleware
│   ├── simple_genkit_provider.go  # Firebase Genkit implementation
│   ├── unified_flow.go       # Unified analysis flow (replaces 5-phase flow)
│   ├── unified_prompt.go     # Unified analysis prompt
│   └── *_test.go             # Tests
│
├── models/                   # Data models (entities)
│   ├── detective.go          # NEW: Observation, Lead, Connection, BigPicture, SiteMapEntry
│   ├── storage.go            # NEW: InMemoryGraph (thread-safe storage)
│   ├── reasoning.go          # LEGACY: Observation, Hypothesis, AttackPlan (deprecated)
│   ├── vulnerabilities.go    # LEGACY: Finding, TestRequest, Verification (deprecated)
│   ├── site_context.go       # LEGACY: SiteContext (deprecated, replaced by InMemoryGraph)
│   └── dto.go                # Data transfer objects
│
├── websocket/                # Real-time communication
│   └── hub.go                # WebSocket manager for dashboard updates
│
└── limits/                   # Rate limiting
    └── limits.go             # Context limits and memory management

docs/                         # Comprehensive documentation (see below)
notes/                        # Design notes and research
```

### Core Components

#### 1. GenkitSecurityAnalyzer (`internal/driven/analyzer.go`)

The heart of the system. Orchestrates the simplified 2-phase detective pipeline:

```go
type GenkitSecurityAnalyzer struct {
    // Single orchestration flow for all AI operations
    detectiveAIFlow *genkitcore.Flow[*llm.DetectiveAIRequest, *llm.DetectiveAIResult, struct{}]

    // Storage (NOT part of Genkit flow)
    graph *models.InMemoryGraph

    // WebSocket
    wsHub *websocket.WebsocketManager
}
```

**Key method**: `AnalyzeHTTPTraffic()` (internal/driven/analyzer.go:60) - processes each request through:
1. Request filter (heuristic, NO LLM) - skips 60-70% of traffic
2. Store exchange in `InMemoryGraph`
3. Unified analysis (single LLM call) → Comment + Observation? + Connections[] + BigPictureImpact?
4. Lead generation (optional, separate LLM call)
5. WebSocket broadcast

#### 2. Models (`internal/models/`)

**Current Entities** (detective.go):
- **HTTPExchange**: Complete HTTP request-response pair with timestamp
- **Observation**: Security-relevant fact (what, where, why) - FACT, not interpretation
- **Lead**: Actionable security lead with PoCs (replaces Hypothesis + Finding)
- **Connection**: Relationship between two entities (obs-1 → obs-3 because...)
- **BigPicture**: High-level understanding (description, functionalities, technologies)
- **BigPictureImpact**: Suggested update to BigPicture
- **SiteMapEntry**: Burp-style site map entry

**Storage** (storage.go):
- **InMemoryGraph**: Thread-safe in-memory storage with `sync.RWMutex`
  - `StoreExchange()` - stores HTTP exchange, returns ID
  - `AddObservation()` - stores observation, returns ID
  - `AddLead()` - stores lead, returns ID
  - `AddConnection()` - stores connection between entities
  - `UpdateBigPicture()` - updates high-level understanding
  - `GetRecentObservations()` - returns N most recent observations

**Legacy Entities** (deprecated, kept for reference):
- `reasoning.go`: Observation, Hypothesis, AttackPlan
- `vulnerabilities.go`: Finding, TestRequest, Verification
- `site_context.go`: SiteContext (replaced by InMemoryGraph)

#### 3. LLM Provider (`internal/llm/`)

**Provider Interface** (`provider.go`):

```go
type Provider interface {
    GenerateSecurityAnalysis(ctx, req) (*SecurityAnalysisResponse, error)
    GenerateURLAnalysis(ctx, req) (*URLAnalysisResponse, error)
    GenerateHypothesis(ctx, req) (*HypothesisResponse, error)
    GenerateVerificationPlan(ctx, req) (*VerificationPlanResponse, error)
    AnalyzeVerificationResults(ctx, req) (*VerificationAnalysisResponse, error)
    AnalyzeBatchVerification(ctx, req) (*BatchVerificationResult, error)

    // ReAct methods
    GenerateReasoning(ctx, req) (*ReasoningResponse, error)
    GeneratePlan(ctx, reasoning, req) (*PlanResponse, error)
}
```

**Implementation**: `SimpleGenkitProvider` - Firebase Genkit integration supporting:
- Gemini API (default)
- Generic OpenAI-compatible APIs (Ollama, LocalAI, etc.)
- JSON schema validation
- Prompt engineering in `prompt.go`

#### 4. Configuration (`internal/config/`)

Environment-based configuration via `.env`:

```bash
# LLM Configuration
LLM_PROVIDER=gemini  # or "generic" for OpenAI-compatible APIs
LLM_MODEL=
API_KEY=
LLM_BASE_URL=       # For generic provider
LLM_FORMAT=openai   # openai, ollama, raw

# Application
PORT=8090

# Burp Suite Integration
BURP_HOST=
BURP_PORT=8080
```

## Documentation

### Main Documentation (`/docs/`)

- **README.md**: Migration documentation index (5-phase → Detective flow)
- **ENTITY_MAPPING.md**: Detailed entity-by-entity mapping analysis
- **ENTITY_MAPPING_DIAGRAM.md**: Visual ASCII diagrams of the architecture
- **MAPPING_CHEAT_SHEET.md**: Quick reference tables for migration
- **MIGRATION_GUIDE.md**: Step-by-step implementation guide with code examples

### Design Notes (`/notes/`)

- **MAIN_IDEA.md**: Project concept and Human-in-the-loop philosophy
- **DETECTIVE_FLOW_DESIGN.md**: Future "detective game" architecture (1000+ lines)
- **DETECTIVE_GAME_FLOW.md**: Detective game mechanics

## Data Flow

### Current Request Lifecycle (Detective Flow)

```
1. HTTP Request received by proxy
   ↓
2. RequestFilter heuristic check (skip 60-70%: static assets, health checks)
   - O(1) extension lookup via map
   - Path-based filtering for analytics/static
   - Content-Type blacklist
   ↓
3. Store Exchange in InMemoryGraph
   - Generate unique exchange ID (exch-N)
   - Thread-safe storage with sync.RWMutex
   ↓
4. Unified Analysis (single LLM call)
   - Input: Exchange + BigPicture + RecentObservations
   - Output: Comment (required) + Observation? + Connections[] + BigPictureImpact?
   ↓
5. Apply AI Results
   - Store Observation (if any)
   - Store Connections (if any)
   - Update BigPicture (if impact suggested)
   ↓
6. Lead Generation (optional, separate LLM call)
   - If observation is actionable
   - Generate Lead with PoCs
   ↓
7. WebSocket Broadcast → Dashboard
   - Single message with all results
```

### Legacy Request Lifecycle (5-Phase Flow)

The old 5-phase pipeline has been migrated to the detective flow. See `/docs/` for details.

## Key Features

- **Real-time traffic analysis**: Intercepts HTTP/HTTPS via proxy
- **2-phase detective flow**: Simplified LLM reasoning with 60-70% fewer calls
- **Heuristic filtering**: O(1) request filtering skips 60-70% of traffic without LLM
- **In-memory graph storage**: Thread-safe storage with `InMemoryGraph`
- **Burp Suite integration**: Works as upstream proxy or standalone
- **BigPicture tracking**: High-level application understanding maintained across requests
- **WebSocket dashboard**: Real-time updates to web interface

## Development Guidelines

### Code Style

- **Language**: Go 1.25.1
- Follow [Go Best Practices](https://go.dev/doc/effective_go) and [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)
- Tests co-located with source files (`*_test.go`)
- Use `sync.RWMutex` for concurrent access to shared state (InMemoryGraph)

### Important Principles

1. **Human-in-the-loop**: This is an assistant, not an automated system
2. **Teach, don't just solve**: Provide explanations with examples from the codebase
3. **Use skills and subagents**: Leverage available tools for speed and quality
4. **Don't make changes without explicit command**: Read-only exploration unless told otherwise

### Key Files to Understand

**Current Implementation**:
- `internal/driven/analyzer.go` - Core 2-phase orchestration logic (simplified from ~1470 to ~400 lines)
- `internal/models/detective.go` - NEW: Observation, Lead, Connection, BigPicture entities
- `internal/models/storage.go` - NEW: InMemoryGraph thread-safe storage
- `internal/llm/unified_flow.go` - NEW: Unified analysis flow (replaces 5-phase flow)
- `internal/llm/unified_prompt.go` - NEW: Unified analysis prompt
- `internal/utils/request_filter.go` - Heuristic filtering (60-70% skip rate, NO LLM)

**Legacy** (kept for reference, see `/docs/` for migration details):
- `internal/models/reasoning.go` - OLD: Hypothesis, AttackPlan
- `internal/models/vulnerabilities.go` - OLD: Finding, TestRequest
- `internal/models/site_context.go` - OLD: SiteContext (replaced by InMemoryGraph)
- `internal/llm/prompt.go` - OLD: Reasoning, Planning, Acting prompts

## Git Worktrees

The project uses Git worktrees for parallel development:

- `worktrees/active-verification/` - Active verification feature
- `worktrees/enhanced-hypothesis/` - Hypothesis enhancements
- `worktrees/enhanced-sitecontext/` - SiteContext improvements

Each worktree has its own CLAUDE.md with branch-specific guidance.

## Current Branch

**Branch**: `feature/plain_agent`

Recent work focuses on refactoring the analysis flow and prompt improvements.

## Security Context

This is a legitimate security testing tool designed for:
- Authorized penetration testing
- Security research and education
- Vulnerability assessment of own applications
- Defensive security analysis

The tool should only be used on systems you own or have explicit permission to test.
