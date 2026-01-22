# Hackerecon

AI-powered security analysis assistant for penetration testing and bug bounty hunting.

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Genkit-1.0.5-FF6F00?style=flat" alt="Genkit Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

## Overview

Hackerecon acts as a "second pilot" for security researchers, analyzing HTTP traffic in real-time to identify potential vulnerabilities. It's designed with a **human-in-the-loop** approach — the AI suggests observations and leads, but humans make decisions.

**Key Principle**: This is an intelligent assistant, not an automated exploitation system.

**Architecture**: Fully client-side application with no centralized server. All processing happens locally on your machine.

## Features

- 🔍 **Real-time HTTP Traffic Analysis** — Intercepts and analyzes HTTP traffic via Burp Suite integration
- 🤖 **4-Phase Agent Pipeline** — Specialized AI agents for different analysis tasks
- 🎯 **Smart Filtering** — 60-70% reduction in LLM calls via heuristic filtering
- 📊 **System Architecture Reconstruction** — Automatically maps application structure
- 🔗 **Connection Discovery** — Finds relationships between security observations
- 📝 **PoC Generation** — Generates proof-of-concept payloads for discovered leads
- 🌐 **Real-time Dashboard** — WebSocket-based live updates

## Architecture

### 4-Phase Agent Pipeline

```
Per-Request (Fast Model):
HTTP Request → Request Filter (heuristic, NO LLM) → 60-70% skip rate
    ↓
Store Exchange → InMemoryGraph (thread-safe storage)
    ↓
PHASE 1: Analyst (per-request, fast LLM)
    → Raw Observations[] + TrafficDigest
    ↓
[Manual Trigger] Deep Analysis Pipeline (Smart Model):
    ↓
PHASE 2: Architect (on raw buffer + site map)
    → SystemArchitecture (TechStack + DataFlows)
    ↓
PHASE 3: Strategist (raw obs + architecture)
    → Aggregated Observations[] + Connections[] + TacticianTasks[]
    ↓
PHASE 4: Tactician (parallel per task, with tools)
    → Leads[] with PoCs
    ↓
WebSocket Broadcast → Dashboard
```

### Agent Roles

| Agent | Model | Purpose |
|-------|-------|---------|
| **Analyst** | Fast (e.g., gemini-1.5-flash) | Per-request analysis, extracts raw observations and traffic digests |
| **Architect** | Smart (e.g., gemini-1.5-pro) | Reconstructs system architecture from collected digests |
| **Strategist** | Smart | Aggregates observations, finds patterns, generates tasks |
| **Tactician** | Smart + Tools | Generates actionable leads with PoCs (parallel execution) |

## Quick Start

### Prerequisites

- Go 1.25+
- Burp Suite (for traffic interception)
- API key for LLM provider (Gemini, OpenAI, or compatible)

### Installation

```bash
# Clone the repository
git clone https://github.com/BetterCallFirewall/Hackerecon.git
cd Hackerecon

# Install dependencies
go mod tidy

# Build
go build -o hackerecon cmd/main.go
```

### Configuration

Create a `.env` file in the project root:

```bash
# LLM Provider (gemini or generic/openai/ollama/localai/lm-studio)
LLM_PROVIDER=gemini

# LLM Models (both required)
LLM_MODEL_FAST=gemini-1.5-flash    # For Analyst (per-request)
LLM_MODEL_SMART=gemini-1.5-pro     # For Architect, Strategist, Tactician

# API Key
API_KEY=your-api-key

# For generic provider (OpenAI-compatible)
# LLM_BASE_URL=https://api.example.com
# LLM_FORMAT=openai

# Application
PORT=8090

# Burp Suite Integration
BURP_HOST=localhost
BURP_PORT=8080
```

### Running

```bash
# Run the application
go run cmd/main.go

# Or run with Genkit Dev UI (for flow inspection)
genkit start -- go run cmd/main.go
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws` | GET | WebSocket for live updates |
| `/health` | GET | Health check |
| `/api/analyze-deep` | POST | Triggers deep analysis (Phases 2-4) |

## Project Structure

```
cmd/
├── main.go                    # Entry point
└── api.go                     # REST API server

internal/
├── config/                    # Environment-based configuration
├── driven/
│   ├── analyzer.go            # 4-phase orchestration (core)
│   ├── burp_integration.go    # Burp Suite proxy integration
│   └── ...
├── llm/
│   ├── analyst_flow.go        # Phase 1: Analyst agent
│   ├── architect_flow.go      # Phase 2: Architect agent
│   ├── strategist_flow.go     # Phase 3: Strategist agent
│   ├── tactician_flow.go      # Phase 4: Tactician agent
│   ├── lead_flow.go           # Tool definitions (getExchange)
│   └── *_prompt.go            # Agent prompts
├── models/
│   ├── detective.go           # Core entities (Observation, Lead, etc.)
│   └── storage.go             # InMemoryGraph (thread-safe storage)
├── utils/
│   └── request_filter.go      # Heuristic filtering
├── websocket/
│   └── hub.go                 # WebSocket manager
└── limits/
    └── limits.go              # Rate limiting
```

## Core Concepts

### Entities

- **HTTPExchange** — Complete HTTP request-response pair
- **Observation** — Security-relevant fact (what, where, why)
- **TrafficDigest** — Token-efficient summary of an exchange
- **Lead** — Actionable security finding with PoCs
- **Connection** — Relationship between entities
- **SystemArchitecture** — Reconstructed tech stack and data flows

### Request Filtering

Heuristic filtering skips 60-70% of traffic:
- Static assets (`.js`, `.png`, `.jpg`, etc.)
- Health checks and monitoring endpoints
- 4xx error responses
- Large responses (>1MB)
- Binary content types (images, video, audio, fonts)

> **Note**: `.css` files are NOT filtered — they can contain sensitive paths/comments

## Development

```bash
# Run tests
go test ./...

# Run specific package tests
go test ./internal/utils -v
go test ./internal/llm -v

# Run specific test
go test -run TestURLNormalizer ./internal/utils
```

## Security Notice

This tool is designed for **legitimate security testing** only:
- Authorized penetration testing
- Security research and education
- Vulnerability assessment of your own applications
- Defensive security analysis

**Only use on systems you own or have explicit permission to test.**

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting a pull request.
