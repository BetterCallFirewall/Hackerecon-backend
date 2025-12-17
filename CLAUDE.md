# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hackerecon is an AI-powered HTTP/HTTPS security proxy that uses Large Language Models to analyze web traffic for vulnerabilities in real-time. Designed as a "human-in-the-loop" assistant for security testing and bug bounty hunting, it intercepts web traffic, analyzes it using LLM models, and provides structured vulnerability reports through a WebSocket-connected dashboard.

## Common Commands

### Running the Application
```bash
# Run the main application (proxy + API server)
make run
# or
go run cmd/main.go

# Run with Genkit Dev UI (for flow inspection and debugging)
genkit start -- go run cmd/main.go

# Build the application
go build -o hackerecon cmd/main.go

# Install dependencies
go mod tidy
```

### Testing
```bash
# Note: Currently minimal test coverage (~5%) - this is a known improvement area
go test ./...  # Run all tests
# No specific package tests exist yet in internal/ directory
```

## Project Architecture

### Performance-Optimized Data Flow

The system uses a **two-stage analysis approach** for optimal performance:

```
HTTP Request → Request Filter (70-90% filtered) → URL Normalizer → Cache Check (40-60% hit rate)
    ↓
Stage 1: Quick URL Analysis (~1 sec) - Is this suspicious?
    ↓ (only for important URLs)
Stage 2: Full Security Analysis (~3 sec) - Complete vulnerability assessment
    ↓
Structured Report → WebSocket Broadcast → Dashboard
```

### Core Components

1. **Main Entry Point** (`cmd/main.go`)
   - Initializes configuration from environment variables
   - Sets up WebSocket manager for real-time communication
   - Creates security proxy with Genkit integration
   - Starts API server for hypothesis generation in separate goroutine

2. **API Server** (`cmd/api.go`)
   - REST API server with CORS middleware
   - `/api/hypothesis/{host}` endpoint for generating security hypotheses
   - Supports technology stack detection and attack vector analysis

3. **Security Proxy** (`internal/driven/http.go`)
   - `SecurityProxyWithGenkit` - Main proxy server with HTTP/HTTPS traffic interception
   - CONNECT tunneling support for HTTPS traffic
   - Optional Burp Suite integration with automatic fallback logic
   - Asynchronous analysis using the security analyzer

4. **AI Security Analyzer** (`internal/driven/analyzer.go`)
   - `GenkitSecurityAnalyzer` - Core analysis engine using Genkit flows
   - Two-stage analysis: quick URL assessment → full security analysis
   - Maintains site context for improved analysis across requests
   - Generates structured vulnerability reports with AI commentary

5. **Unified LLM Provider** (`internal/llm/simple_genkit_provider.go`)
   - **Single unified provider** supporting multiple LLM backends (refactored from 800+ lines to 130 lines)
   - Supports Google Gemini (via Genkit) and OpenAI-compatible APIs (Ollama, LocalAI, etc.)
   - Uses structured JSON output with `GenerateData` for consistent results

6. **Configuration Management** (`internal/config/config.go`)
   - Environment-based configuration loading from `.env` files
   - Support for multiple LLM providers with unified interface
   - Configurable proxy settings and Burp Suite integration

7. **WebSocket Hub** (`internal/websocket/hub.go`)
   - Real-time communication with web dashboard
   - Single client connection with automatic cleanup
   - Broadcasts analysis results and status updates

8. **Optimized Utilities** (`internal/utils/`)
   - `request_filter.go` - Smart filtering (70-90% of requests filtered out)
   - `url_normalizer.go` - Pattern normalization ( `/users/123` → `/users/{id}` )
   - `tech_detector.go` - Technology stack detection from responses

9. **Data Management** (`internal/models/`)
   - `vulnerabilities.go` - Structured vulnerability reports
   - `site_context.go` - Per-site context storage for analysis improvement
   - `dto.go` - Data transfer objects for API communication

### Recent Optimizations (Refactoring Completed)

The codebase has undergone significant refactoring with **10-20x performance improvements**:

- **✅ Unified LLM Provider**: Single Genkit flow replacing 800+ lines of provider code
- **✅ Prompt Optimization**: Reduced by 35% (654→422 lines) with templates in `internal/llm/prompts/`
- **✅ Regex Performance**: Package-level compiled regex for URL normalization
- **✅ Smart Caching**: 40-60% cache hit rate reducing LLM calls by 70-90%
- **✅ Dead Code Removal**: ~1631 lines of unused code eliminated

### LLM Provider Architecture

**Unified Provider Pattern**: The project uses a single `SimpleGenkitProvider` that supports:

- **Gemini Mode** (default): Google's Genkit framework with Google AI models
- **Generic Mode**: OpenAI-compatible APIs with configurable formats:
  - `LLM_FORMAT=openai`: LM Studio, LocalAI, vLLM
  - `LLM_FORMAT=ollama`: Ollama local models
  - `LLM_FORMAT=raw`: Custom HTTP APIs

All providers use the same Genkit flow for consistent structured output.

### Key Features

- **Real-time Analysis**: Two-stage vulnerability detection with ~1 sec quick analysis
- **Smart Filtering**: Automatically filters 70-90% of static requests
- **Multi-Provider Support**: Gemini, Ollama, LM Studio, LocalAI, and OpenAI-compatible APIs
- **Context-Aware**: Maintains per-site context for improved analysis accuracy
- **Structured Output**: JSON-formatted vulnerability reports with AI commentary
- **WebSocket Integration**: Real-time updates to connected dashboard
- **Burp Suite Compatible**: Optional integration with automatic fallback
- **Performance Optimized**: 10-20x faster than previous version with smart caching

## Environment Configuration

Copy `.env.example` to `.env` and configure:

### Required Settings
- `LLM_PROVIDER`: Provider type ("gemini" or "generic")
- `API_KEY`: API key for the LLM provider (Gemini requires key, Ollama doesn't)
- `LLM_MODEL`: Model name to use (e.g., "gemini-1.5-pro", "llama3.1:8b")

### Generic Provider Settings (when `LLM_PROVIDER=generic`)
- `LLM_BASE_URL`: Base URL for the provider API
- `LLM_FORMAT`: API format - "openai" (LM Studio, LocalAI), "ollama", or "raw"

### Proxy Settings
- `PORT`: Proxy listen port (default: 8090)
- `BURP_HOST`/`BURP_PORT`: Optional Burp Suite integration

## Genkit Integration

### Core Flows
- **`securityAnalysisFlow`**: Main vulnerability analysis flow in `internal/driven/analyzer.go`
- **`urlAnalysisFlow`**: Quick URL pattern analysis for filtering
- **`hypothesisFlow`**: Security hypothesis generation for attack vectors

### Development Workflow
```bash
# Run with Genkit Developer UI for flow inspection
genkit start -- go run cmd/main.go

# Access Genkit UI at: http://localhost:4000
# - View flow executions and traces
# - Debug prompt templates and model responses
# - Monitor performance metrics
```

### Prompt Templates
Prompts are stored in `internal/llm/prompts/`:
- `security_analysis.tmpl`: Main vulnerability detection prompt
- `hypothesis.tmpl`: Attack vector hypothesis generation
- `url_analysis.tmpl`: Quick URL pattern assessment

## Development Architecture

### Project Structure
```
cmd/                    # Entry points
├── main.go            # Main proxy + WebSocket + API server
└── api.go             # REST API for hypothesis generation

internal/
├── config/            # Environment configuration management
├── driven/            # Core business logic
│   ├── analyzer.go    # Genkit flows and security analysis
│   ├── http.go        # HTTP/HTTPS proxy server
│   ├── hypothesis.go  # Security hypothesis generation
│   └── extractor.go   # Data extraction from requests/responses
├── llm/               # LLM provider abstraction
│   ├── simple_genkit_provider.go  # Unified provider (130 lines)
│   └── prompts/       # Template files for analysis
├── models/            # Data structures and domain models
├── utils/             # Performance-optimized utilities
│   ├── request_filter.go    # Smart request filtering
│   ├── url_normalizer.go    # Pattern normalization
│   └── tech_detector.go     # Technology detection
└── websocket/         # Real-time communication
```

### Performance Characteristics
- **Request Filtering**: 70-90% of static requests automatically filtered
- **Cache Hit Rate**: 40-60% for repeated URL patterns
- **Analysis Time**: ~1 sec for URL analysis, ~3 sec for full analysis
- **Memory Usage**: In-memory context storage with automatic cleanup

## Security Context

This is a legitimate security testing tool designed for:
- Authorized penetration testing
- Security research and education
- Vulnerability assessment of own applications
- Defensive security analysis

The tool should only be used on systems you own or have explicit permission to test.
- Данный проект предполагает подход Human in the loop. Утилита задумывается как второй пилот для человека, решающего CTF задачи или занимающегося bug bounty. Очень важно создать толкового помощника для решения задач, а не автоматизированную систему
- Данный проект является клиентским приложением без централизованного сервера. То есть весь проект целиком располагается на компьютере пользователя
- Проект пишется на Go. Руководствуйся Go Best Practice и Go Uber гайдами
