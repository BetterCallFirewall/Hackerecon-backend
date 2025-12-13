# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hackerecon is a security analysis proxy that uses AI (Google's Genkit framework) to analyze HTTP traffic for vulnerabilities. The proxy intercepts web traffic, analyzes it using LLM models (primarily Gemini), and provides real-time security assessments through a web dashboard.

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

# Install dependencies
go mod tidy

# Run tests
go test ./...
go test ./internal/utils -v  # Run specific package tests
go test -run TestURLNormalizer ./internal/utils  # Run specific test
```

## Project Architecture

### Core Components

1. **Main Entry Point** (`cmd/main.go`)
   - Initializes configuration from environment variables
   - Sets up WebSocket manager for real-time communication
   - Creates security proxy with Genkit integration
   - Starts API server for hypothesis generation

2. **API Server** (`cmd/api.go`)
   - REST API server with CORS middleware
   - `/api/hypothesis/{host}` endpoint for generating security hypotheses
   - Runs in separate goroutine from main proxy

3. **Security Proxy** (`internal/driven/http.go`)
   - `SecurityProxyWithGenkit` - Main proxy server that intercepts HTTP/HTTPS traffic
   - Supports both direct connections and Burp Suite integration with fallback logic
   - Handles CONNECT tunneling for HTTPS traffic
   - Analyzes traffic asynchronously using the security analyzer

4. **AI Security Analyzer** (`internal/driven/analyzer.go`)
   - `GenkitSecurityAnalyzer` - Core analysis engine using Genkit flows
   - Supports both Gemini (via Genkit) and generic LLM providers
   - Extracts secrets, URLs, JavaScript functions, and HTML data
   - Maintains site context for improved analysis across requests
   - Generates structured vulnerability reports with AI commentary

5. **LLM Providers** (`internal/llm/`)
   - `provider.go` - Provider interface and factory
   - `gemini.go` - Google Gemini integration via Genkit
   - `generic.go` - OpenAI-compatible API support (Ollama, LocalAI, etc.)
   - `prompt.go` - Centralized prompt management

6. **Configuration Management** (`internal/config/config.go`)
   - Loads settings from `.env` files
   - Supports multiple LLM providers (Gemini, Generic/OpenAI-compatible)
   - Configurable proxy settings and Burp Suite integration

7. **WebSocket Hub** (`internal/websocket/hub.go`)
   - Manages real-time communication with the web dashboard
   - Broadcasts analysis results to connected clients
   - Handles single client connection with automatic cleanup

8. **Utility Modules** (`internal/utils/`)
   - `url_normalizer.go` - URL pattern normalization with context awareness
   - `tech_detector.go` - Technology stack detection
   - `request_filter.go` - Request filtering logic

### Data Flow

1. **Traffic Interception**: Proxy receives HTTP/HTTPS requests from clients
2. **Route Handling**: Either forwards through Burp Suite or directly to target
3. **Analysis**: Extracts request/response data and sends to AI analyzer
4. **AI Processing**: Uses Genkit flows to analyze for security vulnerabilities
5. **Result Broadcasting**: Sends results via WebSocket to dashboard
6. **Storage**: Maintains in-memory report storage with statistics

### LLM Integration

The project supports two LLM provider modes:

- **Gemini Mode** (default): Uses Google's Genkit framework with Google AI models
- **Generic Mode**: Supports OpenAI-compatible APIs (including Ollama) with configurable formats

### Testing

- Tests are located alongside source files with `_test.go` suffix
- Main test suite: `internal/utils/url_normalizer_test.go` with comprehensive URL normalization tests
- Run tests with `go test ./...` or specific packages with `go test <package>`
- Tests include edge cases, context-aware normalization, and pattern matching

### Key Features

- Real-time traffic analysis and vulnerability detection
- Support for both HTTP and HTTPS traffic interception
- Burp Suite integration with automatic fallback
- Extracts and analyzes: secrets, API keys, JavaScript functions, form actions
- Maintains per-site context for improved analysis accuracy
- Modern web dashboard with live updates
- Configurable risk levels and vulnerability categorization
- Technology stack detection and hypothesis generation

## Environment Configuration

Copy `.env.example` to `.env` and configure:

- `LLM_PROVIDER`: Provider type ("gemini" or "generic")
- `API_KEY`: API key for the LLM provider
- `LLM_MODEL`: Model name to use
- `LLM_BASE_URL`: Base URL for generic providers
- `LLM_FORMAT`: Format for generic providers ("openai", "ollama", "raw")
- `PORT`: Proxy listen port
- `BURP_HOST`/`BURP_PORT`: Burp Suite integration settings

## Genkit Integration Notes

This project uses Firebase Genkit for AI-powered security analysis. When working with Genkit code:

- The main analysis flow is defined as `securityAnalysisFlow` in `internal/driven/analyzer.go`
- Use `genkit start -- go run cmd/main.go` to inspect flows in the Genkit Developer UI
- The project supports both structured data generation and simple text generation
- Analysis prompts are built dynamically based on extracted traffic data

## Development Notes

### Project Structure
- `cmd/` - Application entry points (main.go, api.go)
- `internal/config/` - Configuration management
- `internal/driven/` - Core security analysis and proxy logic
- `internal/llm/` - LLM provider implementations
- `internal/models/` - Data structures and DTOs
- `internal/utils/` - Utility functions and helpers
- `internal/websocket/` - WebSocket communication
- `internal/cert/` - Certificate management for HTTPS

### URL Normalization
The project includes sophisticated URL normalization that:
- Converts IDs to patterns (e.g., `/api/users/123` → `/api/users/{id}`)
- Handles UUIDs, usernames, slugs, and dates
- Maintains context-aware patterns for repeated analysis
- Preserves query parameters and handles edge cases

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