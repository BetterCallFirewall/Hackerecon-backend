// internal/analyzer/streaming.go
package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
)

type StreamingAnalyzer struct {
	client     *http.Client
	config     *StreamingConfig
	resultChan chan *PartialResult
}

type StreamingConfig struct {
	URL   string
	Model string
}

type PartialResult struct {
	RequestID string      `json:"request_id"`
	Chunk     string      `json:"chunk"`
	Complete  bool        `json:"complete"`
	Analysis  interface{} `json:"analysis,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type OllamaStreamRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaStreamResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func NewStreamingAnalyzer(config *StreamingConfig) *StreamingAnalyzer {
	return &StreamingAnalyzer{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config:     config,
		resultChan: make(chan *PartialResult, 100),
	}
}

func (sa *StreamingAnalyzer) AnalyzeStreaming(ctx context.Context, requestID string, prompt string) (<-chan *PartialResult, error) {
	resultChan := make(chan *PartialResult, 10)

	go func() {
		defer close(resultChan)

		if err := sa.streamAnalysis(ctx, requestID, prompt, resultChan); err != nil {
			resultChan <- &PartialResult{
				RequestID: requestID,
				Error:     err.Error(),
				Complete:  true,
			}
		}
	}()

	return resultChan, nil
}

func (sa *StreamingAnalyzer) streamAnalysis(ctx context.Context, requestID string, prompt string, resultChan chan<- *PartialResult) error {
	reqBody := OllamaStreamRequest{
		Model:  sa.config.Model,
		Prompt: prompt,
		Stream: true,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", sa.config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sa.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var fullResponse strings.Builder
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		var streamResp OllamaStreamResponse
		if err := json.Unmarshal([]byte(line), &streamResp); err != nil {
			continue // Пропускаем невалидные строки
		}

		fullResponse.WriteString(streamResp.Response)

		// Отправляем частичный результат
		resultChan <- &PartialResult{
			RequestID: requestID,
			Chunk:     streamResp.Response,
			Complete:  streamResp.Done,
		}

		if streamResp.Done {
			// Парсим финальный результат
			analysis, err := sa.parseAnalysis(fullResponse.String())
			if err != nil {
				resultChan <- &PartialResult{
					RequestID: requestID,
					Error:     err.Error(),
					Complete:  true,
				}
				return err
			}

			resultChan <- &PartialResult{
				RequestID: requestID,
				Analysis:  analysis,
				Complete:  true,
			}
			break
		}
	}

	return scanner.Err()
}

func (sa *StreamingAnalyzer) parseAnalysis(response string) (*storage.AnalysisResult, error) {
	// Ищем JSON в ответе LLM
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")

	if start == -1 || end == -1 || start >= end {
		return &storage.AnalysisResult{
			VulnerabilitiesFound: false,
			OverallRisk:         "Low",
			PentesterActions:    []string{"Could not parse LLM response: " + response[:100]},
		}, nil
	}

	jsonStr := response[start : end+1]
	var result storage.AnalysisResult

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return &storage.AnalysisResult{
			VulnerabilitiesFound: false,
			OverallRisk:         "Low",
			PentesterActions:    []string{"JSON parse error: " + err.Error()},
		}, nil
	}

	return &result, nil
}