package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// GenericProvider - универсальный провайдер для любого HTTP API
// Поддерживает разные форматы запросов (OpenAI-compatible, Ollama, и т.д.)
type GenericProvider struct {
	client  *http.Client
	name    string
	model   string // Название модели
	baseURL string
	apiKey  string // Опциональный
	format  APIFormat
}

// APIFormat определяет формат API
type APIFormat string

const (
	// FormatOpenAI - OpenAI compatible API (LocalAI, LM Studio, vLLM с OpenAI endpoint, etc.)
	FormatOpenAI APIFormat = "openai"

	// FormatOllama - Ollama API
	FormatOllama APIFormat = "ollama"

	// FormatRaw - простой JSON {"prompt": "...", "temperature": ...}
	FormatRaw APIFormat = "raw"
)

// GenericConfig - конфигурация для Generic провайдера
type GenericConfig struct {
	Name    string    // Название провайдера (для логирования)
	Model   string    // Название модели
	BaseURL string    // Базовый URL (например, "http://localhost:11434")
	APIKey  string    // API ключ (опционально)
	Format  APIFormat // Формат API
}

// NewGenericProvider создаёт новый универсальный HTTP провайдер
func NewGenericProvider(cfg GenericConfig) *GenericProvider {
	// Дефолтные значения
	if cfg.Name == "" {
		cfg.Name = "generic"
	}
	if cfg.Format == "" {
		cfg.Format = FormatOpenAI // По умолчанию OpenAI-compatible
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-3.5-turbo" // Дефолтная модель для OpenAI-compatible
	}

	return &GenericProvider{
		client: &http.Client{
			Timeout: 2 * time.Minute, // Локальные модели могут быть медленными
		},
		name:    cfg.Name,
		model:   cfg.Model,
		baseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		format:  cfg.Format,
	}
}

// GenerateSecurityAnalysis выполняет анализ через HTTP API
func (p *GenericProvider) GenerateSecurityAnalysis(
	ctx context.Context,
	req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	// Строим промпт
	prompt := BuildSecurityAnalysisPrompt(req)

	// Формируем HTTP запрос в зависимости от формата API
	httpReq, err := p.buildHTTPRequest(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Отправляем запрос
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Проверяем статус код
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", httpResp.StatusCode, string(body))
	}

	// Парсим ответ в зависимости от формата
	content, err := p.parseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Очищаем JSON от возможного markdown
	content = cleanJSONResponse(content)

	// Парсим JSON в нашу структуру
	var result models.SecurityAnalysisResponse
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w\nContent: %s", err, content)
	}

	// Инициализируем пустые массивы если null
	if result.VulnerabilityTypes == nil {
		result.VulnerabilityTypes = []string{}
	}
	if result.ExtractedSecrets == nil {
		result.ExtractedSecrets = []models.ExtractedSecret{}
	}
	if result.SecurityChecklist == nil {
		result.SecurityChecklist = []models.SecurityCheckItem{}
	}
	if result.Recommendations == nil {
		result.Recommendations = []string{}
	}
	if result.IdentifiedDataObjects == nil {
		result.IdentifiedDataObjects = []models.DataObject{}
	}

	// Устанавливаем дополнительные поля
	result.Timestamp = time.Now()
	result.URL = req.URL
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.APIKeys...)
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.Secrets...)

	return &result, nil
}

// buildHTTPRequest создаёт HTTP запрос в зависимости от формата API
func (p *GenericProvider) buildHTTPRequest(ctx context.Context, prompt string) (*http.Request, error) {
	var requestBody interface{}
	var endpoint string

	switch p.format {
	case FormatOpenAI:
		// OpenAI-compatible формат
		endpoint = p.baseURL + "/chat/completions"
		requestBody = map[string]interface{}{
			"model": p.model, // Используем модель из конфигурации
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
			"temperature": 0.2,
			"max_tokens":  2000,
			"response_format": map[string]string{
				"type": "json_object", // Просим JSON
			},
		}

	case FormatOllama:
		// Ollama формат
		endpoint = p.baseURL + "/api/generate"
		requestBody = map[string]interface{}{
			"model":  p.model, // Используем модель из конфигурации
			"prompt": prompt,
			"format": "json", // Ollama JSON mode
			"stream": false,
			"options": map[string]interface{}{
				"temperature": 0.2,
				"num_predict": 2000,
			},
		}

	case FormatRaw:
		// Простой формат
		endpoint = p.baseURL
		requestBody = map[string]interface{}{
			"prompt":      prompt,
			"temperature": 0.2,
			"max_tokens":  2000,
		}

	default:
		return nil, fmt.Errorf("unsupported API format: %s", p.format)
	}

	// Сериализуем в JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Создаём HTTP запрос
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/json")

	if p.apiKey != "" {
		// OpenAI-style Authorization
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	return req, nil
}

// parseResponse парсит ответ в зависимости от формата API
func (p *GenericProvider) parseResponse(body []byte) (string, error) {
	switch p.format {
	case FormatOpenAI:
		// OpenAI возвращает: {"choices": [{"message": {"content": "..."}}]}
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse OpenAI response: %w", err)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("no choices in response")
		}
		return resp.Choices[0].Message.Content, nil

	case FormatOllama:
		// Ollama возвращает: {"response": "..."}
		var resp struct {
			Response string `json:"response"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse Ollama response: %w", err)
		}
		return resp.Response, nil

	case FormatRaw:
		// Пробуем несколько вариантов
		// Вариант 1: {"text": "..."}
		var resp1 struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(body, &resp1); err == nil && resp1.Text != "" {
			return resp1.Text, nil
		}

		// Вариант 2: {"response": "..."}
		var resp2 struct {
			Response string `json:"response"`
		}
		if err := json.Unmarshal(body, &resp2); err == nil && resp2.Response != "" {
			return resp2.Response, nil
		}

		// Вариант 3: {"content": "..."}
		var resp3 struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(body, &resp3); err == nil && resp3.Content != "" {
			return resp3.Content, nil
		}

		return "", fmt.Errorf("unknown response format: %s", string(body))

	default:
		return "", fmt.Errorf("unsupported format: %s", p.format)
	}
}

func (p *GenericProvider) GetName() string {
	return p.name
}

func (p *GenericProvider) GetModel() string {
	return p.model
}

// cleanJSONResponse очищает ответ от markdown и лишних символов
func cleanJSONResponse(content string) string {
	// Убираем markdown code blocks
	content = strings.TrimPrefix(content, "```json\n")
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```\n")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "\n```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Ищем первый { и последний }
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")

	if start >= 0 && end > start {
		return content[start : end+1]
	}

	return content
}
