package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	// Нормализуем JSON: экранируем только неэкранированные спецсимволы
	content = normalizeJSONString(content)

	// Парсим JSON в нашу структуру
	var result models.SecurityAnalysisResponse

	// Используем Decoder для более мягкого парсинга
	decoder := json.NewDecoder(strings.NewReader(content))
	if err := decoder.Decode(&result); err != nil {
		// Если не получилось, пробуем через map для диагностики
		var rawMap map[string]interface{}
		if err2 := json.Unmarshal([]byte(content), &rawMap); err2 == nil {
			// JSON валидный, но не соответствует структуре
			log.Printf("⚠️ JSON валидный, но проблема со структурой: %v", err)
			log.Printf("📄 Parsed keys: %v", getMapKeys(rawMap))
		} else {
			// JSON невалидный
			log.Printf("❌ JSON Parse Error: %v", err)
			log.Printf("📄 Content (first 500 chars): %s", TruncateString(content, 500))
		}
		return nil, fmt.Errorf("invalid JSON response: %w", err)
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

	// Нормализуем risk_level к lowercase (на случай если LLM вернул "Low" вместо "low")
	result.RiskLevel = strings.ToLower(strings.TrimSpace(result.RiskLevel))

	// Валидируем risk_level
	validRiskLevels := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validRiskLevels[result.RiskLevel] {
		fmt.Printf("⚠️ Невалидный risk_level '%s', устанавливаем 'low'\n", result.RiskLevel)
		result.RiskLevel = "low"
	}

	// Автоматически устанавливаем has_vulnerability на основе risk_level
	// Если risk_level не "low", значит есть уязвимость
	if result.RiskLevel == "medium" || result.RiskLevel == "high" || result.RiskLevel == "critical" {
		result.HasVulnerability = true
	}

	// Также проверяем наличие списка уязвимостей
	if len(result.VulnerabilityTypes) > 0 {
		result.HasVulnerability = true
	}

	// Устанавливаем дополнительные поля
	result.Timestamp = time.Now()
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

// GenerateURLAnalysis выполняет быструю оценку URL через HTTP API
func (p *GenericProvider) GenerateURLAnalysis(
	ctx context.Context,
	req *models.URLAnalysisRequest,
) (*models.URLAnalysisResponse, error) {
	// Строим промпт
	prompt := BuildURLAnalysisPrompt(req)

	// Формируем HTTP запрос
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

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", httpResp.StatusCode, string(body))
	}

	// Парсим ответ
	content, err := p.parseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Очищаем JSON
	content = cleanJSONResponse(content)

	// Парсим в структуру
	var result models.URLAnalysisResponse
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w\nContent: %s", err, content)
	}

	// Валидация
	if result.URLNote == nil {
		result.URLNote = &models.URLNote{
			Content:    "Analysis completed",
			Suspicious: false,
			Confidence: 0.5,
		}
	}
	result.URLNote.Timestamp = time.Now()

	return &result, nil
}

// GenerateHypothesis выполняет генерацию гипотезы через HTTP API
func (p *GenericProvider) GenerateHypothesis(
	ctx context.Context,
	req *models.HypothesisRequest,
) (*models.HypothesisResponse, error) {
	// Строим промпт
	prompt := BuildHypothesisPrompt(req)

	// Формируем HTTP запрос
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

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", httpResp.StatusCode, string(body))
	}

	// Парсим ответ
	content, err := p.parseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Очищаем JSON
	content = cleanJSONResponse(content)

	// Парсим в структуру
	var result models.HypothesisResponse
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w\nContent: %s", err, content)
	}

	// Валидация
	if result.Hypothesis != nil {
		now := time.Now()
		if result.Hypothesis.CreatedAt.IsZero() {
			result.Hypothesis.CreatedAt = now
		}
		if result.Hypothesis.UpdatedAt.IsZero() {
			result.Hypothesis.UpdatedAt = now
		}
		if result.Hypothesis.ID == "" {
			result.Hypothesis.ID = fmt.Sprintf("%d", time.Now().Unix())
		}
	}

	return &result, nil
}

func (p *GenericProvider) GetName() string {
	return p.name
}

func (p *GenericProvider) GetModel() string {
	return p.model
}

// getMapKeys возвращает ключи map для диагностики
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// normalizeJSONString экранирует неэкранированные спецсимволы в JSON
func normalizeJSONString(content string) string {
	// Используем json.Marshal для безопасного экранирования строк
	// Но сначала нужно извлечь строковые значения и обработать их

	var result strings.Builder
	result.Grow(len(content) + len(content)/10)

	inString := false
	escaped := false

	for i := 0; i < len(content); i++ {
		ch := content[i]

		// Обрабатываем экранирование
		if escaped {
			result.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			result.WriteByte(ch)
			escaped = true
			continue
		}

		// Переключаем режим строки при встрече "
		if ch == '"' {
			inString = !inString
			result.WriteByte(ch)
			continue
		}

		// Внутри строки обрабатываем спецсимволы
		if inString {
			switch ch {
			case '\n':
				result.WriteString("\\n")
			case '\r':
				result.WriteString("\\r")
			case '\t':
				result.WriteString("\\t")
			case '\b':
				result.WriteString("\\b")
			case '\f':
				result.WriteString("\\f")
			default:
				// Для остальных символов проверяем, не нужно ли экранирование
				if ch < 0x20 {
					// Управляющие символы экранируем как \uXXXX
					result.WriteString(fmt.Sprintf("\\u%04x", ch))
				} else {
					result.WriteByte(ch)
				}
			}
		} else {
			result.WriteByte(ch)
		}
	}

	return result.String()
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
