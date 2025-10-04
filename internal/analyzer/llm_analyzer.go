package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
)

type LLMAnalyzer struct {
	config     *config.Config
	httpClient *http.Client
}

type LLMRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type LLMResponse struct {
	Response string `json:"response"`
}

func NewLLMAnalyzer(cfg *config.Config) *LLMAnalyzer {
	return &LLMAnalyzer{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (a *LLMAnalyzer) Analyze(req *storage.RequestData, resp *storage.ResponseData) (*storage.AnalysisResult, error) {
	// Формируем промпт для анализа
	prompt := a.buildPrompt(req, resp)

	// Отправляем запрос к LLM
	llmReq := LLMRequest{
		Model:  a.config.LLM.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(llmReq)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", a.config.LLM.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var llmResp LLMResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&llmResp); err != nil {
		return nil, err
	}

	// Парсим результат анализа
	return a.parseAnalysisResult(llmResp.Response)
}

func (a *LLMAnalyzer) buildPrompt(req *storage.RequestData, resp *storage.ResponseData) string {
	systemPrompt := `Ты - эксперт по веб-безопасности. Анализируй HTTP трафик и выявляй потенциальные уязвимости.

АНАЛИЗИРУЙ НА ПРЕДМЕТ:
1. SQL injection (в параметрах, заголовках, cookies)
2. XSS (reflected, stored)
3. Проблемы аутентификации (слабые токены, session fixation)
4. CSRF уязвимости
5. Небезопасные HTTP заголовки
6. Утечки информации

ФОРМАТ ОТВЕТА (только JSON):
{
  "vulnerabilities_found": true/false,
  "findings": [
    {
      "type": "тип уязвимости",
      "severity": "High/Medium/Low", 
      "location": "где найдено",
      "description": "краткое описание",
      "recommendation": "как исправить"
    }
  ],
  "overall_risk": "High/Medium/Low",
  "pentester_actions": ["список рекомендуемых действий для пентестера"]
}`

	userPrompt := fmt.Sprintf(`Проанализируй HTTP запрос:

URL: %s
Method: %s
Headers: %v
Body: %s
Response Status: %d
Response Headers: %v
Response Body: %s

Найди все потенциальные уязвимости и дай рекомендации для пентестера.`,
		req.URL, req.Method, req.Headers, req.Body,
		resp.Status, resp.Headers, resp.Body)

	return systemPrompt + "\n\n" + userPrompt
}

func (a *LLMAnalyzer) parseAnalysisResult(response string) (*storage.AnalysisResult, error) {
	// Простой парсинг JSON ответа от LLM
	var result storage.AnalysisResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		// Если не удалось распарсить JSON, создаем базовый результат
		return &storage.AnalysisResult{
			VulnerabilitiesFound: false,
			Findings:            []storage.VulnerabilityFinding{},
			OverallRisk:         "Low",
			PentesterActions:    []string{"Review raw response: " + response},
		}, nil
	}

	return &result, nil
}