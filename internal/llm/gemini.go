package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// GeminiProvider - провайдер для Google Gemini через Genkit
type GeminiProvider struct {
	genkitApp *genkit.Genkit
	model     string
}

// NewGeminiProvider создаёт новый Gemini провайдер
func NewGeminiProvider(genkitApp *genkit.Genkit, model string) *GeminiProvider {
	return &GeminiProvider{
		genkitApp: genkitApp,
		model:     model,
	}
}

// GenerateSecurityAnalysis выполняет анализ безопасности через Genkit
func (p *GeminiProvider) GenerateSecurityAnalysis(
	ctx context.Context,
	req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	// Строим промпт для анализа
	prompt := p.buildPrompt(req)

	// Используем Genkit для генерации структурированного ответа
	// Genkit автоматически валидирует JSON schema через generic type
	result, _, err := genkit.GenerateData[models.SecurityAnalysisResponse](
		ctx,
		p.genkitApp,
		ai.WithPrompt(prompt),
	)

	if err != nil {
		return nil, fmt.Errorf("gemini generation failed: %w", err)
	}

	// Устанавливаем timestamp и URL
	result.Timestamp = time.Now()

	// Дополняем результат извлеченными секретами
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.APIKeys...)
	result.ExtractedSecrets = append(result.ExtractedSecrets, req.ExtractedData.Secrets...)

	return result, nil
}

// buildPrompt создаёт детальный промпт для анализа безопасности
func (p *GeminiProvider) buildPrompt(req *models.SecurityAnalysisRequest) string {
	// Используем helper функцию из другого пакета
	return BuildSecurityAnalysisPrompt(req)
}

// GenerateURLAnalysis выполняет быструю оценку URL через Genkit
func (p *GeminiProvider) GenerateURLAnalysis(
	ctx context.Context,
	req *models.URLAnalysisRequest,
) (*models.URLAnalysisResponse, error) {
	// Строим промпт для быстрой оценки
	prompt := BuildURLAnalysisPrompt(req)

	// Используем Genkit для генерации структурированного ответа
	result, _, err := genkit.GenerateData[models.URLAnalysisResponse](
		ctx,
		p.genkitApp,
		ai.WithPrompt(prompt),
	)

	if err != nil {
		return nil, fmt.Errorf("gemini URL analysis failed: %w", err)
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

	return result, nil
}

// GenerateHypothesis выполняет генерацию гипотезы через Genkit
func (p *GeminiProvider) GenerateHypothesis(
	ctx context.Context,
	req *models.HypothesisRequest,
) (*models.HypothesisResponse, error) {
	// Строим промпт для генерации гипотезы
	prompt := BuildHypothesisPrompt(req)

	// Используем Genkit для генерации структурированного ответа
	result, _, err := genkit.GenerateData[models.HypothesisResponse](
		ctx,
		p.genkitApp,
		ai.WithPrompt(prompt),
	)

	if err != nil {
		return nil, fmt.Errorf("gemini hypothesis generation failed: %w", err)
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

	return result, nil
}

func (p *GeminiProvider) GetName() string {
	return "gemini"
}

func (p *GeminiProvider) GetModel() string {
	return p.model
}
