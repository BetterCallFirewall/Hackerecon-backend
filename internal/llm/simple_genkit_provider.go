package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/compat_oai"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

// SimpleGenkitProvider - минимальный универсальный провайдер для всех LLM через Genkit
type SimpleGenkitProvider struct {
	genkitApp *genkit.Genkit
	modelName string
}

// NewSimpleProvider создает универсальный провайдер с уже инициализированным GenkitApp
func NewSimpleProvider(genkitApp *genkit.Genkit, cfg config.LLMConfig) (*SimpleGenkitProvider, error) {
	if genkitApp == nil {
		return nil, fmt.Errorf("genkitApp cannot be nil")
	}

	// Формируем универсальное имя модели
	modelName := cfg.Provider + "/" + cfg.Model

	return &SimpleGenkitProvider{
		genkitApp: genkitApp,
		modelName: modelName,
	}, nil
}

// InitGenkitApp создает и инициализирует Genkit с нужными плагинами
func InitGenkitApp(ctx context.Context, cfg config.LLMConfig) (*genkit.Genkit, error) {
	switch cfg.Provider {
	case "gemini":
		return genkit.Init(
			ctx, genkit.WithPlugins(
				&googlegenai.GoogleAI{
					APIKey: cfg.ApiKey,
				},
			),
		), nil

	case "openai", "ollama", "localai", "lm-studio":
		return genkit.Init(
			ctx, genkit.WithPlugins(
				&compat_oai.OpenAICompatible{
					Provider: cfg.Provider,
					APIKey:   cfg.ApiKey,
					BaseURL:  cfg.BaseURL,
				},
			),
		), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
}

// getMiddlewares возвращает стандартный middleware stack для всех LLM запросов
func getMiddlewares() []ai.ModelMiddleware {
	return []ai.ModelMiddleware{
		RetryMiddleware(3, 1*time.Second), // 3 попытки с exponential backoff: 1s → 2s → 4s
	}
}

// GenerateSecurityAnalysis выполняет анализ безопасности
func (p *SimpleGenkitProvider) GenerateSecurityAnalysis(
	ctx context.Context,
	req *models.SecurityAnalysisRequest,
) (*models.SecurityAnalysisResponse, error) {
	prompt := BuildSecurityAnalysisPrompt(req)

	result, _, err := genkit.GenerateData[models.SecurityAnalysisResponse](
		ctx,
		p.genkitApp,
		ai.WithModelName(p.modelName),
		ai.WithPrompt(prompt),
		ai.WithMiddleware(getMiddlewares()...),
	)

	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	return result, nil
}

// GenerateURLAnalysis выполняет быструю оценку URL
func (p *SimpleGenkitProvider) GenerateURLAnalysis(
	ctx context.Context,
	req *models.URLAnalysisRequest,
) (*models.URLAnalysisResponse, error) {
	prompt := BuildURLAnalysisPrompt(req)

	result, _, err := genkit.GenerateData[models.URLAnalysisResponse](
		ctx,
		p.genkitApp,
		ai.WithModelName(p.modelName),
		ai.WithPrompt(prompt),
		ai.WithMiddleware(getMiddlewares()...),
	)

	if err != nil {
		return nil, fmt.Errorf("URL analysis failed: %w", err)
	}

	return result, nil
}

// GenerateHypothesis выполняет генерацию гипотез
func (p *SimpleGenkitProvider) GenerateHypothesis(
	ctx context.Context,
	req *models.HypothesisRequest,
) (*models.HypothesisResponse, error) {
	prompt := BuildHypothesisPrompt(req)

	result, _, err := genkit.GenerateData[models.HypothesisResponse](
		ctx,
		p.genkitApp,
		ai.WithModelName(p.modelName),
		ai.WithPrompt(prompt),
		ai.WithMiddleware(getMiddlewares()...),
	)

	if err != nil {
		return nil, fmt.Errorf("hypothesis generation failed: %w", err)
	}

	return result, nil
}

// GenerateVerificationPlan генерирует план верификации гипотезы
func (p *SimpleGenkitProvider) GenerateVerificationPlan(
	ctx context.Context,
	req *models.VerificationPlanRequest,
) (*models.VerificationPlanResponse, error) {
	prompt := BuildVerificationPlanPrompt(req)

	result, _, err := genkit.GenerateData[models.VerificationPlanResponse](
		ctx,
		p.genkitApp,
		ai.WithModelName(p.modelName),
		ai.WithPrompt(prompt),
		ai.WithMiddleware(getMiddlewares()...),
	)

	if err != nil {
		return nil, fmt.Errorf("verification plan generation failed: %w", err)
	}

	return result, nil
}

// AnalyzeVerificationResults анализирует результаты верификации
func (p *SimpleGenkitProvider) AnalyzeVerificationResults(
	ctx context.Context,
	req *models.VerificationAnalysisRequest,
) (*models.VerificationAnalysisResponse, error) {
	prompt := BuildVerificationAnalysisPrompt(req)

	result, _, err := genkit.GenerateData[models.VerificationAnalysisResponse](
		ctx,
		p.genkitApp,
		ai.WithModelName(p.modelName),
		ai.WithPrompt(prompt),
		ai.WithMiddleware(getMiddlewares()...),
	)

	if err != nil {
		return nil, fmt.Errorf("verification analysis failed: %w", err)
	}

	return result, nil
}
