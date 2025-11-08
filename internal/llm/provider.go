package llm

import (
	"context"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// Provider - интерфейс для любого LLM провайдера
// Это простая абстракция, которая позволяет легко переключаться между разными моделями
type Provider interface {
	// GenerateSecurityAnalysis - основной метод для анализа безопасности
	// Принимает запрос, возвращает структурированный ответ
	GenerateSecurityAnalysis(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error)

	// GetName возвращает название провайдера (для логирования)
	GetName() string

	// GetModel возвращает используемую модель
	GetModel() string
}
