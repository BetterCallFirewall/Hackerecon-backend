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

	// GenerateURLAnalysis - быстрая оценка значимости URL
	// Используется для оптимизации нагрузки на LLM
	GenerateURLAnalysis(ctx context.Context, req *models.URLAnalysisRequest) (*models.URLAnalysisResponse, error)

	// GenerateHypothesis - генерация главной гипотезы об уязвимости
	// Анализирует накопленную информацию о сайте
	GenerateHypothesis(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error)
}
