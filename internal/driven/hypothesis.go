package driven

import (
	"context"
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	genkitcore "github.com/firebase/genkit/go/core"
)

// HypothesisGenerator генерирует гипотезы об уязвимостях
type HypothesisGenerator struct {
	hypothesisFlow *genkitcore.Flow[*models.HypothesisRequest, *models.HypothesisResponse, struct{}]
	wsHub          *websocket.WebsocketManager
	contextManager *SiteContextManager
}

// NewHypothesisGenerator создает новый генератор гипотез
func NewHypothesisGenerator(
	hypothesisFlow *genkitcore.Flow[*models.HypothesisRequest, *models.HypothesisResponse, struct{}],
	wsHub *websocket.WebsocketManager,
	contextManager *SiteContextManager,
) *HypothesisGenerator {
	return &HypothesisGenerator{
		hypothesisFlow: hypothesisFlow,
		wsHub:          wsHub,
		contextManager: contextManager,
	}
}

// GenerateForHost принудительно генерирует гипотезу для хоста
func (g *HypothesisGenerator) GenerateForHost(host string) (*models.HypothesisResponse, error) {
	siteContext := g.contextManager.Get(host)
	if siteContext == nil {
		return nil, fmt.Errorf("no context found for host: %s", host)
	}

	// Проверяем что есть достаточно данных
	if len(siteContext.URLPatterns) < minURLPatternsForHypothesis {
		return nil, fmt.Errorf(
			"insufficient data: only %d URL patterns discovered (need at least %d)",
			len(siteContext.URLPatterns), minURLPatternsForHypothesis,
		)
	}

	// Валидация качества данных
	if err := g.validateDataQuality(siteContext); err != nil {
		return nil, fmt.Errorf("data quality validation failed: %w", err)
	}

	// Собираем только подозрительные паттерны для подсветки LLM
	suspiciousPatterns := g.collectSuspiciousPatterns(siteContext)

	// Собираем информацию о технологиях
	techInfo := g.analyzeTechVulnerabilities(siteContext)

	// Собираем результаты верификации
	verificationSummary := g.buildVerificationSummary(siteContext)

	// Ищем кросс-эндпоинт паттерны
	crossEndpointPatterns := g.contextManager.FindCrossEndpointPatterns(siteContext.Host)

	// Создаем запрос - даем LLM весь контекст для самостоятельного анализа
	hypothesisReq := &models.HypothesisRequest{
		SiteContext:           siteContext,
		SuspiciousPatterns:    suspiciousPatterns,
		TechVulnerabilities:   techInfo,
		PreviousHypothesis:    nil, // Убрано из SiteContext
		VerificationResults:   verificationSummary,
		CrossEndpointPatterns: crossEndpointPatterns,
	}

	// Запускаем генерацию гипотезы
	ctx, cancel := context.WithTimeout(context.Background(), defaultAnalysisTimeout)
	defer cancel()

	resp, err := g.hypothesisFlow.Run(ctx, hypothesisReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
	}

	// Логируем результат генерации гипотез
	if len(resp.InvestigationSuggestions) > 0 {
		mainSuggestion := resp.InvestigationSuggestions[0]
		log.Printf(
			"🎯 Hypotheses generated for %s: %d suggestions, main: %s (priority: %s)",
			host, len(resp.InvestigationSuggestions), mainSuggestion.Title, mainSuggestion.Priority,
		)
	}

	return resp, nil
}

// collectSuspiciousPatterns собирает подозрительные паттерны для приоритизации
func (g *HypothesisGenerator) collectSuspiciousPatterns(siteContext *models.SiteContext) []*models.URLPattern {
	suspiciousPatterns := make([]*models.URLPattern, 0)

	for _, pattern := range siteContext.URLPatterns {
		// Берем последнюю заметку из массива
		if len(pattern.Notes) > 0 {
			lastNote := pattern.Notes[len(pattern.Notes)-1]
			if lastNote.Suspicious {
				suspiciousPatterns = append(suspiciousPatterns, pattern)
			}
		}
	}

	return suspiciousPatterns
}

// analyzeTechVulnerabilities собирает информацию о технологическом стеке
func (g *HypothesisGenerator) analyzeTechVulnerabilities(siteContext *models.SiteContext) []string {
	techInfo := make([]string, 0)

	if siteContext.TechStack == nil || len(siteContext.TechStack.Technologies) == 0 {
		return techInfo
	}

	// Собираем информацию о всех технологиях
	for _, tech := range siteContext.TechStack.Technologies {
		info := fmt.Sprintf("%s (confidence: %.2f) - %s", tech.Name, tech.Confidence, tech.Reason)
		techInfo = append(techInfo, info)
	}

	return techInfo
}

// validateDataQuality проверяет качество данных для генерации гипотезы
func (g *HypothesisGenerator) validateDataQuality(siteContext *models.SiteContext) error {
	highQualityNotes := 0
	totalNotes := 0

	for _, pattern := range siteContext.URLPatterns {
		// Берем последнюю заметку из массива
		if len(pattern.Notes) > 0 {
			lastNote := pattern.Notes[len(pattern.Notes)-1]
			totalNotes++
			if lastNote.Confidence >= 0.6 {
				highQualityNotes++
			}
		}
	}

	if totalNotes == 0 {
		return fmt.Errorf("no URL notes available")
	}

	qualityRatio := float64(highQualityNotes) / float64(totalNotes)
	if qualityRatio < 0.3 {
		return fmt.Errorf("insufficient data quality: only %.1f%% of notes have confidence >= 0.6", qualityRatio*100)
	}

	return nil
}

// buildVerificationSummary собирает информацию о результатах верификации
func (g *HypothesisGenerator) buildVerificationSummary(siteContext *models.SiteContext) *models.VerificationSummary {
	if len(siteContext.VerifiedPatterns) == 0 {
		return nil
	}

	summary := &models.VerificationSummary{
		TotalPatternsAnalyzed: len(siteContext.VerifiedPatterns),
		HighConfidenceMatches: make([]string, 0),
		RepeatingPatterns:     make([]string, 0),
	}

	// Подсчитаем результаты
	for _, verification := range siteContext.VerifiedPatterns {
		if verification.IsVulnerable && verification.Confidence > 0.7 {
			summary.ConfirmedVulnerable++
			if verification.Confidence > 0.85 {
				summary.HighConfidenceMatches = append(summary.HighConfidenceMatches, verification.Pattern)
			}
		} else if !verification.IsVulnerable && verification.Confidence > 0.7 {
			summary.ConfirmedSafe++
		} else {
			summary.Inconclusive++
		}

		// Если паттерн видели на нескольких эндпоинтах
		if verification.SeenCount >= 2 {
			summary.RepeatingPatterns = append(summary.RepeatingPatterns, verification.Pattern)
		}
	}

	log.Printf("📊 Verification Summary: %d analyzed, %d vulnerable, %d safe, %d inconclusive",
		summary.TotalPatternsAnalyzed, summary.ConfirmedVulnerable, summary.ConfirmedSafe, summary.Inconclusive)

	return summary
}
