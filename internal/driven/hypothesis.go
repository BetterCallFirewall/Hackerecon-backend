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

	// Создаем запрос - даем LLM весь контекст для самостоятельного анализа
	hypothesisReq := &models.HypothesisRequest{
		SiteContext:         siteContext,
		SuspiciousPatterns:  suspiciousPatterns,
		TechVulnerabilities: techInfo,
		PreviousHypothesis:  nil, // Убрано из SiteContext
	}

	// Запускаем генерацию гипотезы
	ctx, cancel := context.WithTimeout(context.Background(), defaultAnalysisTimeout)
	defer cancel()

	resp, err := g.hypothesisFlow.Run(ctx, hypothesisReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
	}

	// Обновляем контекст с главной гипотезой (первый вектор или старый формат)
	var mainHypothesis *models.SecurityHypothesis
	if len(resp.AttackVectors) > 0 {
		mainHypothesis = resp.AttackVectors[0]
		resp.MainHypothesis = mainHypothesis // Для обратной совместимости
	} else if resp.Hypothesis != nil {
		// Старый формат (обратная совместимость)
		mainHypothesis = resp.Hypothesis
		resp.AttackVectors = []*models.SecurityHypothesis{resp.Hypothesis}
		resp.MainHypothesis = resp.Hypothesis
	}

	if mainHypothesis != nil {
		g.updateSiteContextWithHypothesis(siteContext, mainHypothesis)

		log.Printf(
			"🎯 Hypotheses generated for %s: %d vectors, main: %s (confidence: %.2f)",
			host, len(resp.AttackVectors), mainHypothesis.Title, mainHypothesis.Confidence,
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

// updateSiteContextWithHypothesis обновляет контекст с новой гипотезой
func (g *HypothesisGenerator) updateSiteContextWithHypothesis(
	siteContext *models.SiteContext,
	hypothesis *models.SecurityHypothesis,
) {
	// Просто логируем - гипотеза больше не хранится в SiteContext
	// (убрано MainHypothesis, LastHypothesisUpdate, LastUpdated)
}

// GetCurrent возвращает текущую гипотезу для хоста (устарело)
func (g *HypothesisGenerator) GetCurrent(host string) *models.SecurityHypothesis {
	// Гипотеза больше не хранится в SiteContext
	return nil
}

// GetAll возвращает все гипотезы для всех хостов (устарело)
func (g *HypothesisGenerator) GetAll() map[string]*models.SecurityHypothesis {
	// Гипотезы больше не хранятся в SiteContext
	return make(map[string]*models.SecurityHypothesis)
}
