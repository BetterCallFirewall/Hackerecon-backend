package driven

import (
	"context"
	"fmt"
	"log"
	"time"

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
		PreviousHypothesis:  siteContext.MainHypothesis,
	}

	// Запускаем генерацию гипотезы
	ctx, cancel := context.WithTimeout(context.Background(), defaultAnalysisTimeout)
	defer cancel()

	resp, err := g.hypothesisFlow.Run(ctx, hypothesisReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
	}

	// Обновляем контекст
	g.updateSiteContextWithHypothesis(siteContext, resp.Hypothesis)

	log.Printf(
		"🎯 Manual hypothesis generated for %s: %s (confidence: %.2f)",
		host, resp.Hypothesis.Title, resp.Hypothesis.Confidence,
	)

	return resp, nil
}

// collectSuspiciousPatterns собирает подозрительные паттерны для приоритизации
func (g *HypothesisGenerator) collectSuspiciousPatterns(siteContext *models.SiteContext) []*models.URLPattern {
	suspiciousPatterns := make([]*models.URLPattern, 0)

	for _, pattern := range siteContext.URLPatterns {
		if pattern.LastNote != nil && pattern.LastNote.Suspicious {
			suspiciousPatterns = append(suspiciousPatterns, pattern)
		}
	}

	return suspiciousPatterns
}

// analyzeTechVulnerabilities собирает информацию о технологическом стеке
func (g *HypothesisGenerator) analyzeTechVulnerabilities(siteContext *models.SiteContext) []string {
	techInfo := make([]string, 0)

	if siteContext.TechStack == nil {
		return techInfo
	}

	// Собираем информацию о Frontend технологиях
	for _, tech := range siteContext.TechStack.Frontend {
		info := g.formatTechInfo(tech, "Frontend")
		techInfo = append(techInfo, info)
	}

	// Собираем информацию о Backend технологиях
	for _, tech := range siteContext.TechStack.Backend {
		info := g.formatTechInfo(tech, "Backend")
		techInfo = append(techInfo, info)
	}

	// Собираем информацию о Database технологиях
	for _, tech := range siteContext.TechStack.Database {
		info := g.formatTechInfo(tech, "Database")
		techInfo = append(techInfo, info)
	}

	// Собираем информацию о Frameworks
	for _, tech := range siteContext.TechStack.Frameworks {
		info := g.formatTechInfo(tech, "Framework")
		techInfo = append(techInfo, info)
	}

	// Собираем информацию о Servers
	for _, tech := range siteContext.TechStack.Servers {
		info := g.formatTechInfo(tech, "Server")
		techInfo = append(techInfo, info)
	}

	return techInfo
}

// formatTechInfo форматирует информацию о технологии
func (g *HypothesisGenerator) formatTechInfo(tech models.Technology, category string) string {
	info := fmt.Sprintf("%s: %s", category, tech.Name)

	if tech.Version != "" {
		info += fmt.Sprintf(" (версия: %s)", tech.Version)
	}

	if tech.Confidence > 0 {
		info += fmt.Sprintf(" [уверенность: %.2f]", tech.Confidence)
	}

	return info
}

// validateDataQuality проверяет качество данных для генерации гипотезы
func (g *HypothesisGenerator) validateDataQuality(siteContext *models.SiteContext) error {
	highQualityNotes := 0
	totalNotes := 0

	for _, pattern := range siteContext.URLPatterns {
		if pattern.LastNote != nil {
			totalNotes++
			if pattern.LastNote.Confidence >= 0.6 {
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
	siteContext.MainHypothesis = hypothesis
	siteContext.LastHypothesisUpdate = time.Now()
	siteContext.LastUpdated = time.Now()
}

// GetCurrent возвращает текущую гипотезу для хоста
func (g *HypothesisGenerator) GetCurrent(host string) *models.SecurityHypothesis {
	siteContext := g.contextManager.Get(host)
	if siteContext == nil {
		return nil
	}
	return siteContext.MainHypothesis
}

// GetAll возвращает все гипотезы для всех хостов
func (g *HypothesisGenerator) GetAll() map[string]*models.SecurityHypothesis {
	result := make(map[string]*models.SecurityHypothesis)

	contexts := g.contextManager.GetAll()
	for host, context := range contexts {
		if context.MainHypothesis != nil {
			result[host] = context.MainHypothesis
		}
	}

	return result
}
