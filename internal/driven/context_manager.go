package driven

import (
	"fmt"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// SiteContextManager управляет контекстами сайтов
type SiteContextManager struct {
	contexts map[string]*models.SiteContext
	mutex    sync.RWMutex
}

// NewSiteContextManager создает новый менеджер контекстов
func NewSiteContextManager() *SiteContextManager {
	return &SiteContextManager{
		contexts: make(map[string]*models.SiteContext),
	}
}

// GetOrCreate получает или создает контекст для хоста
func (m *SiteContextManager) GetOrCreate(host string) *models.SiteContext {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if context, exists := m.contexts[host]; exists {
		return context
	}

	newContext := models.NewSiteContext(host)
	m.contexts[host] = newContext
	return newContext
}

// Get возвращает контекст для хоста
func (m *SiteContextManager) Get(host string) *models.SiteContext {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.contexts[host]
}

// UpdateFromAnalysis обновляет контекст на основе ответа от LLM
func (m *SiteContextManager) UpdateFromAnalysis(
	host string,
	url string,
	llmResponse *models.SecurityAnalysisResponse,
) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	context, exists := m.contexts[host]
	if !exists {
		return
	}

	context.LastUpdated = time.Now()
}

// UpdateURLPattern обновляет паттерн URL с новой заметкой
func (m *SiteContextManager) UpdateURLPattern(
	siteContext *models.SiteContext,
	normalizedURL, method string,
	urlNote *models.URLNote,
) {
	patternKey := fmt.Sprintf("%s:%s", method, normalizedURL)

	var urlPattern *models.URLPattern
	if existing, exists := siteContext.URLPatterns[patternKey]; exists {
		urlPattern = existing
		urlPattern.LastSeen = time.Now()
		urlPattern.AccessCount++
		urlPattern.LastNote = urlNote

		// Ограничиваем размер Notes, храним только последние 100 заметок
		const maxNotes = 100
		if len(urlPattern.Notes) >= maxNotes {
			// Удаляем самую старую заметку
			urlPattern.Notes = urlPattern.Notes[1:]
		}
		urlPattern.Notes = append(urlPattern.Notes, *urlNote)
	} else {
		urlPattern = &models.URLPattern{
			Pattern:   normalizedURL,
			Method:    method,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			LastNote:  urlNote,
			Notes:     []models.URLNote{*urlNote},
		}
		siteContext.URLPatterns[patternKey] = urlPattern
	}

	// Обновляем purpose если есть в заметке
	if urlNote.Content != "" {
		urlPattern.Purpose = urlNote.Content
	}

	siteContext.LastUpdated = time.Now()
}

// GetAll возвращает все контексты сайтов
func (m *SiteContextManager) GetAll() map[string]*models.SiteContext {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*models.SiteContext, len(m.contexts))
	for host, context := range m.contexts {
		result[host] = context
	}

	return result
}
