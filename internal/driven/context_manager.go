package driven

import (
	"fmt"
	"sync"

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

// UpdateURLPattern обновляет паттерн URL с новой заметкой
func (m *SiteContextManager) UpdateURLPattern(
	siteContext *models.SiteContext,
	url, method string,
	urlNote *models.URLNote,
) {
	patternKey := fmt.Sprintf("%s:%s", method, url)

	var urlPattern *models.URLPattern
	if existing, exists := siteContext.URLPatterns[patternKey]; exists {
		urlPattern = existing

		// Ограничиваем размер Notes, храним только последние 100 заметок
		const maxNotes = 100
		if len(urlPattern.Notes) >= maxNotes {
			// Удаляем самую старую заметку
			urlPattern.Notes = urlPattern.Notes[1:]
		}
		urlPattern.Notes = append(urlPattern.Notes, *urlNote)
	} else {
		urlPattern = &models.URLPattern{
			Pattern: url,
			Method:  method,
			Notes:   []models.URLNote{*urlNote},
		}
		siteContext.URLPatterns[patternKey] = urlPattern
	}

	// Обновляем purpose если есть в заметке
	if urlNote.Content != "" {
		urlPattern.Purpose = urlNote.Content
	}
}
