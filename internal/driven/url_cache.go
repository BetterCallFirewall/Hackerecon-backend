package driven

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// URLAnalysisCache кэш для результатов Quick URL Analysis
type URLAnalysisCache struct {
	mu      sync.RWMutex
	cache   map[string]*cacheEntry
	maxSize int
}

type cacheEntry struct {
	result    *models.URLAnalysisResponse
	timestamp time.Time
	hits      int
}

// NewURLAnalysisCache создает новый кэш
func NewURLAnalysisCache(maxSize int) *URLAnalysisCache {
	return &URLAnalysisCache{
		cache:   make(map[string]*cacheEntry, maxSize),
		maxSize: maxSize,
	}
}

// Get получает результат из кэша
func (c *URLAnalysisCache) Get(pattern string) (*models.URLAnalysisResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[pattern]
	if !ok {
		return nil, false
	}

	// Проверяем TTL (5 минут)
	if time.Since(entry.timestamp) > 5*time.Minute {
		return nil, false
	}

	// FIXED: increment hits under write lock to prevent race condition
	entry.hits++
	return entry.result, true
}

// Set сохраняет результат в кэш
func (c *URLAnalysisCache) Set(pattern string, result *models.URLAnalysisResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Если кэш переполнен, удаляем самую старую запись
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[pattern] = &cacheEntry{
		result:    result,
		timestamp: time.Now(),
		hits:      0,
	}
}

// evictOldest удаляет самую старую запись из кэша
func (c *URLAnalysisCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.cache {
		if oldestKey == "" || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// Stats возвращает статистику кэша
func (c *URLAnalysisCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalHits := 0
	for _, entry := range c.cache {
		totalHits += entry.hits
	}

	return map[string]interface{}{
		"size":       len(c.cache),
		"max_size":   c.maxSize,
		"total_hits": totalHits,
	}
}

// Pre-compiled regex patterns for URL normalization (OPTIMIZATION: compile once, use many times)
var (
	uuidPattern      = regexp.MustCompile(`/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	hashPattern      = regexp.MustCompile(`/[0-9a-fA-F]{32,}`)
	objectIdPattern  = regexp.MustCompile(`/[0-9a-fA-F]{24}`)
	numericIDPattern = regexp.MustCompile(`/\d+`)
)

// normalizeURLPattern нормализует URL для кэширования
// /api/users/123 → /api/users/{id}
// /api/orders/456/items/789 → /api/orders/{id}/items/{id}
func normalizeURLPattern(url string) string {
	// Удаляем query параметры
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}

	// Применяем паттерны от более специфичных к менее специфичным
	// чтобы избежать неправильных замен
	// OPTIMIZATION: Use pre-compiled patterns

	// 1. Заменяем UUID на {uuid} (самый специфичный)
	url = uuidPattern.ReplaceAllString(url, "/{uuid}")

	// 2. Заменяем длинные хеши (32+ hex) на {hash}
	url = hashPattern.ReplaceAllString(url, "/{hash}")

	// 3. Заменяем MongoDB ObjectId (24 hex) на {objectid}
	url = objectIdPattern.ReplaceAllString(url, "/{objectid}")

	// 4. Заменяем числовые ID на {id} (самый общий, применяем последним)
	url = numericIDPattern.ReplaceAllString(url, "/{id}")

	return url
}
