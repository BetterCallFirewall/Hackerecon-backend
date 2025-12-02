package driven

import (
	"log"
	"sort"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// CachedAnalysis представляет кэшированный результат анализа
type CachedAnalysis struct {
	URLPattern     string
	LastAnalyzed   time.Time
	AnalysisResult *models.URLAnalysisResponse
	AccessCount    int
	Confidence     float64
}

// AnalysisCache управляет кэшированием результатов анализа URL
type AnalysisCache struct {
	cache  map[string]*CachedAnalysis
	mutex  sync.RWMutex
	expiry time.Duration
}

// NewAnalysisCache создает новый кэш анализа
func NewAnalysisCache() *AnalysisCache {
	return &AnalysisCache{
		cache:  make(map[string]*CachedAnalysis),
		expiry: defaultCacheExpiry,
	}
}

// Get возвращает кэшированный результат анализа
func (c *AnalysisCache) Get(cacheKey string) *CachedAnalysis {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cached, exists := c.cache[cacheKey]; exists {
		// Проверяем не устарел ли кэш
		if time.Since(cached.LastAnalyzed) < c.expiry {
			return cached
		}
	}

	return nil
}

// CheckAndDecide проверяет кэш и решает, нужно ли пропустить анализ
func (c *AnalysisCache) CheckAndDecide(cacheKey string) bool {
	cached := c.Get(cacheKey)
	if cached == nil {
		log.Printf("🆕 Новый паттерн: %s", cacheKey)
		return false
	}

	// Обновляем статистику кэша
	c.Update(cacheKey)

	// Простая проверка: кэш свежий = пропускаем
	log.Printf("📦 Пропуск анализа %s - кэшированный результат (возраст: %v)",
		cacheKey, time.Since(cached.LastAnalyzed))
	return true
}

// Set сохраняет результат анализа в кэш
func (c *AnalysisCache) Set(cacheKey string, resp *models.URLAnalysisResponse) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[cacheKey] = &CachedAnalysis{
		URLPattern:     cacheKey,
		LastAnalyzed:   time.Now(),
		AnalysisResult: resp,
		AccessCount:    1,
		Confidence:     resp.URLNote.Confidence,
	}

	// Очищаем старые записи если кэш слишком большой
	if len(c.cache) > defaultCacheSizeLimit {
		c.cleanup()
	}
}

// Update обновляет статистику кэшированного анализа
func (c *AnalysisCache) Update(cacheKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if existing, exists := c.cache[cacheKey]; exists {
		existing.AccessCount++
		existing.LastAnalyzed = time.Now()
	}
}

// cleanup очищает старые записи из кэша
func (c *AnalysisCache) cleanup() {
	// Удаляем самые старые записи
	if len(c.cache) < minCacheSizeForCleanup {
		return
	}

	// Простая реализация - оставляем половину самых свежих
	type cacheItem struct {
		key    string
		cached *CachedAnalysis
	}

	items := make([]cacheItem, 0, len(c.cache))
	for key, cached := range c.cache {
		items = append(items, cacheItem{key, cached})
	}

	// Сортируем по времени (самые свежие первые) используя sort.Slice
	sort.Slice(items, func(i, j int) bool {
		return items[i].cached.LastAnalyzed.After(items[j].cached.LastAnalyzed)
	})

	// Оставляем только половину самых свежих
	retainCount := int(float64(len(items)) * cacheRetentionRatio)
	c.cache = make(map[string]*CachedAnalysis, retainCount)
	for i := 0; i < retainCount; i++ {
		c.cache[items[i].key] = items[i].cached
	}
}
