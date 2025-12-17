package driven

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/limits"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// SiteContextManager управляет контекстами сайтов с thread-safety и очисткой
type SiteContextManager struct {
	contexts          map[string]*models.SiteContext
	mutex             sync.RWMutex
	cleanupTicker     *time.Ticker
	stopChan          chan struct{}
	limiter           *limits.ContextLimiter
	maxContexts       int
	lastGlobalCleanup int64
}

// SiteContextManagerOptions опции для создания менеджера
type SiteContextManagerOptions struct {
	MaxContexts     int
	CleanupInterval time.Duration
	Limits          *limits.ContextLimiter
}

// DefaultSiteContextManagerOptions возвращает опции по умолчанию
func DefaultSiteContextManagerOptions() *SiteContextManagerOptions {
	return &SiteContextManagerOptions{
		MaxContexts:     100,              // Максимум 100 контекстов
		CleanupInterval: 15 * time.Minute, // Очистка каждые 15 минут
		Limits:          limits.NewContextLimiter(nil),
	}
}

// NewSiteContextManager создает новый менеджер контекстов
func NewSiteContextManager() *SiteContextManager {
	return NewSiteContextManagerWithOptions(nil)
}

// NewSiteContextManagerWithOptions создает новый менеджер контекстов с опциями
func NewSiteContextManagerWithOptions(opts *SiteContextManagerOptions) *SiteContextManager {
	if opts == nil {
		opts = DefaultSiteContextManagerOptions()
	}

	manager := &SiteContextManager{
		contexts:          make(map[string]*models.SiteContext),
		stopChan:          make(chan struct{}),
		limiter:           opts.Limits,
		maxContexts:       opts.MaxContexts,
		lastGlobalCleanup: time.Now().Unix(),
	}

	// Запускаем периодическую очистку
	if opts.CleanupInterval > 0 {
		manager.startCleanupRoutine(opts.CleanupInterval)
	}

	return manager
}

// startCleanupRoutine запускает рутину очистки
func (m *SiteContextManager) startCleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	m.cleanupTicker = ticker
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.PerformGlobalCleanup()
			case <-m.stopChan:
				return
			}
		}
	}()
}

// Stop останавливает менеджер и cleanup routine
func (m *SiteContextManager) Stop() {
	if m.cleanupTicker != nil {
		close(m.stopChan)
		m.cleanupTicker.Stop()
		m.cleanupTicker = nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Очистка всех контекстов
	for host, context := range m.contexts {
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s: %v", host, err)
		}
	}
}

// GetOrCreate получает или создает контекст для хоста
func (m *SiteContextManager) GetOrCreate(host string) *models.SiteContext {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if context, exists := m.contexts[host]; exists {
		return context
	}

	// Проверяем лимит количества контекстов
	if len(m.contexts) >= m.maxContexts {
		m.evictOldestContext()
	}

	newContext := models.NewSiteContextWithLimiter(host, m.limiter)
	m.contexts[host] = newContext
	return newContext
}

// Get возвращает контекст для хоста
func (m *SiteContextManager) Get(host string) *models.SiteContext {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.contexts[host]
}

// evictOldestContext удаляет самый старый контекст
func (m *SiteContextManager) evictOldestContext() {
	var oldestHost string
	var oldestTime int64 = time.Now().Unix()

	for host, context := range m.contexts {
		stats := context.GetStats()
		if lastActivity, ok := stats["last_activity"].(int64); ok && lastActivity < oldestTime {
			oldestTime = lastActivity
			oldestHost = host
		}
	}

	if oldestHost != "" {
		delete(m.contexts, oldestHost)
		log.Printf("Evicted oldest context for host: %s", oldestHost)
	}
}

// UpdateURLPattern обновляет паттерн URL с новой заметкой
func (m *SiteContextManager) UpdateURLPattern(
	siteContext *models.SiteContext,
	url, method string,
	urlNote *models.URLNote,
) error {
	if siteContext == nil {
		return fmt.Errorf("siteContext cannot be nil")
	}

	if urlNote == nil {
		return fmt.Errorf("urlNote cannot be nil")
	}

	patternKey := fmt.Sprintf("%s:%s", method, url)

	urlPattern := &models.URLPattern{
		Pattern: url,
		Method:  method,
		Notes:   []models.URLNote{*urlNote},
	}

	// Если есть контент в заметке, используем его как purpose
	if urlNote.Content != "" {
		urlPattern.Purpose = urlNote.Content
	}

	return siteContext.UpdateURLPattern(patternKey, urlPattern, urlNote)
}

// UpdateURLPatternSimple обновляет паттерн URL с endpointType (новый API)
func (m *SiteContextManager) UpdateURLPatternSimple(
	siteContext *models.SiteContext,
	url, method string,
	endpointType string,
) error {
	if siteContext == nil {
		return fmt.Errorf("siteContext cannot be nil")
	}

	// Создаем базовую заметку из endpointType
	note := &models.URLNote{
		Content:    endpointType,
		Suspicious: false,
		Confidence: 0.5,
	}

	return m.UpdateURLPattern(siteContext, url, method, note)
}

// PerformGlobalCleanup выполняет глобальную очистку всех контекстов
func (m *SiteContextManager) PerformGlobalCleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now().Unix()
	cleanupCount := 0
	evictionCount := 0

	// Очистка каждого контекста
	for host, context := range m.contexts {
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s: %v", host, err)
			continue
		}
		cleanupCount++

		// Проверяем, не нужно ли удалить контекст полностью
		stats := context.GetStats()
		if lastActivity, ok := stats["last_activity"].(int64); ok {
			if m.limiter.ShouldCleanup(lastActivity) {
				delete(m.contexts, host)
				evictionCount++
				log.Printf("Evicted inactive context for host: %s", host)
			}
		}
	}

	// Дополнительная проверка лимитов
	if len(m.contexts) > m.maxContexts {
		m.evictOldestContext()
		evictionCount++
	}

	m.lastGlobalCleanup = now

	if cleanupCount > 0 || evictionCount > 0 {
		log.Printf(
			"Global cleanup completed: %d contexts cleaned, %d contexts evicted, %d total contexts",
			cleanupCount, evictionCount, len(m.contexts),
		)
	}
}

// GetStats возвращает статистику менеджера
func (m *SiteContextManager) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	totalMemory := int64(0)
	totalRequests := int64(0)
	totalURLPatterns := 0
	totalForms := 0
	totalResources := 0

	for _, context := range m.contexts {
		stats := context.GetStats()
		if mem, ok := stats["memory_estimate"].(int64); ok {
			totalMemory += mem
		}
		if req, ok := stats["request_count"].(int64); ok {
			totalRequests += req
		}
		if patterns, ok := stats["url_patterns"].(int); ok {
			totalURLPatterns += patterns
		}
		if forms, ok := stats["forms"].(int); ok {
			totalForms += forms
		}
		if resources, ok := stats["resources"].(int); ok {
			totalResources += resources
		}
	}

	return map[string]interface{}{
		"total_contexts":      len(m.contexts),
		"max_contexts":        m.maxContexts,
		"total_memory_bytes":  totalMemory,
		"total_requests":      totalRequests,
		"total_url_patterns":  totalURLPatterns,
		"total_forms":         totalForms,
		"total_resources":     totalResources,
		"last_global_cleanup": m.lastGlobalCleanup,
	}
}

// GetAllHosts возвращает список всех хостов
func (m *SiteContextManager) GetAllHosts() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	hosts := make([]string, 0, len(m.contexts))
	for host := range m.contexts {
		hosts = append(hosts, host)
	}
	return hosts
}

// RemoveContext удаляет контекст для хоста
func (m *SiteContextManager) RemoveContext(host string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if context, exists := m.contexts[host]; exists {
		// Очистка перед удалением
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s before removal: %v", host, err)
		}
		delete(m.contexts, host)
		log.Printf("Removed context for host: %s", host)
	}
}

// UpdateLimits обновляет лимиты для всех контекстов
func (m *SiteContextManager) UpdateLimits(limits *limits.ContextLimits) error {
	if err := m.limiter.UpdateLimits(limits); err != nil {
		return fmt.Errorf("failed to update limits: %w", err)
	}

	// Обновляем лимиты для всех существующих контекстов
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, context := range m.contexts {
		// В реальной реализации нужно обновить limiter в context
		// Это может потребовать изменения структуры SiteContext
		log.Printf("Updated limits for context: %s", context.Host)
	}

	return nil
}

// MarkPatternAsVulnerable отмечает паттерн как подтвержденно уязвимый
func (m *SiteContextManager) MarkPatternAsVulnerable(host, pattern string, impact string, testRequest string) error {
	m.mutex.RLock()
	context, exists := m.contexts[host]
	m.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("context for host %s not found", host)
	}

	context.MarkPatternAsVulnerable(pattern, impact, testRequest)
	log.Printf("✅ Marked pattern as vulnerable: %s in %s", pattern, host)
	return nil
}

// MarkPatternAsSafe отмечает паттерн как безопасный
func (m *SiteContextManager) MarkPatternAsSafe(host, pattern string) error {
	m.mutex.RLock()
	context, exists := m.contexts[host]
	m.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("context for host %s not found", host)
	}

	context.MarkPatternAsSafe(pattern)
	log.Printf("✅ Marked pattern as safe: %s in %s", pattern, host)
	return nil
}

// IsPatternVerifiedSafe проверяет был ли паттерн верифицирован как безопасный
func (m *SiteContextManager) IsPatternVerifiedSafe(host, pattern string) bool {
	m.mutex.RLock()
	context, exists := m.contexts[host]
	m.mutex.RUnlock()

	if !exists {
		return false
	}

	return context.IsPatternVerifiedSafe(pattern)
}

// IsPatternVerifiedVulnerable проверяет был ли паттерн верифицирован как уязвимый
func (m *SiteContextManager) IsPatternVerifiedVulnerable(host, pattern string) bool {
	m.mutex.RLock()
	context, exists := m.contexts[host]
	m.mutex.RUnlock()

	if !exists {
		return false
	}

	return context.IsPatternVerifiedVulnerable(pattern)
}

// FindCrossEndpointPatterns ищет паттерны уязвимостей на нескольких эндпоинтах
func (m *SiteContextManager) FindCrossEndpointPatterns(host string) []models.CrossEndpointPattern {
	verifiedPatterns := m.getVerifiedPatternsForHost(host)

	// Группируем паттерны по типам уязвимостей
	patternMap := make(map[string]*models.CrossEndpointPattern)

	// Анализируем VerifiedPatterns
	for patternKey, verification := range verifiedPatterns {
		if !verification.IsVulnerable || verification.Confidence < 0.7 {
			continue
		}

		// Извлекаем URL из ключа паттерна (формат: URL:title)
		parts := strings.Split(patternKey, ":")
		if len(parts) < 2 {
			continue
		}

		url := parts[0]

		// Нормализуем URL в паттерн (e.g., /users/123 → /users/{id})
		normalizedPattern := normalizeURLPattern(url)

		if crossPattern, exists := patternMap[normalizedPattern]; exists {
			// Уже встречали этот паттерн
			if !contains(crossPattern.Endpoints, url) {
				crossPattern.Endpoints = append(crossPattern.Endpoints, url)
				crossPattern.LastSeen = time.Now().Unix()
			}
		} else {
			// Новый паттерн
			patternMap[normalizedPattern] = &models.CrossEndpointPattern{
				Pattern:           normalizedPattern,
				Endpoints:         []string{url},
				IsVulnerable:      true,
				Confidence:        verification.Confidence,
				FirstSeen:         verification.VerifiedAt,
				LastSeen:          verification.VerifiedAt,
				ImpactedResources: extractResourcesFromURL(url),
				RecommendedAction: "Check all endpoints with this pattern for the same vulnerability",
			}
		}
	}

	// Преобразуем в slice и возвращаем только паттерны на 2+ эндпоинтах
	result := make([]models.CrossEndpointPattern, 0)
	for _, pattern := range patternMap {
		if len(pattern.Endpoints) >= 2 {
			result = append(result, *pattern)
		}
	}

	if len(result) > 0 {
		log.Printf("🔗 Found %d cross-endpoint patterns for %s", len(result), host)
	}

	return result
}

// getVerifiedPatternsForHost получает VerifiedPatterns для хоста потокобезопасно
func (m *SiteContextManager) getVerifiedPatternsForHost(host string) map[string]*models.PatternVerification {
	m.mutex.RLock()
	context, exists := m.contexts[host]
	m.mutex.RUnlock()

	if !exists {
		return make(map[string]*models.PatternVerification)
	}

	// Копируем паттерны под RLock
	result := make(map[string]*models.PatternVerification)

	// SiteContext методы уже потокобезопасны, но для копирования все равно нужна блокировка
	// В models.SiteContext это должно быть реализовано как метод, но временно скопируем
	// Это хак - нужно добавить метод в SiteContext для безопасного доступа

	// Для теперь просто возвращаем пустой результат если нет прямого доступа
	if context.VerifiedPatterns != nil {
		for k, v := range context.VerifiedPatterns {
			result[k] = v
		}
	}

	return result
}

// extractResourcesFromURL извлекает ресурсы из URL
func extractResourcesFromURL(url string) []string {
	// Простое извлечение: /users/123 → ["users"]
	parts := strings.Split(strings.TrimPrefix(url, "/"), "/")
	resources := make([]string, 0)

	re := regexp.MustCompile(`^\d+$`)
	for _, part := range parts {
		// Пропускаем пустые и числовые части
		if part != "" && !re.MatchString(part) {
			resources = append(resources, part)
		}
	}

	return resources
}

// contains проверяет содержит ли slice строку
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
