package driven

import (
	"net/http"
	"strings"
	"testing"

	"github.com/BetterCallFirewall/Hackerecon/internal/utils"
	"github.com/stretchr/testify/assert"
)

// TestCacheKeyGeneration проверяет, что разные тела запросов дают разные ключи кэша
func TestCacheKeyGeneration(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	// Тест 1: POST запросы с разными телами должны иметь разные ключи
	req1, _ := http.NewRequest("POST", "/api/login", strings.NewReader(`{"user":"admin","pass":"123"}`))
	req2, _ := http.NewRequest("POST", "/api/login", strings.NewReader(`{"user":"' OR 1=1 --","pass":"123"}`))

	body1 := `{"user":"admin","pass":"123"}`
	body2 := `{"user":"' OR 1=1 --","pass":"123"}`

	key1 := analyzer.generateCacheKey(req1, body1)
	key2 := analyzer.generateCacheKey(req2, body2)

	// Ключи должны быть разными
	assert.NotEqual(t, key1, key2, "Cache keys should be different for different request bodies")

	// Ключи должны содержать хэш тела
	assert.Contains(t, key1, "POST:/api/login:", "POST request key should contain body hash")
	assert.Contains(t, key2, "POST:/api/login:", "POST request key should contain body hash")
}

// TestCacheKeyGeneration_PUT_PATCH проверяет PUT и PATCH запросы
func TestCacheKeyGeneration_PUT_PATCH(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	// Тест PUT запроса
	putReq1, _ := http.NewRequest("PUT", "/api/users/123", strings.NewReader(`{"name":"John"}`))
	putReq2, _ := http.NewRequest("PUT", "/api/users/123", strings.NewReader(`{"name":"<script>alert(1)</script>"}`))

	putKey1 := analyzer.generateCacheKey(putReq1, `{"name":"John"}`)
	putKey2 := analyzer.generateCacheKey(putReq2, `{"name":"<script>alert(1)</script>"}`)

	assert.NotEqual(t, putKey1, putKey2, "PUT requests with different bodies should have different cache keys")
	assert.Contains(t, putKey1, "PUT:/api/users/{id}:", "PUT request key should contain normalized URL and body hash")

	// Тест PATCH запроса
	patchReq, _ := http.NewRequest("PATCH", "/api/users/123", strings.NewReader(`{"email":"test@example.com"}`))
	patchKey := analyzer.generateCacheKey(patchReq, `{"email":"test@example.com"}`)

	assert.Contains(t, patchKey, "PATCH:/api/users/{id}:", "PATCH request key should contain normalized URL and body hash")
}

// TestCacheKeyGeneration_GET_requests проверяет, что GET запросы не включают тело в ключ
func TestCacheKeyGeneration_GET_requests(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	// GET запросы не должны включать тело в ключ
	getReq, _ := http.NewRequest("GET", "/api/users", nil)
	getReqBody := "this should be ignored"
	getKey := analyzer.generateCacheKey(getReq, getReqBody)

	assert.NotContains(t, getKey, getReqBody, "GET requests should not include body in cache key")
	assert.Equal(t, "GET:/api/users", getKey, "GET request key should be simple and predictable")

	// HEAD запросы также не должны включать тело
	headReq, _ := http.NewRequest("HEAD", "/api/health", nil)
	headKey := analyzer.generateCacheKey(headReq, "ignored body")

	assert.Equal(t, "HEAD:/api/health", headKey, "HEAD requests should not include body in cache key")
}

// TestCacheKeyGeneration_same_body_different_URLs проверяет, что одинаковые тела на разных URL дают разные ключи
func TestCacheKeyGeneration_same_body_different_URLs(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	body := `{"test":"data"}`

	req1, _ := http.NewRequest("POST", "/api/users", strings.NewReader(body))
	req2, _ := http.NewRequest("POST", "/api/orders", strings.NewReader(body))

	key1 := analyzer.generateCacheKey(req1, body)
	key2 := analyzer.generateCacheKey(req2, body)

	assert.NotEqual(t, key1, key2, "Same body on different URLs should have different cache keys")
	assert.Contains(t, key1, "POST:/api/users:")
	assert.Contains(t, key2, "POST:/api/orders:")
}

// TestCacheKeyGeneration_empty_body проверяет обработку пустого тела
func TestCacheKeyGeneration_empty_body(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	postReq, _ := http.NewRequest("POST", "/api/test", strings.NewReader(""))
	keyWithEmptyBody := analyzer.generateCacheKey(postReq, "")

	postReqWithBody, _ := http.NewRequest("POST", "/api/test", strings.NewReader("data"))
	keyWithBody := analyzer.generateCacheKey(postReqWithBody, "data")

	// Ключи должны быть разными
	assert.NotEqual(t, keyWithEmptyBody, keyWithBody, "Empty body and non-empty body should have different keys")

	// Ключ с пустым телом должен быть простым
	assert.Equal(t, "POST:/api/test", keyWithEmptyBody, "Empty body should result in simple cache key")
}

// TestShouldIncludeBodyInCache проверяет логику определения методов с телом
func TestShouldIncludeBodyInCache(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{}

	// Методы, которые должны включать тело в кэш
	assert.True(t, analyzer.shouldIncludeBodyInCache("POST"))
	assert.True(t, analyzer.shouldIncludeBodyInCache("PUT"))
	assert.True(t, analyzer.shouldIncludeBodyInCache("PATCH"))

	// Методы, которые НЕ должны включать тело в кэш
	assert.False(t, analyzer.shouldIncludeBodyInCache("GET"))
	assert.False(t, analyzer.shouldIncludeBodyInCache("HEAD"))
	assert.False(t, analyzer.shouldIncludeBodyInCache("OPTIONS"))
	assert.False(t, analyzer.shouldIncludeBodyInCache("DELETE"))
	assert.False(t, analyzer.shouldIncludeBodyInCache("TRACE"))
	assert.False(t, analyzer.shouldIncludeBodyInCache("CONNECT"))
}

// TestCacheKeyGeneration_consistency проверяет, что одни и те же данные всегда дают одинаковый ключ
func TestCacheKeyGeneration_consistency(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	req, _ := http.NewRequest("POST", "/api/login", strings.NewReader(`{"user":"admin","pass":"123"}`))
	body := `{"user":"admin","pass":"123"}`

	// Генерируем ключ несколько раз
	key1 := analyzer.generateCacheKey(req, body)
	key2 := analyzer.generateCacheKey(req, body)
	key3 := analyzer.generateCacheKey(req, body)

	// Все ключи должны быть одинаковыми
	assert.Equal(t, key1, key2, "Cache key generation should be consistent")
	assert.Equal(t, key2, key3, "Cache key generation should be consistent")
}

// TestCacheKeyGeneration_URL_normalization проверяет, что URL нормализуются в ключах кэша
func TestCacheKeyGeneration_URL_normalization(t *testing.T) {
	analyzer := &GenkitSecurityAnalyzer{
		urlNormalizer: utils.NewContextAwareNormalizer(),
	}

	body := `{"test":"data"}`

	// Запросы с разными ID должны нормализоваться в ОДИН паттерн
	req1, _ := http.NewRequest("POST", "/api/users/123", strings.NewReader(body))
	req2, _ := http.NewRequest("POST", "/api/users/456", strings.NewReader(body))

	key1 := analyzer.generateCacheKey(req1, body)
	key2 := analyzer.generateCacheKey(req2, body)

	// Ключи должны содержать нормализованный паттерн {id}
	assert.Contains(t, key1, "POST:/api/users/{id}:")
	assert.Contains(t, key2, "POST:/api/users/{id}:")

	// Для ОДИНАКОВОГО паттерна и ОДИНАКОВОГО тела ключи должны быть ИДЕНТИЧНЫМИ
	assert.Equal(t, key1, key2, "Same pattern and same body should produce identical cache keys")
}
