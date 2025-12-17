package driven

import (
	"testing"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

func TestNormalizeURLPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "numeric ID",
			input:    "/api/users/123",
			expected: "/api/users/{id}",
		},
		{
			name:     "multiple numeric IDs",
			input:    "/api/orders/456/items/789",
			expected: "/api/orders/{id}/items/{id}",
		},
		{
			name:     "UUID",
			input:    "/api/users/550e8400-e29b-41d4-a716-446655440000",
			expected: "/api/users/{uuid}",
		},
		{
			name:     "MongoDB ObjectId",
			input:    "/api/documents/507f1f77bcf86cd799439011",
			expected: "/api/documents/{objectid}",
		},
		{
			name:     "long hash",
			input:    "/api/files/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
			expected: "/api/files/{hash}",
		},
		{
			name:     "URL with query params",
			input:    "/api/users/123?page=1&limit=10",
			expected: "/api/users/{id}",
		},
		{
			name:     "mixed IDs",
			input:    "/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000",
			expected: "/api/users/{id}/orders/{uuid}",
		},
		{
			name:     "no normalization needed",
			input:    "/api/users",
			expected: "/api/users",
		},
		{
			name:     "trailing slash preserved",
			input:    "/api/users/",
			expected: "/api/users/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeURLPattern(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeURLPattern(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestURLAnalysisCache(t *testing.T) {
	cache := NewURLAnalysisCache(3)

	// Test Set and Get
	pattern1 := "/api/users/{id}"
	response1 := &models.URLAnalysisResponse{
		InterestLevel: "high",
		EndpointType:  "data_access",
		Observations:  []string{"User endpoint"},
	}
	cache.Set(pattern1, response1)

	result, ok := cache.Get(pattern1)
	if !ok {
		t.Fatal("Expected cache hit, got miss")
	}
	if len(result.Observations) == 0 || result.Observations[0] != response1.Observations[0] {
		t.Errorf("Expected observation %q, got %v", response1.Observations[0], result.Observations)
	}

	// Test cache miss
	_, ok = cache.Get("/api/nonexistent")
	if ok {
		t.Error("Expected cache miss, got hit")
	}

	// Test cache eviction (max size = 3)
	cache.Set("/api/pattern2", &models.URLAnalysisResponse{InterestLevel: "medium", EndpointType: "other"})
	cache.Set("/api/pattern3", &models.URLAnalysisResponse{InterestLevel: "low", EndpointType: "static"})
	cache.Set("/api/pattern4", &models.URLAnalysisResponse{InterestLevel: "high", EndpointType: "api"})

	// First entry should be evicted
	_, ok = cache.Get(pattern1)
	if ok {
		t.Error("Expected first entry to be evicted")
	}

	// Test stats
	stats := cache.Stats()
	if stats["size"].(int) != 3 {
		t.Errorf("Expected cache size 3, got %d", stats["size"])
	}
	if stats["max_size"].(int) != 3 {
		t.Errorf("Expected max size 3, got %d", stats["max_size"])
	}
}

func TestURLAnalysisCacheTTL(t *testing.T) {
	cache := NewURLAnalysisCache(10)

	pattern := "/api/test"
	response := &models.URLAnalysisResponse{
		InterestLevel: "high",
		EndpointType:  "api",
		Observations:  []string{"Test endpoint"},
	}
	cache.Set(pattern, response)

	// Immediately should be cached
	_, ok := cache.Get(pattern)
	if !ok {
		t.Error("Expected cache hit")
	}

	// Manually expire the entry
	cache.mu.Lock()
	cache.cache[pattern].timestamp = time.Now().Add(-10 * time.Minute)
	cache.mu.Unlock()

	// Should be expired now
	_, ok = cache.Get(pattern)
	if ok {
		t.Error("Expected cache miss after TTL expiration")
	}
}

func TestURLAnalysisCacheHits(t *testing.T) {
	cache := NewURLAnalysisCache(10)

	pattern := "/api/test"
	response := &models.URLAnalysisResponse{
		InterestLevel: "high",
		EndpointType:  "api",
		Observations:  []string{"Test endpoint"},
	}
	cache.Set(pattern, response)

	// Get multiple times
	for i := 0; i < 5; i++ {
		cache.Get(pattern)
	}

	stats := cache.Stats()
	totalHits := stats["total_hits"].(int)
	if totalHits != 5 {
		t.Errorf("Expected 5 hits, got %d", totalHits)
	}
}
