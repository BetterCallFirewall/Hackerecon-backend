package utils

import (
	"testing"
)

func TestURLNormalizer(t *testing.T) {
	normalizer := NewURLNormalizer()

	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		// API эндпоинты с ID
		{
			"/api/users/123",
			"/api/users/{id}",
			"API users with numeric ID",
		},
		{
			"/api/v1/orders/456",
			"/api/v1/orders/{id}",
			"API v1 orders with numeric ID",
		},
		{
			"/api/products/7890",
			"/api/products/{id}",
			"API products with numeric ID",
		},

		// API эндпоинты с username
		{
			"/api/profiles/john_doe",
			"/api/profiles/{username}",
			"API profiles with username",
		},
		{
			"/api/accounts/admin",
			"/api/accounts/{username}",
			"API accounts with username",
		},
		{
			"/api/blogs/techblog",
			"/api/blogs/{username}",
			"API blogs with username",
		},

		// Профили в вебе
		{
			"/users/john",
			"/users/{username}",
			"Web user profile",
		},
		{
			"/profile/admin_user",
			"/profile/{username}",
			"Web profile",
		},
		{
			"/account/support",
			"/account/{username}",
			"Web account",
		},

		// Статьи и посты со слагами
		{
			"/articles/how-to-code-in-go",
			"/articles/{slug}",
			"Article with slug",
		},
		{
			"/blog/security-tips-for-2024",
			"/blog/{slug}",
			"Blog post with slug",
		},
		{
			"/posts/getting-started-with-react",
			"/posts/{slug}",
			"Posts with slug",
		},

		// UUID (высший приоритет)
		{
			"/api/sessions/550e8400-e29b-41d4-a716-446655440000",
			"/api/sessions/{uuid}",
			"Session with UUID",
		},
		{
			"/users/123e4567-e89b-12d3-a456-426614174000",
			"/users/{uuid}",
			"User with UUID",
		},

		// Ресурсы с ID
		{
			"/orders/123",
			"/orders/{id}",
			"Orders with numeric ID",
		},
		{
			"/files/789",
			"/files/{id}",
			"Files with numeric ID",
		},
		{
			"/comments/42",
			"/comments/{id}",
			"Comments with numeric ID",
		},

		// Даты
		{
			"/archives/2024-01-15",
			"/archives/{date}",
			"Archive with date",
		},
		{
			"/reports/2024-12-25",
			"/reports/{date}",
			"Reports with date",
		},

		// Хеши и токены
		{
			"/reset-password/a1b2c3d4e5f6g7h8",
			"/reset-password/{hash}",
			"Password reset with hash",
		},

		// Явные username
		{
			"/u/john_doe",
			"/u/{username}",
			"Explicit username with /u/",
		},
		{
			"/user/admin",
			"/user/{username}",
			"Explicit username with /user/",
		},

		// Не должны нормализоваться
		{
			"/api/users",
			"/api/users",
			"API users list (no ID)",
		},
		{
			"/static/css/main.css",
			"/static/css/main.css",
			"Static CSS file",
		},
		{
			"/assets/images/logo.png",
			"/assets/images/logo.png",
			"Static image file",
		},
		{
			"/admin/dashboard",
			"/admin/dashboard",
			"Admin dashboard (no parameters)",
		},
		{
			"/settings",
			"/settings",
			"Settings page (no parameters)",
		},
		{
			"/login",
			"/login",
			"Login page (no parameters)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := normalizer.NormalizeURL(tc.input)
			if result != tc.expected {
				t.Errorf("Input: %s\nExpected: %s\nGot:      %s", tc.input, tc.expected, result)
			}
		})
	}
}

func TestContextAwareNormalizer(t *testing.T) {
	normalizer := NewContextAwareNormalizer()

	// Первые запросы создают новые паттерны
	if got := normalizer.NormalizeWithContext("/api/users/123"); got != "/api/users/{id}" {
		t.Errorf("Expected /api/users/{id}, got %s", got)
	}

	if got := normalizer.NormalizeWithContext("/api/users/456"); got != "/api/users/{id}" {
		t.Errorf("Expected /api/users/{id}, got %s", got)
	}

	// Проверяем статистику
	examples := normalizer.GetPatternExamples("/api/users/{id}", 2)
	if len(examples) != 2 {
		t.Errorf("Expected 2 examples, got %d", len(examples))
	}
}

func TestEdgeCases(t *testing.T) {
	normalizer := NewURLNormalizer()

	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		// Сложные URL
		{
			"/api/v1/users/123/orders/456/items",
			"/api/v1/users/{id}/orders/456/items",
			"Complex URL - only first part matched",
		},
		{
			"/users/john/profile/settings",
			"/users/{username}/profile/settings",
			"Username in middle of path",
		},

		// Query параметры должны убираться
		{
			"/api/users/123?sort=desc&page=2",
			"/api/users/{id}",
			"URL with query params",
		},

		// Хвостовые слэши
		{
			"/api/users/123/",
			"/api/users/{id}",
			"URL with trailing slash",
		},

		// Специальные случаи
		{
			"/api/users/me",
			"/api/users/me",
			"Special 'me' user should not be normalized to {username}",
		},
		{
			"/admin/settings",
			"/admin/settings",
			"Admin settings should not be normalized",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := normalizer.NormalizeURL(tc.input)
			if result != tc.expected {
				t.Errorf("Input: %s\nExpected: %s\nGot:      %s", tc.input, tc.expected, result)
			}
		})
	}
}