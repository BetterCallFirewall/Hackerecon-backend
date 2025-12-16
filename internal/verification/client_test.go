package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerificationClient_MakeRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "test response"}`))
	}))
	defer server.Close()

	client := NewVerificationClient(VerificationClientConfig{
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	})

	req := TestRequest{
		URL:    server.URL,
		Method: "GET",
		Headers: map[string]string{
			"User-Agent": "Hackerecon-Verifier/1.0",
		},
	}

	resp, err := client.MakeRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if len(resp.ResponseBody) == 0 {
		t.Error("Expected non-empty response body")
	}
}

func TestVerificationClient_MakeRequest_InvalidURL(t *testing.T) {
	client := NewVerificationClient(VerificationClientConfig{
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	})

	req := TestRequest{
		URL:    "not-a-url",
		Method: "GET",
	}

	_, err := client.MakeRequest(context.Background(), req)

	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestVerificationClient_SafeHeaders(t *testing.T) {
	// Track what headers were received by the server
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "test response"}`))
	}))
	defer server.Close()

	client := NewVerificationClient(VerificationClientConfig{
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	})

	req := TestRequest{
		URL:    server.URL,
		Method: "GET",
		Headers: map[string]string{
			"User-Agent":    "Custom-Agent",
			"Accept":        "text/html",
			"Authorization": "Bearer secret-token",
			"Cookie":        "session=abc123",
			"Content-Type":  "application/json",
		},
	}

	_, err := client.MakeRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check that dangerous headers were filtered out from the request
	if receivedHeaders.Get("Authorization") != "" {
		t.Error("Authorization header should have been filtered out")
	}

	if receivedHeaders.Get("Cookie") != "" {
		t.Error("Cookie header should have been filtered out")
	}

	// Check that safe headers were included in the request
	if receivedHeaders.Get("User-Agent") != "Custom-Agent" {
		t.Errorf("Expected User-Agent 'Custom-Agent', got '%s'", receivedHeaders.Get("User-Agent"))
	}

	if receivedHeaders.Get("Accept") != "text/html" {
		t.Errorf("Expected Accept 'text/html', got '%s'", receivedHeaders.Get("Accept"))
	}
}

func TestVerificationClient_DefaultConfig(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "test"}`))
	}))
	defer server.Close()

	// Test with empty config
	client := NewVerificationClient(VerificationClientConfig{})

	req := TestRequest{
		URL:    server.URL,
		Method: "GET",
	}

	_, err := client.MakeRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should have default user agent
	if receivedHeaders.Get("User-Agent") != "Hackerecon-Verifier/1.0" {
		t.Errorf("Expected default User-Agent, got '%s'", receivedHeaders.Get("User-Agent"))
	}
}

func TestVerificationClient_RedirectBlocking(t *testing.T) {
	// Create a server that always redirects
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/other", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := NewVerificationClient(VerificationClientConfig{
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	})

	// Test with a URL that redirects (should return redirect response)
	req := TestRequest{
		URL:    redirectServer.URL,
		Method: "GET",
	}

	resp, err := client.MakeRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should get redirect status code, not follow the redirect
	if resp.StatusCode != 302 {
		t.Errorf("Expected redirect status (302), got %d", resp.StatusCode)
	}
}