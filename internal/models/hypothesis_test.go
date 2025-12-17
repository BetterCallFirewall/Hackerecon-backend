package models

import (
	"encoding/json"
	"testing"
)

func TestHypothesisResponseSerialization(t *testing.T) {
	// Создаём тестовую структуру
	response := HypothesisResponse{
		InvestigationSuggestions: []InvestigationSuggestion{
			{
				Title:                "Test Investigation",
				Reasoning:            "This is a test reasoning",
				AffectedEndpoints:    []string{"/api/users", "/api/orders"},
				WhatToCheck:          []string{"Step 1", "Step 2"},
				Priority:             "recommend",
				CrossEndpointPattern: "IDOR pattern",
			},
		},
		SiteUnderstanding: SiteUnderstanding{
			LikelyArchitecture:   "SPA + REST API",
			AuthMechanism:        "JWT",
			DataSensitivity:      "PII, Financial",
			AttackSurfaceSummary: "High risk endpoints detected",
		},
	}

	// Сериализуем в JSON
	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal HypothesisResponse: %v", err)
	}

	t.Logf("Serialized JSON:\n%s", string(jsonData))

	// Десериализуем обратно
	var deserialized HypothesisResponse
	if err := json.Unmarshal(jsonData, &deserialized); err != nil {
		t.Fatalf("Failed to unmarshal HypothesisResponse: %v", err)
	}

	// Проверяем, что данные совпадают
	if len(deserialized.InvestigationSuggestions) != len(response.InvestigationSuggestions) {
		t.Errorf("Expected %d investigation suggestions, got %d",
			len(response.InvestigationSuggestions),
			len(deserialized.InvestigationSuggestions))
	}

	if deserialized.InvestigationSuggestions[0].Title != response.InvestigationSuggestions[0].Title {
		t.Errorf("Title mismatch: expected %q, got %q",
			response.InvestigationSuggestions[0].Title,
			deserialized.InvestigationSuggestions[0].Title)
	}

	if deserialized.SiteUnderstanding.LikelyArchitecture != response.SiteUnderstanding.LikelyArchitecture {
		t.Errorf("Architecture mismatch: expected %q, got %q",
			response.SiteUnderstanding.LikelyArchitecture,
			deserialized.SiteUnderstanding.LikelyArchitecture)
	}
}

func TestInvestigationSuggestionWithNullPattern(t *testing.T) {
	// Тест с null значением для cross_endpoint_pattern
	jsonWithNull := `{
		"title": "Test",
		"reasoning": "Test reasoning",
		"affected_endpoints": ["/api/test"],
		"what_to_check": ["step 1"],
		"priority": "recommend",
		"cross_endpoint_pattern": null
	}`

	var suggestion InvestigationSuggestion
	if err := json.Unmarshal([]byte(jsonWithNull), &suggestion); err != nil {
		t.Fatalf("Failed to unmarshal with null pattern: %v", err)
	}

	if suggestion.CrossEndpointPattern != "" {
		t.Errorf("Expected empty string for null pattern, got %q", suggestion.CrossEndpointPattern)
	}

	// Тест с пустой строкой
	jsonWithEmpty := `{
		"title": "Test",
		"reasoning": "Test reasoning",
		"affected_endpoints": ["/api/test"],
		"what_to_check": ["step 1"],
		"priority": "recommend",
		"cross_endpoint_pattern": ""
	}`

	if err := json.Unmarshal([]byte(jsonWithEmpty), &suggestion); err != nil {
		t.Fatalf("Failed to unmarshal with empty pattern: %v", err)
	}

	if suggestion.CrossEndpointPattern != "" {
		t.Errorf("Expected empty string, got %q", suggestion.CrossEndpointPattern)
	}
}
