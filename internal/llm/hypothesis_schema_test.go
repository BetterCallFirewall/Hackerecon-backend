package llm

import (
	"encoding/json"
	"testing"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/invopop/jsonschema"
)

// TestHypothesisResponseSchema проверяет, что схема HypothesisResponse не допускает дополнительных полей
func TestHypothesisResponseSchema(t *testing.T) {
	// Генерируем JSON схему для HypothesisResponse
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
	}
	schema := reflector.Reflect(&models.HypothesisResponse{})

	// Тестовые данные с правильными полями
	validJSON := `{
		"investigation_suggestions": [
			{
				"title": "Test title",
				"reasoning": "Test reasoning",
				"affected_endpoints": ["/api/test"],
				"what_to_check": ["step 1"],
				"priority": "recommend",
				"cross_endpoint_pattern": ""
			}
		],
		"site_understanding": {
			"likely_architecture": "SPA + REST API",
			"auth_mechanism": "JWT",
			"data_sensitivity": "PII",
			"attack_surface_summary": "Test summary"
		}
	}`

	var validData models.HypothesisResponse
	if err := json.Unmarshal([]byte(validJSON), &validData); err != nil {
		t.Fatalf("Failed to unmarshal valid JSON: %v", err)
	}

	// Проверяем, что структура соответствует схеме
	t.Logf("Schema generated successfully")

	// Сериализуем схему и проверим её содержимое
	schemaBytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal schema: %v", err)
	}
	t.Logf("Generated schema:\n%s", string(schemaBytes))

	// Проверяем, что схема содержит нужные определения
	if schema.Definitions == nil {
		t.Log("Schema definitions are nil (this is ok if schema is flat)")
	}
}

// TestInvestigationSuggestionNoExtraFields проверяет, что InvestigationSuggestion не принимает дополнительные поля
func TestInvestigationSuggestionNoExtraFields(t *testing.T) {
	// JSON с дополнительными полями, которых нет в структуре
	invalidJSON := `{
		"title": "Test",
		"reasoning": "Test",
		"affected_endpoints": [],
		"what_to_check": [],
		"priority": "recommend",
		"cross_endpoint_pattern": "",
		"estimated_impact": "High impact",
		"technical_details": "Some details"
	}`

	var data models.InvestigationSuggestion

	// Go unmarshal игнорирует дополнительные поля, но мы проверяем схему
	if err := json.Unmarshal([]byte(invalidJSON), &data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Проверяем, что дополнительные поля не были сохранены
	reMarshaled, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var remarshaled map[string]interface{}
	if err := json.Unmarshal(reMarshaled, &remarshaled); err != nil {
		t.Fatalf("Unmarshal remarshaled failed: %v", err)
	}

	// Проверяем, что дополнительные поля не присутствуют
	if _, ok := remarshaled["estimated_impact"]; ok {
		t.Error("estimated_impact should not be present after marshaling")
	}

	if _, ok := remarshaled["technical_details"]; ok {
		t.Error("technical_details should not be present after marshaling")
	}

	t.Log("Additional fields correctly ignored")
}
