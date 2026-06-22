package providers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestOpenAIStructuredOutputInterface verifies OpenAI provider implements StructuredOutputProvider
func TestOpenAIStructuredOutputInterface(t *testing.T) {
	cfg := llm.ProviderConfig{
		APIKey:       "test-key",
		DefaultModel: "gpt-4",
	}

	provider, err := NewOpenAIProvider(cfg)
	if err != nil {
		t.Fatalf("Failed to create OpenAI provider: %v", err)
	}

	// Test interface implementation
	var sop llm.StructuredOutputProvider
	var ok bool
	sop, ok = interface{}(provider).(llm.StructuredOutputProvider)
	if !ok {
		t.Fatal("OpenAI provider does not implement StructuredOutputProvider interface")
	}

	t.Log("✓ OpenAI provider implements StructuredOutputProvider interface")

	// Test format support
	tests := []struct {
		format   types.ResponseFormatType
		expected bool
		name     string
	}{
		{types.ResponseFormatJSONObject, true, "json_object"},
		{types.ResponseFormatJSONSchema, true, "json_schema"},
		{types.ResponseFormatText, false, "text"},
	}

	for _, tt := range tests {
		t.Run("Supports_"+tt.name, func(t *testing.T) {
			supported := sop.SupportsStructuredOutput(tt.format)
			if supported != tt.expected {
				t.Errorf("SupportsStructuredOutput(%s) = %v, want %v", tt.name, supported, tt.expected)
			}
		})
	}
}

// TestOpenAICompleteStructuredValidation tests validation of structured output requests
func TestOpenAICompleteStructuredValidation(t *testing.T) {
	cfg := llm.ProviderConfig{
		APIKey:       "test-key",
		DefaultModel: "gpt-4",
	}

	provider, err := NewOpenAIProvider(cfg)
	if err != nil {
		t.Fatalf("Failed to create OpenAI provider: %v", err)
	}

	sop := interface{}(provider).(llm.StructuredOutputProvider)

	t.Run("NilResponseFormat", func(t *testing.T) {
		req := llm.CompletionRequest{
			Model: "gpt-4",
			Messages: []llm.Message{
				llm.NewUserMessage("test"),
			},
			ResponseFormat: nil,
		}

		_, err := sop.CompleteStructured(context.Background(), req)
		if err == nil {
			t.Error("Expected error for nil ResponseFormat, got nil")
		}
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		req := llm.CompletionRequest{
			Model: "gpt-4",
			Messages: []llm.Message{
				llm.NewUserMessage("test"),
			},
			ResponseFormat: &types.ResponseFormat{
				Type: types.ResponseFormatText,
			},
		}

		_, err := sop.CompleteStructured(context.Background(), req)
		if err == nil {
			t.Error("Expected error for unsupported format, got nil")
		}
	})

	t.Run("JSONSchemaWithoutName", func(t *testing.T) {
		schema := &types.JSONSchema{
			Type: "object",
			Properties: map[string]*types.JSONSchema{
				"name": {Type: "string"},
			},
		}

		req := llm.CompletionRequest{
			Model: "gpt-4",
			Messages: []llm.Message{
				llm.NewUserMessage("test"),
			},
			ResponseFormat: &types.ResponseFormat{
				Type:   types.ResponseFormatJSONSchema,
				Schema: schema,
				Name:   "", // Missing name
			},
		}

		_, err := sop.CompleteStructured(context.Background(), req)
		if err == nil {
			t.Error("Expected error for json_schema without name, got nil")
		}
	})
}

// TestOpenAIJSONSchemaConversion tests schema conversion helper
func TestOpenAIJSONSchemaConversion(t *testing.T) {
	t.Run("NilSchema", func(t *testing.T) {
		_, err := jsonSchemaToMap(nil)
		if err == nil {
			t.Error("Expected error for nil schema, got nil")
		}
	})

	t.Run("ValidSchema", func(t *testing.T) {
		schema := &types.JSONSchema{
			Type: "object",
			Properties: map[string]*types.JSONSchema{
				"name": {
					Type:        "string",
					Description: "The name field",
				},
				"age": {
					Type:    "integer",
					Minimum: openaiFloat64Ptr(0),
				},
			},
			Required: []string{"name"},
		}

		result, err := jsonSchemaToMap(schema)
		if err != nil {
			t.Fatalf("jsonSchemaToMap failed: %v", err)
		}

		// Verify structure
		if result["type"] != "object" {
			t.Errorf("Expected type=object, got %v", result["type"])
		}

		props, ok := result["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("Properties is not a map")
		}

		if _, ok := props["name"]; !ok {
			t.Error("Missing 'name' property")
		}

		if _, ok := props["age"]; !ok {
			t.Error("Missing 'age' property")
		}

		required, ok := result["required"].([]interface{})
		if !ok {
			t.Fatal("Required is not an array")
		}

		if len(required) != 1 || required[0] != "name" {
			t.Errorf("Expected required=['name'], got %v", required)
		}
	})
}

func openaiFloat64Ptr(f float64) *float64 {
	return &f
}

// TestBuildResponseFormat verifies the OpenAI response_format object built for
// each supported format type.
func TestBuildResponseFormat(t *testing.T) {
	t.Run("JSONObject", func(t *testing.T) {
		rf, err := buildResponseFormat(&types.ResponseFormat{Type: types.ResponseFormatJSONObject})
		if err != nil {
			t.Fatalf("buildResponseFormat: %v", err)
		}
		if rf["type"] != "json_object" {
			t.Errorf("type = %v, want json_object", rf["type"])
		}
		if _, ok := rf["json_schema"]; ok {
			t.Error("json_object format must not carry a json_schema field")
		}
	})

	t.Run("JSONSchema", func(t *testing.T) {
		rf, err := buildResponseFormat(&types.ResponseFormat{
			Type:   types.ResponseFormatJSONSchema,
			Name:   "person",
			Strict: true,
			Schema: &types.JSONSchema{
				Type:       "object",
				Properties: map[string]*types.JSONSchema{"name": {Type: "string"}},
				Required:   []string{"name"},
			},
		})
		if err != nil {
			t.Fatalf("buildResponseFormat: %v", err)
		}
		if rf["type"] != "json_schema" {
			t.Errorf("type = %v, want json_schema", rf["type"])
		}
		js, ok := rf["json_schema"].(map[string]any)
		if !ok {
			t.Fatal("json_schema is not a map")
		}
		if js["name"] != "person" {
			t.Errorf("name = %v, want person", js["name"])
		}
		if js["strict"] != true {
			t.Errorf("strict = %v, want true", js["strict"])
		}
		if _, ok := js["schema"].(map[string]interface{}); !ok {
			t.Error("schema is not a map")
		}
	})

	t.Run("JSONSchemaNilSchema", func(t *testing.T) {
		_, err := buildResponseFormat(&types.ResponseFormat{
			Type: types.ResponseFormatJSONSchema,
			Name: "x",
		})
		if err == nil {
			t.Error("expected error for json_schema with nil schema, got nil")
		}
	})
}

// TestInjectResponseFormat verifies the Eino request-payload modifier merges
// response_format into the serialized request without dropping existing fields.
func TestInjectResponseFormat(t *testing.T) {
	rf := map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "person",
			"schema": map[string]any{"type": "object"},
			"strict": true,
		},
	}

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"temperature":0.5}`)

	out, err := injectResponseFormat(rf)(context.Background(), nil, body)
	if err != nil {
		t.Fatalf("injectResponseFormat: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal modified payload: %v", err)
	}

	// Existing fields preserved.
	for _, k := range []string{"model", "messages", "temperature"} {
		if _, ok := got[k]; !ok {
			t.Errorf("modifier dropped existing field %q", k)
		}
	}

	// response_format injected and well-formed.
	raw, ok := got["response_format"]
	if !ok {
		t.Fatal("response_format was not injected")
	}
	var injected map[string]any
	if err := json.Unmarshal(raw, &injected); err != nil {
		t.Fatalf("unmarshal response_format: %v", err)
	}
	if injected["type"] != "json_schema" {
		t.Errorf("response_format.type = %v, want json_schema", injected["type"])
	}
}

// TestInjectResponseFormatBadPayload verifies the modifier surfaces an error
// when handed a non-object payload.
func TestInjectResponseFormatBadPayload(t *testing.T) {
	_, err := injectResponseFormat(map[string]any{"type": "json_object"})(
		context.Background(), nil, []byte(`not-json`))
	if err == nil {
		t.Error("expected error for invalid payload, got nil")
	}
}
