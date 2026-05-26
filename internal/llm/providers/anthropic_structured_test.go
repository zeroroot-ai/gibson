package providers

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestAnthropicProvider_SupportsStructuredOutput(t *testing.T) {
	provider := &AnthropicProvider{}

	tests := []struct {
		name     string
		format   types.ResponseFormatType
		expected bool
	}{
		{
			name:     "json_schema supported",
			format:   types.ResponseFormatJSONSchema,
			expected: true,
		},
		{
			name:     "json_object not supported",
			format:   types.ResponseFormatJSONObject,
			expected: false,
		},
		{
			name:     "text not supported",
			format:   types.ResponseFormatText,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.SupportsStructuredOutput(tt.format)
			if result != tt.expected {
				t.Errorf("SupportsStructuredOutput(%v) = %v, want %v", tt.format, result, tt.expected)
			}
		})
	}
}

func TestConvertResponseFormatToTool(t *testing.T) {
	format := &types.ResponseFormat{
		Type: types.ResponseFormatJSONSchema,
		Name: "test_response",
		Schema: &types.JSONSchema{
			Type:        "object",
			Description: "Test schema",
			Properties: map[string]*types.JSONSchema{
				"name": {
					Type:        "string",
					Description: "A name field",
				},
				"age": {
					Type:        "integer",
					Description: "An age field",
				},
			},
			Required: []string{"name"},
		},
	}

	tool := convertResponseFormatToTool(format)

	if tool.Name != "test_response" {
		t.Errorf("Expected tool name 'test_response', got '%s'", tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}

	if tool.Parameters.Type != "object" {
		t.Errorf("Expected parameters type 'object', got '%s'", tool.Parameters.Type)
	}

	if len(tool.Parameters.Properties) != 2 {
		t.Errorf("Expected 2 properties, got %d", len(tool.Parameters.Properties))
	}

	if len(tool.Parameters.Required) != 1 {
		t.Errorf("Expected 1 required field, got %d", len(tool.Parameters.Required))
	}
}

func TestConvertSDKSchemaToInternal(t *testing.T) {
	sdkSchema := &types.JSONSchema{
		Type:        "object",
		Description: "Test schema",
		Properties: map[string]*types.JSONSchema{
			"name": {
				Type:        "string",
				Description: "Name field",
				MinLength:   intPtr(1),
				MaxLength:   intPtr(100),
			},
			"tags": {
				Type: "array",
				Items: &types.JSONSchema{
					Type: "string",
				},
			},
		},
		Required: []string{"name"},
	}

	internalSchema := convertSDKSchemaToInternal(sdkSchema)

	if internalSchema.Type != "object" {
		t.Errorf("Expected type 'object', got '%s'", internalSchema.Type)
	}

	if internalSchema.Description != "Test schema" {
		t.Errorf("Expected description 'Test schema', got '%s'", internalSchema.Description)
	}

	if len(internalSchema.Properties) != 2 {
		t.Errorf("Expected 2 properties, got %d", len(internalSchema.Properties))
	}

	nameField, ok := internalSchema.Properties["name"]
	if !ok {
		t.Fatal("Expected 'name' property to exist")
	}

	if nameField.Type != "string" {
		t.Errorf("Expected name field type 'string', got '%s'", nameField.Type)
	}

	if nameField.MinLength == nil || *nameField.MinLength != 1 {
		t.Error("Expected name field MinLength to be 1")
	}

	if nameField.MaxLength == nil || *nameField.MaxLength != 100 {
		t.Error("Expected name field MaxLength to be 100")
	}

	tagsField, ok := internalSchema.Properties["tags"]
	if !ok {
		t.Fatal("Expected 'tags' property to exist")
	}

	if tagsField.Type != "array" {
		t.Errorf("Expected tags field type 'array', got '%s'", tagsField.Type)
	}

	if tagsField.Items == nil {
		t.Fatal("Expected tags field to have items schema")
	}

	if tagsField.Items.Type != "string" {
		t.Errorf("Expected tags items type 'string', got '%s'", tagsField.Items.Type)
	}
}

func TestConvertSDKSchemaFieldToInternal(t *testing.T) {
	sdkField := &types.JSONSchema{
		Type:        "string",
		Description: "Test field",
		Pattern:     "^[a-z]+$",
		Format:      "email",
		Enum:        []any{"option1", "option2"},
	}

	internalField := convertSDKSchemaFieldToInternal(sdkField)

	if internalField.Type != "string" {
		t.Errorf("Expected type 'string', got '%s'", internalField.Type)
	}

	if internalField.Description != "Test field" {
		t.Errorf("Expected description 'Test field', got '%s'", internalField.Description)
	}

	if internalField.Pattern != "^[a-z]+$" {
		t.Errorf("Expected pattern '^[a-z]+$', got '%s'", internalField.Pattern)
	}

	if internalField.Format != "email" {
		t.Errorf("Expected format 'email', got '%s'", internalField.Format)
	}

	if len(internalField.Enum) != 2 {
		t.Errorf("Expected 2 enum values, got %d", len(internalField.Enum))
	}
}

func TestConvertSDKSchemaToInternal_NilSchema(t *testing.T) {
	internalSchema := convertSDKSchemaToInternal(nil)

	if internalSchema.Type != "object" {
		t.Errorf("Expected default type 'object', got '%s'", internalSchema.Type)
	}
}

func TestConvertSDKSchemaFieldToInternal_NilField(t *testing.T) {
	internalField := convertSDKSchemaFieldToInternal(nil)

	if internalField.Type != "object" {
		t.Errorf("Expected default type 'object', got '%s'", internalField.Type)
	}
}

func TestConvertSDKSchemaToInternal_NestedProperties(t *testing.T) {
	sdkSchema := &types.JSONSchema{
		Type: "object",
		Properties: map[string]*types.JSONSchema{
			"person": {
				Type: "object",
				Properties: map[string]*types.JSONSchema{
					"name": {
						Type: "string",
					},
					"age": {
						Type:    "integer",
						Minimum: float64Ptr(0),
						Maximum: float64Ptr(150),
					},
				},
				Required: []string{"name"},
			},
		},
	}

	internalSchema := convertSDKSchemaToInternal(sdkSchema)

	personField, ok := internalSchema.Properties["person"]
	if !ok {
		t.Fatal("Expected 'person' property to exist")
	}

	if personField.Type != "object" {
		t.Errorf("Expected person field type 'object', got '%s'", personField.Type)
	}

	if len(personField.Properties) != 2 {
		t.Errorf("Expected 2 nested properties, got %d", len(personField.Properties))
	}

	nameField, ok := personField.Properties["name"]
	if !ok {
		t.Fatal("Expected nested 'name' property to exist")
	}

	if nameField.Type != "string" {
		t.Errorf("Expected nested name field type 'string', got '%s'", nameField.Type)
	}

	ageField, ok := personField.Properties["age"]
	if !ok {
		t.Fatal("Expected nested 'age' property to exist")
	}

	if ageField.Minimum == nil || *ageField.Minimum != 0 {
		t.Error("Expected age field Minimum to be 0")
	}

	if ageField.Maximum == nil || *ageField.Maximum != 150 {
		t.Error("Expected age field Maximum to be 150")
	}
}

// Helper functions for test
func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}

// Compile-time check that AnthropicProvider implements StructuredOutputProvider
var _ llm.StructuredOutputProvider = (*AnthropicProvider)(nil)
