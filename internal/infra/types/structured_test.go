package types

import (
	"encoding/json"
	"testing"
)

func TestResponseFormatType_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		rType ResponseFormatType
		want  bool
	}{
		{
			name:  "text format is valid",
			rType: ResponseFormatText,
			want:  true,
		},
		{
			name:  "json_object format is valid",
			rType: ResponseFormatJSONObject,
			want:  true,
		},
		{
			name:  "json_schema format is valid",
			rType: ResponseFormatJSONSchema,
			want:  true,
		},
		{
			name:  "invalid format",
			rType: ResponseFormatType("invalid"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rType.IsValid(); got != tt.want {
				t.Errorf("ResponseFormatType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResponseFormat_Validate(t *testing.T) {
	tests := []struct {
		name    string
		format  ResponseFormat
		wantErr bool
	}{
		{
			name: "valid text format",
			format: ResponseFormat{
				Type: ResponseFormatText,
			},
			wantErr: false,
		},
		{
			name: "valid json_object format",
			format: ResponseFormat{
				Type: ResponseFormatJSONObject,
				Name: "test",
			},
			wantErr: false,
		},
		{
			name: "valid json_schema format",
			format: ResponseFormat{
				Type: ResponseFormatJSONSchema,
				Name: "test",
				Schema: &JSONSchema{
					Type: "object",
				},
			},
			wantErr: false,
		},
		{
			name: "json_schema without schema",
			format: ResponseFormat{
				Type: ResponseFormatJSONSchema,
				Name: "test",
			},
			wantErr: true,
		},
		{
			name: "json_schema without name",
			format: ResponseFormat{
				Type: ResponseFormatJSONSchema,
				Schema: &JSONSchema{
					Type: "object",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid format type",
			format: ResponseFormat{
				Type: ResponseFormatType("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.format.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ResponseFormat.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewTextFormat(t *testing.T) {
	format := NewTextFormat()
	if format.Type != ResponseFormatText {
		t.Errorf("NewTextFormat() type = %v, want %v", format.Type, ResponseFormatText)
	}
}

func TestNewJSONObjectFormat(t *testing.T) {
	name := "test_object"
	format := NewJSONObjectFormat(name)
	if format.Type != ResponseFormatJSONObject {
		t.Errorf("NewJSONObjectFormat() type = %v, want %v", format.Type, ResponseFormatJSONObject)
	}
	if format.Name != name {
		t.Errorf("NewJSONObjectFormat() name = %v, want %v", format.Name, name)
	}
}

func TestNewJSONSchemaFormat(t *testing.T) {
	name := "test_schema"
	schema := &JSONSchema{Type: "object"}
	strict := true

	format := NewJSONSchemaFormat(name, schema, strict)

	if format.Type != ResponseFormatJSONSchema {
		t.Errorf("NewJSONSchemaFormat() type = %v, want %v", format.Type, ResponseFormatJSONSchema)
	}
	if format.Name != name {
		t.Errorf("NewJSONSchemaFormat() name = %v, want %v", format.Name, name)
	}
	if format.Schema != schema {
		t.Errorf("NewJSONSchemaFormat() schema doesn't match")
	}
	if format.Strict != strict {
		t.Errorf("NewJSONSchemaFormat() strict = %v, want %v", format.Strict, strict)
	}
}

func TestJSONSchema_MarshalJSON(t *testing.T) {
	schema := &JSONSchema{
		Type:        "object",
		Description: "A test schema",
		Properties: map[string]*JSONSchema{
			"name": {
				Type:        "string",
				Description: "User name",
			},
			"age": {
				Type:        "number",
				Description: "User age",
			},
		},
		Required: []string{"name"},
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Failed to marshal JSONSchema: %v", err)
	}

	// Unmarshal to verify structure
	var unmarshaled JSONSchema
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal JSONSchema: %v", err)
	}

	if unmarshaled.Type != schema.Type {
		t.Errorf("Type mismatch after unmarshal: got %v, want %v", unmarshaled.Type, schema.Type)
	}
	if unmarshaled.Description != schema.Description {
		t.Errorf("Description mismatch after unmarshal: got %v, want %v", unmarshaled.Description, schema.Description)
	}
	if len(unmarshaled.Required) != len(schema.Required) {
		t.Errorf("Required length mismatch: got %v, want %v", len(unmarshaled.Required), len(schema.Required))
	}
}

func TestResponseFormat_MarshalJSON(t *testing.T) {
	format := ResponseFormat{
		Type:   ResponseFormatJSONSchema,
		Name:   "user_schema",
		Strict: true,
		Schema: &JSONSchema{
			Type: "object",
			Properties: map[string]*JSONSchema{
				"id": {Type: "string"},
			},
		},
	}

	data, err := json.Marshal(format)
	if err != nil {
		t.Fatalf("Failed to marshal ResponseFormat: %v", err)
	}

	var unmarshaled ResponseFormat
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal ResponseFormat: %v", err)
	}

	if unmarshaled.Type != format.Type {
		t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, format.Type)
	}
	if unmarshaled.Name != format.Name {
		t.Errorf("Name mismatch: got %v, want %v", unmarshaled.Name, format.Name)
	}
	if unmarshaled.Strict != format.Strict {
		t.Errorf("Strict mismatch: got %v, want %v", unmarshaled.Strict, format.Strict)
	}
}

func TestStructuredOutputValidationError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     StructuredOutputValidationError
		wantMsg string
	}{
		{
			name: "error with value",
			err: StructuredOutputValidationError{
				Field:   "type",
				Message: "invalid type",
				Value:   "invalid_type",
			},
			wantMsg: "validation error: type: invalid type (value: invalid_type)",
		},
		{
			name: "error without value",
			err: StructuredOutputValidationError{
				Field:   "schema",
				Message: "schema is required",
			},
			wantMsg: "validation error: schema: schema is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("StructuredOutputValidationError.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestStructuredOutputUnmarshalError_Error(t *testing.T) {
	underlyingErr := json.Unmarshal([]byte("invalid"), &struct{}{})
	err := &StructuredOutputUnmarshalError{
		RawJSON:         `{"invalid": "json"}`,
		UnderlyingError: underlyingErr,
	}

	errMsg := err.Error()
	if errMsg == "" {
		t.Error("StructuredOutputUnmarshalError.Error() returned empty string")
	}
}

func TestStructuredOutputUnmarshalError_Unwrap(t *testing.T) {
	underlyingErr := json.Unmarshal([]byte("invalid"), &struct{}{})
	err := &StructuredOutputUnmarshalError{
		RawJSON:         `{"invalid": "json"}`,
		UnderlyingError: underlyingErr,
	}

	if err.Unwrap() != underlyingErr {
		t.Error("StructuredOutputUnmarshalError.Unwrap() didn't return underlying error")
	}
}

func TestStructuredOutputOptions(t *testing.T) {
	// Test that StructuredOutputOptions struct compiles and can be initialized
	opts := StructuredOutputOptions{
		Format: ResponseFormat{
			Type: ResponseFormatJSONSchema,
			Name: "test",
			Schema: &JSONSchema{
				Type: "object",
			},
		},
		ValidateSchema:  true,
		ReturnRawOnFail: false,
	}

	if opts.Format.Type != ResponseFormatJSONSchema {
		t.Errorf("StructuredOutputOptions format type = %v, want %v", opts.Format.Type, ResponseFormatJSONSchema)
	}
	if !opts.ValidateSchema {
		t.Error("StructuredOutputOptions ValidateSchema should be true")
	}
	if opts.ReturnRawOnFail {
		t.Error("StructuredOutputOptions ReturnRawOnFail should be false")
	}
}
