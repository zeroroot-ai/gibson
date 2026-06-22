package types

// ResponseFormatType specifies how the LLM should format its response
type ResponseFormatType string

const (
	// ResponseFormatText indicates default, free-form text output
	ResponseFormatText ResponseFormatType = "text"
	// ResponseFormatJSONObject indicates any valid JSON object output
	ResponseFormatJSONObject ResponseFormatType = "json_object"
	// ResponseFormatJSONSchema indicates JSON output matching a specific schema
	ResponseFormatJSONSchema ResponseFormatType = "json_schema"
)

// String returns the string representation of ResponseFormatType
func (r ResponseFormatType) String() string {
	return string(r)
}

// IsValid checks if the response format type is valid
func (r ResponseFormatType) IsValid() bool {
	switch r {
	case ResponseFormatText, ResponseFormatJSONObject, ResponseFormatJSONSchema:
		return true
	default:
		return false
	}
}

// JSONSchema represents a JSON Schema for structured output validation.
type JSONSchema struct {
	// Type specifies the JSON type (object, array, string, number, boolean, null)
	Type string `json:"type,omitempty"`

	// Properties defines object properties (for type: object)
	Properties map[string]*JSONSchema `json:"properties,omitempty"`

	// Required lists required property names (for type: object)
	Required []string `json:"required,omitempty"`

	// Items defines array item schema (for type: array)
	Items *JSONSchema `json:"items,omitempty"`

	// Description provides human-readable schema documentation
	Description string `json:"description,omitempty"`

	// Enum constrains values to a specific set
	Enum []any `json:"enum,omitempty"`

	// Format specifies string format (date-time, email, uri, etc.)
	Format string `json:"format,omitempty"`

	// Pattern specifies a regex pattern for string validation
	Pattern string `json:"pattern,omitempty"`

	// Minimum specifies minimum numeric value
	Minimum *float64 `json:"minimum,omitempty"`

	// Maximum specifies maximum numeric value
	Maximum *float64 `json:"maximum,omitempty"`

	// MinLength specifies minimum string/array length
	MinLength *int `json:"minLength,omitempty"`

	// MaxLength specifies maximum string/array length
	MaxLength *int `json:"maxLength,omitempty"`

	// AdditionalProperties controls whether additional properties are allowed (for type: object)
	AdditionalProperties *bool `json:"additionalProperties,omitempty"`

	// OneOf specifies that the value must match exactly one of the schemas
	OneOf []*JSONSchema `json:"oneOf,omitempty"`

	// AnyOf specifies that the value must match at least one of the schemas
	AnyOf []*JSONSchema `json:"anyOf,omitempty"`

	// AllOf specifies that the value must match all of the schemas
	AllOf []*JSONSchema `json:"allOf,omitempty"`
}

// ResponseFormat specifies the desired response structure from the LLM.
// This type is used to configure structured output in completion requests.
type ResponseFormat struct {
	// Type specifies the response format (text, json_object, json_schema)
	Type ResponseFormatType `json:"type"`

	// Name is an optional schema name for tracing and debugging
	Name string `json:"name,omitempty"`

	// Schema defines the JSON schema (required for json_schema type)
	Schema *JSONSchema `json:"schema,omitempty"`

	// Strict enforces exact schema match when true (provider-dependent)
	Strict bool `json:"strict,omitempty"`
}

// StructuredOutputOptions configures structured output behavior for completion requests.
// These options control how the SDK handles structured output validation and error handling.
type StructuredOutputOptions struct {
	// Format specifies the desired response format and schema
	Format ResponseFormat

	// ValidateSchema enables response validation against the schema (default: true)
	ValidateSchema bool

	// ReturnRawOnFail returns raw JSON on unmarshal failure instead of error
	ReturnRawOnFail bool
}

// NewTextFormat creates a ResponseFormat for plain text output
func NewTextFormat() ResponseFormat {
	return ResponseFormat{
		Type: ResponseFormatText,
	}
}

// NewJSONObjectFormat creates a ResponseFormat for any valid JSON output
func NewJSONObjectFormat(name string) ResponseFormat {
	return ResponseFormat{
		Type: ResponseFormatJSONObject,
		Name: name,
	}
}

// NewJSONSchemaFormat creates a ResponseFormat with a specific JSON schema
func NewJSONSchemaFormat(name string, schema *JSONSchema, strict bool) ResponseFormat {
	return ResponseFormat{
		Type:   ResponseFormatJSONSchema,
		Name:   name,
		Schema: schema,
		Strict: strict,
	}
}

// Validate checks if the ResponseFormat is valid
func (r ResponseFormat) Validate() error {
	if !r.Type.IsValid() {
		return &StructuredOutputValidationError{
			Field:   "type",
			Message: "invalid response format type",
			Value:   string(r.Type),
		}
	}

	if r.Type == ResponseFormatJSONSchema {
		if r.Schema == nil {
			return &StructuredOutputValidationError{
				Field:   "schema",
				Message: "schema is required for json_schema format",
			}
		}
		if r.Name == "" {
			return &StructuredOutputValidationError{
				Field:   "name",
				Message: "name is required for json_schema format",
			}
		}
	}

	return nil
}

// StructuredOutputValidationError represents a structured output validation error
type StructuredOutputValidationError struct {
	Field   string
	Message string
	Value   any
}

// Error implements the error interface
func (e *StructuredOutputValidationError) Error() string {
	if e.Value != nil {
		return "validation error: " + e.Field + ": " + e.Message + " (value: " + anyToString(e.Value) + ")"
	}
	return "validation error: " + e.Field + ": " + e.Message
}

// StructuredOutputUnmarshalError represents an error that occurred during JSON unmarshaling of structured output
type StructuredOutputUnmarshalError struct {
	// RawJSON contains the raw JSON that failed to unmarshal
	RawJSON string

	// UnderlyingError is the original unmarshal error
	UnderlyingError error

	// Schema is the JSON schema that was expected (if available)
	Schema *JSONSchema
}

// Error implements the error interface
func (e *StructuredOutputUnmarshalError) Error() string {
	return "failed to unmarshal structured output: " + e.UnderlyingError.Error()
}

// Unwrap returns the underlying error for error chain inspection
func (e *StructuredOutputUnmarshalError) Unwrap() error {
	return e.UnderlyingError
}

// anyToString converts any value to string for error messages
func anyToString(v any) string {
	if v == nil {
		return "<nil>"
	}
	// Use type assertion for common types
	switch val := v.(type) {
	case string:
		return val
	case int, int8, int16, int32, int64:
		return string(rune(val.(int)))
	case float32, float64:
		return string(rune(int(val.(float64))))
	default:
		return "<unknown>"
	}
}
