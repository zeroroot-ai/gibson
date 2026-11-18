// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

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
