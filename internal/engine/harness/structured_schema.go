// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/schema"
)

// convertToSDKSchema converts internal schema.JSON to sdk/types.JSONSchema.
// This handles the translation between the internal schema representation used
// for generation and the SDK type used in the public API.
func convertToSDKSchema(s schema.JSON) *types.JSONSchema {
	if s.Type == "" {
		return nil
	}

	result := &types.JSONSchema{
		Type:        s.Type,
		Description: s.Description,
		Required:    s.Required,
	}

	// Convert properties
	if len(s.Properties) > 0 {
		result.Properties = make(map[string]*types.JSONSchema)
		for name, field := range s.Properties {
			result.Properties[name] = convertSchemaFieldToSDK(field)
		}
	}

	// Convert items for array types
	if s.Items != nil {
		result.Items = convertSchemaFieldToSDK(*s.Items)
	}

	// Note: SDK schema.JSON doesn't have AdditionalProperties field

	return result
}

// convertSchemaFieldToSDK converts internal schema.JSON to sdk/types.JSONSchema.
// This recursive function handles nested schemas and all field types.
func convertSchemaFieldToSDK(f schema.JSON) *types.JSONSchema {
	result := &types.JSONSchema{
		Type:        f.Type,
		Description: f.Description,
		Format:      f.Format,
		Pattern:     f.Pattern,
		Minimum:     f.Minimum,
		Maximum:     f.Maximum,
		MinLength:   f.MinLength,
		MaxLength:   f.MaxLength,
		Required:    f.Required,
	}

	// Convert enum ([]string to []any)
	if len(f.Enum) > 0 {
		result.Enum = make([]any, len(f.Enum))
		for i, v := range f.Enum {
			result.Enum[i] = v
		}
	}

	// Convert nested properties
	if len(f.Properties) > 0 {
		result.Properties = make(map[string]*types.JSONSchema)
		for name, nestedField := range f.Properties {
			result.Properties[name] = convertSchemaFieldToSDK(nestedField)
		}
	}

	// Convert items for array types
	if f.Items != nil {
		result.Items = convertSchemaFieldToSDK(*f.Items)
	}

	return result
}

// StructuredSchema returns the name and the JSON Schema of a Go type, for a
// call that asks the model for structured output. Each object lists all of its
// properties as required and refuses other properties, as strict structured
// output needs.
func StructuredSchema(schemaType any) (string, json.RawMessage, error) {
	t := reflect.TypeOf(schemaType)
	if t == nil {
		return "", nil, fmt.Errorf("schema type cannot be nil")
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	name := t.Name()
	if name == "" {
		name = "AnonymousType"
	}
	sdk := convertToSDKSchema(schemaFromReflectType(t))
	if sdk == nil {
		return "", nil, fmt.Errorf("type %s has no object schema", name)
	}
	strictSchema(sdk)
	raw, err := json.Marshal(sdk)
	if err != nil {
		return "", nil, fmt.Errorf("encode the schema of %s: %w", name, err)
	}
	return name, raw, nil
}

// strictSchema marks each object as closed and lists each property as required.
func strictSchema(s *types.JSONSchema) {
	if s == nil {
		return
	}
	if s.Type == "object" {
		closed := false
		s.AdditionalProperties = &closed
		s.Required = s.Required[:0]
		names := make([]string, 0, len(s.Properties))
		for n := range s.Properties {
			names = append(names, n)
		}
		sort.Strings(names)
		s.Required = names
	}
	for _, p := range s.Properties {
		strictSchema(p)
	}
	strictSchema(s.Items)
}
