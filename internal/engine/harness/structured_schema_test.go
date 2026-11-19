// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"encoding/json"
	"testing"
)

type schemaProbe struct {
	Action string   `json:"action" jsonschema:"description=What to do"`
	Tags   []string `json:"tags"`
	Inner  struct {
		N int `json:"n"`
	} `json:"inner"`
}

// A strict schema closes each object and lists each property as required.
func TestStructuredSchema_IsStrict(t *testing.T) {
	name, raw, err := StructuredSchema(&schemaProbe{})
	if err != nil {
		t.Fatalf("StructuredSchema: %v", err)
	}
	if name != "schemaProbe" {
		t.Errorf("name = %q", name)
	}
	var s struct {
		Type                 string                     `json:"type"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if s.Type != "object" || s.AdditionalProperties == nil || *s.AdditionalProperties {
		t.Errorf("schema = %s, want a closed object", raw)
	}
	if len(s.Required) != len(s.Properties) || len(s.Properties) != 3 {
		t.Errorf("required = %v, properties = %d", s.Required, len(s.Properties))
	}
}

func TestStructuredSchema_NilTypeIsAnError(t *testing.T) {
	if _, _, err := StructuredSchema(nil); err == nil {
		t.Error("a nil type was accepted")
	}
}
