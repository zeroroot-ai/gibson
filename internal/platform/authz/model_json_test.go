// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"encoding/json"
	"testing"
)

// TestModelJSON asserts the embedded model renders to the JSON shape OpenFGA's
// /authorization-models API accepts, carrying the real type set — not an empty
// or malformed model. This is the exact output the install seeds OpenFGA with
// (`gibson dump-fga-model`), so a store written from it enforces the same model
// the daemon does.
func TestModelJSON(t *testing.T) {
	out, err := ModelJSON()
	if err != nil {
		t.Fatalf("ModelJSON() error: %v", err)
	}

	var model struct {
		SchemaVersion   string `json:"schema_version"`
		TypeDefinitions []struct {
			Type string `json:"type"`
		} `json:"type_definitions"`
	}
	if err := json.Unmarshal([]byte(out), &model); err != nil {
		t.Fatalf("ModelJSON() is not valid JSON: %v", err)
	}
	if model.SchemaVersion == "" {
		t.Error("ModelJSON() has no schema_version — OpenFGA rejects a model without one")
	}

	got := make(map[string]bool, len(model.TypeDefinitions))
	for _, td := range model.TypeDefinitions {
		got[td.Type] = true
	}
	// A representative slice of model.fga's types. If the transform silently
	// dropped the model these would be absent.
	for _, want := range []string{"user", "tenant", "component", "mission", "secret"} {
		if !got[want] {
			t.Errorf("ModelJSON() is missing type %q (rendered %d types)", want, len(model.TypeDefinitions))
		}
	}
}

// TestModelJSONDeterministic guards the seed being stable across calls — the
// install renders it once per fga-init run and must not depend on map ordering.
func TestModelJSONDeterministic(t *testing.T) {
	a, err := ModelJSON()
	if err != nil {
		t.Fatalf("first ModelJSON(): %v", err)
	}
	b, err := ModelJSON()
	if err != nil {
		t.Fatalf("second ModelJSON(): %v", err)
	}
	if a != b {
		t.Error("ModelJSON() is not deterministic across calls")
	}
}

// TestModelJSONFromDSL_TransformError covers the transform-error branch: an
// invalid DSL string yields an error rather than a panic or empty output.
func TestModelJSONFromDSL_TransformError(t *testing.T) {
	if _, err := modelJSONFromDSL("this is not a valid fga model {{{{"); err == nil {
		t.Fatal("expected a transform error for an invalid DSL")
	}
}
