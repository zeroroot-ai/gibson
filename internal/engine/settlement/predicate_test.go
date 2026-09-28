// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package settlement

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTechniqueID_Validate(t *testing.T) {
	tests := []struct {
		name    string
		id      TechniqueID
		wantErr bool
	}{
		{name: "valid", id: "T1190", wantErr: false},
		{name: "empty", id: "", wantErr: true},
		{name: "whitespace only", id: "   ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPredicateType_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pt      PredicateType
		wantErr bool
	}{
		{name: "valid", pt: "marker_present", wantErr: false},
		{name: "empty", pt: "", wantErr: true},
		{name: "whitespace only", pt: "  ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pt.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       Predicate
		wantErr bool
	}{
		{
			name:    "valid",
			p:       Predicate{Technique: "T1190", Type: "marker_present", Params: json.RawMessage(`{"marker":"x"}`)},
			wantErr: false,
		},
		{
			name:    "missing technique",
			p:       Predicate{Type: "marker_present", Params: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "missing type",
			p:       Predicate{Technique: "T1190", Params: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "params allowed empty",
			p:       Predicate{Technique: "T1190", Type: "marker_present"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPredicate_JSONRoundTrip proves a Predicate is plain, serializable data:
// it must survive a marshal/unmarshal round trip unchanged, because
// settlement (ADR-0027) stores it on the graph next to the Hypothesis it
// belongs to and reconstructs it later for replay.
func TestPredicate_JSONRoundTrip(t *testing.T) {
	original := Predicate{
		Technique: "T1190",
		Type:      "http_status_equals",
		Params:    json.RawMessage(`{"want":200}`),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Predicate
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Technique, decoded.Technique)
	assert.Equal(t, original.Type, decoded.Type)
	assert.JSONEq(t, string(original.Params), string(decoded.Params))
}
