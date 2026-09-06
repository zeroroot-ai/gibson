// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package authz — model_json.go
//
// ModelJSON renders the embedded model.fga (see model_subject_types.go) into
// the JSON form OpenFGA's /authorization-models API accepts. It lives beside
// the //go:embed of model.fga on purpose: the daemon enforces this exact model,
// so a store seeded from this output cannot drift from what the daemon checks.
//
// `gibson dump-fga-model` (see pkg/gibsond) prints this, so the install seeds
// OpenFGA from the daemon image itself — no second, hand-vendored copy of the
// model to keep in step.
package authz

import (
	"fmt"

	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/encoding/protojson"
)

// ModelJSON returns the embedded OpenFGA authorization model as the JSON the
// /authorization-models API accepts. The marshal options match
// cmd/gen-fga-model-json byte for byte, so output from either path is
// interchangeable.
func ModelJSON() (string, error) {
	return modelJSONFromDSL(modelDSL)
}

// modelJSONFromDSL is the testable core of ModelJSON: it transforms an OpenFGA
// DSL string to the /authorization-models JSON. Split out so the error branches
// (an invalid DSL) are reachable in a test — the embedded model.fga cannot be
// invalid in production.
func modelJSONFromDSL(dsl string) (string, error) {
	model, err := transformer.TransformDSLToProto(dsl)
	if err != nil {
		return "", fmt.Errorf("transform embedded model.fga: %w", err)
	}
	out, err := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		UseProtoNames: true,
	}.Marshal(model)
	if err != nil {
		return "", fmt.Errorf("marshal authorization model: %w", err)
	}
	return string(out), nil
}
