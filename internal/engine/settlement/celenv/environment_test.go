// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnv_Builds(t *testing.T) {
	env, err := NewEnv()
	require.NoError(t, err)
	require.NotNil(t, env)
}

func TestNewEnv_DeclaresEvidenceVariable(t *testing.T) {
	env, err := NewEnv()
	require.NoError(t, err)

	_, issues := env.Compile(`evidence.size() >= 0`)
	require.NoError(t, issues.Err())
}

func TestNewEnv_DeclaresHelperCatalog(t *testing.T) {
	env, err := NewEnv()
	require.NoError(t, err)

	for name, expr := range map[string]string{
		fnEvidenceText:  `evidence.exists(e, evidenceText(e) != "")`,
		fnRegexMatch:    `regexMatch("hello world", "^hello")`,
		fnJSONPath:      `jsonPath("{\"a\":1}", "a") == 1`,
		fnHTTPStatus:    `evidence.exists(e, httpStatus(e) == 200)`,
		fnMarkerPresent: `markerPresent(evidence, "nonce")`,
	} {
		t.Run(name, func(t *testing.T) {
			_, issues := env.Compile(expr)
			assert.NoError(t, issues.Err())
		})
	}
}

// TestNewEnv_IsMinimal locks down that the environment declares nothing
// beyond EvidenceVariable and the curated helper catalog: no stdlib
// extension (strings, lists, …) sneaks in additional functions that would
// widen ADR-0131's environment surface without a deliberate decision.
func TestNewEnv_IsMinimal(t *testing.T) {
	env, err := NewEnv()
	require.NoError(t, err)

	for _, expr := range []string{
		`"hello".trim()`,      // ext.Strings
		`[1, 2].flatten()`,    // ext.Lists / ext.Math
		`evidence.toJSON()`,   // ext.Encoders / protobuf
		`math.greatest(1, 2)`, // ext.Math
	} {
		t.Run(expr, func(t *testing.T) {
			_, issues := env.Compile(expr)
			assert.Error(t, issues.Err(), "expected %q to be outside the environment", expr)
		})
	}
}

// TestNewEnv_WrapsBuildError exercises newEnv's cel.NewEnv error-wrap with a
// genuinely conflicting extra declaration (redefining an already-declared
// overload ID with a different signature is a real cel-go build error, not a
// fabricated one) — NewEnv's own fixed, hardcoded declarations can never
// trigger this on their own, which is why the test goes through newEnv's
// extra-options seam instead.
func TestNewEnv_WrapsBuildError(t *testing.T) {
	_, err := newEnv(
		cel.Function(fnEvidenceText,
			cel.Overload("evidence_text_map", []*cel.Type{cel.StringType}, cel.BoolType),
		),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "celenv: build environment")
}
