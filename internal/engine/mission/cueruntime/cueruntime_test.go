// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cueruntime_test

import (
	"context"
	_ "embed"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/targetbind"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
)

//go:embed testdata/recon.cue
var reconCUE string

//go:embed testdata/webapp-scan.cue
var webappScanCUE string

//go:embed testdata/secrets-audit.cue
var secretsAuditCUE string

//go:embed testdata/compliance-check.cue
var complianceCheckCUE string

// invalidCUE is deliberately malformed to exercise error diagnostic paths.
const invalidCUE = `
import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name: 12345  // type error: string field assigned an integer
	UNCLOSED {   // syntax error: brace not properly opened
`

// TestValidate_ValidTemplate asserts that each ADK template produces zero
// error diagnostics when validated against the mission schema.
func TestValidate_ValidTemplate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		source string
	}{
		{"recon", reconCUE},
		{"webapp-scan", webappScanCUE},
		{"secrets-audit", secretsAuditCUE},
		{"compliance-check", complianceCheckCUE},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diags, err := cueruntime.Validate(context.Background(), tc.source)
			require.NoError(t, err, "Validate must not return a Go error for valid CUE")
			// Filter to only errors (warnings are allowed).
			var errDiags []cueruntime.Diagnostic
			for _, d := range diags {
				if d.Severity == "error" {
					errDiags = append(errDiags, d)
				}
			}
			assert.Empty(t, errDiags, "expected zero error diagnostics for template %s", tc.name)
		})
	}
}

// TestValidate_InvalidCUE asserts that malformed CUE returns at least one
// error diagnostic with a line number greater than zero.
func TestValidate_InvalidCUE(t *testing.T) {
	t.Parallel()
	diags, err := cueruntime.Validate(context.Background(), invalidCUE)
	require.NoError(t, err, "Validate must not return a Go error; errors go into diagnostics")
	require.NotEmpty(t, diags, "expected at least one diagnostic for invalid CUE")

	hasLineInfo := false
	for _, d := range diags {
		if d.Line > 0 {
			hasLineInfo = true
			break
		}
	}
	assert.True(t, hasLineInfo, "at least one diagnostic should carry line > 0")
}

// TestExport_ReconTemplate asserts that the recon template exports to a
// non-nil MissionDefinition proto with at least one node.
func TestExport_ReconTemplate(t *testing.T) {
	t.Parallel()
	def, err := cueruntime.Export(context.Background(), reconCUE)
	require.NoError(t, err, "Export must succeed for the recon template")
	require.NotNil(t, def, "Export must return a non-nil MissionDefinition")
	assert.NotEmpty(t, def.GetName(), "exported MissionDefinition must have a name")
	assert.NotEmpty(t, def.GetNodes(), "exported MissionDefinition must have at least one node")
}

// TestComplete_ReturnsItems asserts that Complete returns a non-nil slice and
// does not panic, even for a trivially positioned cursor.
func TestComplete_ReturnsItems(t *testing.T) {
	t.Parallel()
	items, err := cueruntime.Complete(context.Background(), reconCUE, 1, 1)
	require.NoError(t, err, "Complete must not return an error")
	assert.NotNil(t, items, "Complete must return a non-nil slice")
}

// TestHover_ReturnsString asserts that Hover does not panic and returns
// a string (possibly empty) for a cursor positioned at line 1 col 1.
func TestHover_ReturnsString(t *testing.T) {
	t.Parallel()
	doc, err := cueruntime.Hover(context.Background(), reconCUE, 1, 1)
	require.NoError(t, err, "Hover must not return an error")
	// doc may be empty — the contract is no panic, no error.
	_ = doc
}

// TestValidate_RefusesAnUnknownTargetBinding is the gibson#495 fixture at the
// earliest point it can fail. Nothing in CUE knows what {{target.X}} means, so a
// typo compiles cleanly and the mission registers. Before this check, the only
// thing that noticed was the scan, by running against the literal text.
func TestValidate_RefusesAnUnknownTargetBinding(t *testing.T) {
	t.Parallel()
	source := strings.Replace(reconCUE, "{{target.domain}}", "{{target.hostname}}", 1)

	diags, err := cueruntime.Validate(context.Background(), source)
	require.NoError(t, err, "a bad binding is a diagnostic, not a Go error")

	var found *cueruntime.Diagnostic
	for i := range diags {
		if strings.Contains(diags[i].Message, "{{target.hostname}}") {
			found = &diags[i]
		}
	}
	require.NotNil(t, found, "no diagnostic named the unknown binding: %+v", diags)
	assert.Equal(t, "error", found.Severity)
	assert.Positive(t, found.Line, "the author needs the line")
	assert.Positive(t, found.Col, "and the column")
	assert.Contains(t, found.Message, "{{target.domain}}", "the message lists the vocabulary")
}

// The vocabulary itself must pass, or the check would refuse every real mission.
func TestValidate_AcceptsEveryTargetBinding(t *testing.T) {
	t.Parallel()
	for _, name := range targetbind.Names() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			source := strings.Replace(reconCUE, "{{target.domain}}", "{{"+name+"}}", 1)
			diags, err := cueruntime.Validate(context.Background(), source)
			require.NoError(t, err)
			for _, d := range diags {
				assert.NotContains(t, d.Message, "names no target field", "%s was refused", name)
			}
		})
	}
}

// A placeholder in another namespace is somebody else's to resolve. Refusing it
// here would make adding one a breaking change.
func TestValidate_LeavesAnotherNamespaceAlone(t *testing.T) {
	t.Parallel()
	source := strings.Replace(reconCUE, "{{target.domain}}", "{{var.ref}}", 1)
	diags, err := cueruntime.Validate(context.Background(), source)
	require.NoError(t, err)
	for _, d := range diags {
		assert.NotContains(t, d.Message, "names no target field")
	}
}
