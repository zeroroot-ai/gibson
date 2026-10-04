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
	jobv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
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

// The ADK templates take no parameters: recon and its siblings read
// {{target.domain}} and nothing else, so DeclaredParams reporting none for them
// is the real-file half of this. The synthetic cases below cover a mission that
// does declare some.
func TestDeclaredParams_TheShippedTemplatesDeclareNone(t *testing.T) {
	t.Parallel()
	for name, src := range map[string]string{
		"recon":            reconCUE,
		"webapp-scan":      webappScanCUE,
		"secrets-audit":    secretsAuditCUE,
		"compliance-check": complianceCheckCUE,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := cueruntime.DeclaredParams(src)
			require.NoError(t, err)
			assert.Empty(t, got, "%s declares no _params, so none must be reported", name)
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

// `_params` is a CUE HIDDEN field. cue.Str finds nothing and returns no error,
// which reads as "this mission takes no parameters" — so a reader that addressed
// it the wrong way would silently accept a call that supplied none. This asserts
// the field is actually found.
func TestDeclaredParams_FindsAHiddenFieldNotNothing(t *testing.T) {
	t.Parallel()
	const src = `
import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

_params: {
	alpha: string
	beta:  string
}

mission: missionv1.#MissionDefinition & {
	name: "t"
	nodes: {}
}
`
	got, err := cueruntime.DeclaredParams(src)
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "beta"}, got)

	// Sorted and unique, so the render order is stable, and unquoted, so a name
	// goes straight into a CUE key.
	assert.IsIncreasing(t, got)
	seen := map[string]bool{}
	for _, n := range got {
		assert.False(t, seen[n], "%s reported twice", n)
		seen[n] = true
		assert.NotContains(t, n, `"`, "a name arrives unquoted")
		assert.Contains(t, src, n+":", "%s is not declared in the source", n)
	}
}

// A parameter the mission marks optional is still a parameter a caller may send,
// so it is reported.
func TestDeclaredParams_IncludesAnOptionalParameter(t *testing.T) {
	t.Parallel()
	const src = `
import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

_params: {
	alpha:  string
	beta?:  string
}

mission: missionv1.#MissionDefinition & {
	name: "t"
	nodes: {}
}
`
	got, err := cueruntime.DeclaredParams(src)
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "beta"}, got)
}

// A mission whose graph is fully determined by its target takes no parameters,
// and that is not an error.
func TestDeclaredParams_NoParamsIsNotAnError(t *testing.T) {
	t.Parallel()
	const src = `
import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name: "t"
	nodes: {}
}
`
	got, err := cueruntime.DeclaredParams(src)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestDeclaredParams_SourceThatDoesNotCompileIsAnError(t *testing.T) {
	t.Parallel()
	_, err := cueruntime.DeclaredParams("mission: UNCLOSED {")
	require.Error(t, err)
}

// A mission author must be able to name a DeliverableKind. There is no other
// way to say "open a merge request", and writing the enum's number instead
// would put a magic 2 in a first-party mission.
//
// Before packageRewrites covered job/v1 this failed with
//
//	cannot find package "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1":
//	no files in package directory with package name "v1"
//
// so the daemon's own catalog could not author a JOB node at all, while the
// ADK's templates could. The two must accept the same CUE.
func TestExport_AMissionMayImportTheJobPackage(t *testing.T) {
	const src = `
import (
	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"
)

mission: missionv1.#MissionDefinition & {
	name:    "job-import"
	version: "1.0.0"
	nodes: {
		fix: {
			id:   "fix"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: "bank/core"
				spec: {
					goal: "Fix it."
					repositories: [{
						name:         "repo"
						connectorRef: "connector/forge"
						project:      "group/repo"
						deliverable:  jobv1.#DELIVERABLE_KIND_MERGE_REQUEST
					}]
				}
			}
		}
	}
	entryPoints: ["fix"]
	exitPoints: ["fix"]
}
`
	def, err := cueruntime.Export(context.Background(), src)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	repos := def.GetNodes()["fix"].GetJobConfig().GetSpec().GetRepositories()
	if len(repos) != 1 {
		t.Fatalf("repositories = %d, want 1", len(repos))
	}
	// Through protojson into the Go type, so this is a drift guard on the SDK
	// job proto as well: a renamed or retyped field fails here, not at a
	// mission author's submit.
	if got := repos[0].GetDeliverable(); got != jobv1.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST {
		t.Errorf("deliverable = %v, want MERGE_REQUEST", got)
	}
}
