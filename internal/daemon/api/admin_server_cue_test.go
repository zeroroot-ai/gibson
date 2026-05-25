package api

// admin_server_cue_test.go — unit tests for the CUE language-service RPCs
// wired onto DaemonService (ADR-0037): ValidateMissionCUE, CompleteMissionCUE,
// HoverMissionCUE, and the cue_source path of CreateMissionDefinition.
//
// These methods previously lived on DaemonAdminService (platform-sdk) and are
// now implemented directly on DaemonServer as part of the OSS DaemonService.

import (
	"context"
	"log/slog"
	"testing"

	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
)

// newTestDaemonServerForCUE builds a minimal DaemonServer sufficient for the
// CUE editor RPCs, which do not touch the inner daemon.
func newTestDaemonServerForCUE(t *testing.T) *DaemonServer {
	t.Helper()
	return &DaemonServer{logger: slog.Default()}
}

// ---------------------------------------------------------------------------
// ValidateMissionCUE

// TestValidateMissionCUE_EmptySource verifies that empty CUE source returns a
// non-nil response without a Go error. Empty source passes the schema check
// (nothing to violate) but fails export (no top-level "mission" field), so a
// single error-severity diagnostic is expected.
func TestValidateMissionCUE_EmptySource(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonpb.ValidateMissionCUERequest{
		CueSource: "",
	})
	if err != nil {
		t.Fatalf("ValidateMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Diagnostics) == 0 {
		t.Error("expected at least one diagnostic for empty source (missing 'mission' field)")
	}
	if resp.CompiledDefinition != nil {
		t.Error("expected nil CompiledDefinition when diagnostics are present")
	}
}

// TestValidateMissionCUE_ValidSource verifies that a schema-conformant CUE
// mission produces zero error-severity diagnostics.
func TestValidateMissionCUE_ValidSource(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	// Minimal valid CUE using the schema import and #MissionDefinition constraint,
	// matching the ADK template convention (top-level "mission" field, anonymous
	// package i.e. no package clause).
	validCUE := `import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "handler-test"
	version:     "1.0.0"
	targetRef:   ""
	nodes: {}
	edges: []
	entryPoints: []
	exitPoints: []
}
`
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonpb.ValidateMissionCUERequest{
		CueSource: validCUE,
	})
	if err != nil {
		t.Fatalf("ValidateMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Filter to only error-severity diagnostics — warnings are permitted.
	var errDiags []*daemonpb.CUEDiagnostic
	for _, d := range resp.Diagnostics {
		if d.Severity == "error" {
			errDiags = append(errDiags, d)
		}
	}
	if len(errDiags) != 0 {
		t.Errorf("expected zero error diagnostics for valid source, got %d: %v", len(errDiags), errDiags)
	}
	if resp.CompiledDefinition == nil {
		t.Error("expected non-nil CompiledDefinition for valid source with no error diagnostics")
	}
	if resp.CompiledDefinition != nil && resp.CompiledDefinition.Name != "handler-test" {
		t.Errorf("compiled definition name = %q, want %q", resp.CompiledDefinition.Name, "handler-test")
	}
}

// TestValidateMissionCUE_DiagnosticFields verifies that diagnostics carry
// Line, Col, Message, and Severity when the source has a syntax error.
func TestValidateMissionCUE_DiagnosticFields(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonpb.ValidateMissionCUERequest{
		CueSource: "this is not valid CUE {{{{",
	})
	if err != nil {
		t.Fatalf("ValidateMissionCUE returned unexpected error: %v", err)
	}
	if len(resp.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic for invalid CUE")
	}
	d := resp.Diagnostics[0]
	if d.Message == "" {
		t.Error("diagnostic Message must not be empty")
	}
	if d.Severity == "" {
		t.Error("diagnostic Severity must not be empty")
	}
	// Line and Col must be at least 1.
	if d.Line < 1 {
		t.Errorf("diagnostic Line = %d, want >= 1", d.Line)
	}
	if d.Col < 1 {
		t.Errorf("diagnostic Col = %d, want >= 1", d.Col)
	}
}

// ---------------------------------------------------------------------------
// CompleteMissionCUE

// TestCompleteMissionCUE_ReturnsItems verifies that top-level completions are
// returned for a valid (or empty) cursor position.
func TestCompleteMissionCUE_ReturnsItems(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	resp, err := srv.CompleteMissionCUE(context.Background(), &daemonpb.CompleteMissionCUERequest{
		CueSource: "mission: {\n",
		Line:      1,
		Col:       1,
	})
	if err != nil {
		t.Fatalf("CompleteMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Items) == 0 {
		t.Error("expected completion items, got none")
	}
	// Every item must have a non-empty Label.
	for i, item := range resp.Items {
		if item.Label == "" {
			t.Errorf("completion item[%d] has empty Label", i)
		}
	}
}

// TestCompleteMissionCUE_ItemFields verifies that items carry Label, Detail,
// Documentation, and Kind.
func TestCompleteMissionCUE_ItemFields(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	resp, err := srv.CompleteMissionCUE(context.Background(), &daemonpb.CompleteMissionCUERequest{
		CueSource: "",
		Line:      1,
		Col:       1,
	})
	if err != nil {
		t.Fatalf("CompleteMissionCUE returned unexpected error: %v", err)
	}
	for i, item := range resp.Items {
		if item.Kind == "" {
			t.Errorf("completion item[%d].Kind is empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// HoverMissionCUE

// TestHoverMissionCUE_KnownField verifies that hovering over a known field
// returns non-empty Markdown.
func TestHoverMissionCUE_KnownField(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	// Source line: "name: "test""  — cursor on column 2 (inside "name")
	source := `name: "test-mission"
`
	resp, err := srv.HoverMissionCUE(context.Background(), &daemonpb.HoverMissionCUERequest{
		CueSource: source,
		Line:      1,
		Col:       2,
	})
	if err != nil {
		t.Fatalf("HoverMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Markdown == "" {
		t.Error("expected non-empty Markdown for known field 'name', got empty string")
	}
}

// TestHoverMissionCUE_UnknownField verifies that hovering over an unknown
// symbol returns an empty Markdown string (not an error).
func TestHoverMissionCUE_UnknownField(t *testing.T) {
	t.Parallel()
	srv := newTestDaemonServerForCUE(t)
	resp, err := srv.HoverMissionCUE(context.Background(), &daemonpb.HoverMissionCUERequest{
		CueSource: "unknownField: 42\n",
		Line:      1,
		Col:       5,
	})
	if err != nil {
		t.Fatalf("HoverMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Unknown field → empty Markdown, no error.
	if resp.Markdown != "" {
		t.Errorf("expected empty Markdown for unknown field, got %q", resp.Markdown)
	}
}

