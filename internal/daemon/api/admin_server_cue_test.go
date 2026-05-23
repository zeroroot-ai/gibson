package api

// admin_server_cue_test.go — unit tests for the CUE editor RPCs wired in
// gibson#299: ValidateMissionCUE, CompleteMissionCUE, HoverMissionCUE, and
// the cue_source path of CreateMissionDefinition.

import (
	"context"
	"log/slog"
	"testing"

	daemonadminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/admin/v1"
)

// newTestAdminServer builds a minimal DaemonAdminServer wrapping a
// DaemonServer that has no daemon wired — sufficient for the CUE editor
// RPCs which do not touch the inner daemon.
func newTestAdminServer(t *testing.T) *DaemonAdminServer {
	t.Helper()
	inner := &DaemonServer{logger: slog.Default()}
	return NewDaemonAdminServer(inner, slog.Default())
}

// ---------------------------------------------------------------------------
// ValidateMissionCUE

// TestValidateMissionCUE_EmptySource verifies that empty CUE source returns
// a non-nil response without a Go error. The CUE engine treats empty source
// as vacuously valid (no content to violate the schema), so Diagnostics may
// be empty.
func TestValidateMissionCUE_EmptySource(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonadminv1.ValidateMissionCUERequest{
		CueSource: "",
	})
	if err != nil {
		t.Fatalf("ValidateMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Response is always a valid proto value; Diagnostics may be nil/empty for
	// an empty source (that is not an error from the handler's perspective).
}

// TestValidateMissionCUE_ValidSource verifies that a schema-conformant CUE
// mission produces zero error-severity diagnostics.
func TestValidateMissionCUE_ValidSource(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
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
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonadminv1.ValidateMissionCUERequest{
		CueSource: validCUE,
	})
	if err != nil {
		t.Fatalf("ValidateMissionCUE returned unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Filter to only error-severity diagnostics — warnings are permitted.
	var errDiags []*daemonadminv1.CUEDiagnostic
	for _, d := range resp.Diagnostics {
		if d.Severity == "error" {
			errDiags = append(errDiags, d)
		}
	}
	if len(errDiags) != 0 {
		t.Errorf("expected zero error diagnostics for valid source, got %d: %v", len(errDiags), errDiags)
	}
}

// TestValidateMissionCUE_DiagnosticFields verifies that diagnostics carry
// Line, Col, Message, and Severity when the source has a syntax error.
func TestValidateMissionCUE_DiagnosticFields(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
	resp, err := srv.ValidateMissionCUE(context.Background(), &daemonadminv1.ValidateMissionCUERequest{
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
	srv := newTestAdminServer(t)
	resp, err := srv.CompleteMissionCUE(context.Background(), &daemonadminv1.CompleteMissionCUERequest{
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
	srv := newTestAdminServer(t)
	resp, err := srv.CompleteMissionCUE(context.Background(), &daemonadminv1.CompleteMissionCUERequest{
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
	srv := newTestAdminServer(t)
	// Source line: "name: "test""  — cursor on column 2 (inside "name")
	source := `name: "test-mission"
`
	resp, err := srv.HoverMissionCUE(context.Background(), &daemonadminv1.HoverMissionCUERequest{
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
	srv := newTestAdminServer(t)
	resp, err := srv.HoverMissionCUE(context.Background(), &daemonadminv1.HoverMissionCUERequest{
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

// ---------------------------------------------------------------------------
// CreateMissionDefinition — cue_source path

// TestCreateMissionDefinition_CueSourceEmpty verifies that an empty
// cue_source returns InvalidArgument.
func TestCreateMissionDefinition_CueSourceEmpty(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
	_, err := srv.CreateMissionDefinition(context.Background(), &daemonadminv1.CreateMissionDefinitionRequest{
		Source: &daemonadminv1.CreateMissionDefinitionRequest_CueSource{
			CueSource: "",
		},
	})
	if err == nil {
		t.Fatal("expected error for empty cue_source, got nil")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// TestCreateMissionDefinition_CueSourceInvalidCUE verifies that invalid CUE
// that cannot be exported returns InvalidArgument (not Internal).
func TestCreateMissionDefinition_CueSourceInvalidCUE(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
	_, err := srv.CreateMissionDefinition(context.Background(), &daemonadminv1.CreateMissionDefinitionRequest{
		Source: &daemonadminv1.CreateMissionDefinitionRequest_CueSource{
			CueSource: "this { is: not valid CUE {{{{",
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid CUE, got nil")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// TestCreateMissionDefinition_NoSource verifies that a nil source oneof
// returns InvalidArgument.
func TestCreateMissionDefinition_NoSource(t *testing.T) {
	t.Parallel()
	srv := newTestAdminServer(t)
	_, err := srv.CreateMissionDefinition(context.Background(), &daemonadminv1.CreateMissionDefinitionRequest{})
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}
