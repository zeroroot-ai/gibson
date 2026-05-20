package discovery_test

// validate_test.go — first behavior test for the discovery RPC handlers.
//
// First tracer-bullet of issue #56 (epic Epic: tdd-coverage-gibson-sdk).
// internal/api/ had zero test files prior to this; the goal here is one
// vertical slice through ValidateComponent's public surface, establishing
// the pattern. Follow-up branches will cover the remaining ValidateComponent
// branches (parse error, missing name, kind validation, permissions YAML
// access errors) as separate tracer-bullet tests in this same file.

import (
	"context"
	"strings"
	"testing"

	discoverypb "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/discovery/v1"

	"github.com/zero-day-ai/gibson/internal/api/discovery"
)

// TestValidateComponent_EmptyComponentYaml_ReportsRequiredSchemaError asserts
// the documented behaviour: a ValidateComponent call with an empty
// component_yaml comes back with Ok=false and a single schema error pointing
// at component_yaml. This is the canonical "schema-only" branch that does not
// reach FGA or the component registry, so the server can be constructed
// without those collaborators.
func TestValidateComponent_EmptyComponentYaml_ReportsRequiredSchemaError(t *testing.T) {
	srv := discovery.NewServer(nil /*authorizer*/, nil /*registry*/, nil /*logger*/)

	resp, err := srv.ValidateComponent(context.Background(), &discoverypb.ValidateComponentRequest{})
	if err != nil {
		t.Fatalf("ValidateComponent returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("ValidateComponent returned nil response")
	}
	if resp.Ok {
		t.Errorf("expected Ok=false on empty component_yaml, got true")
	}
	if got := len(resp.SchemaErrors); got != 1 {
		t.Fatalf("expected exactly 1 schema error, got %d: %+v", got, resp.SchemaErrors)
	}
	se := resp.SchemaErrors[0]
	if se.Path != "component_yaml" {
		t.Errorf("schema error path = %q, want %q", se.Path, "component_yaml")
	}
	if !strings.Contains(se.Message, "component.yaml is required") {
		t.Errorf("schema error message = %q, want it to contain %q", se.Message, "component.yaml is required")
	}

	// Sanity: no other error buckets should be populated for this path.
	if len(resp.AccessErrors) != 0 {
		t.Errorf("expected zero access errors on schema-only path, got %d", len(resp.AccessErrors))
	}
	if len(resp.SlotErrors) != 0 {
		t.Errorf("expected zero slot errors on schema-only path, got %d", len(resp.SlotErrors))
	}
	if len(resp.ProtoViolations) != 0 {
		t.Errorf("expected zero proto violations on schema-only path, got %d", len(resp.ProtoViolations))
	}
}
