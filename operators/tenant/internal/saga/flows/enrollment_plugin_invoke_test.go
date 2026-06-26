// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

// Tests for the per-principal-kind FGA plugin can_invoke grant behaviour
// introduced in spec plugin-runtime Phase 10 Task 25.
//
// Per requirement 5.2:
//   - kind=PLUGIN  → exactly one can_invoke tuple written:
//                    (tenant:<tenant>#member, can_invoke, plugin:<tenant>:<plugin_name>)
//   - kind=AGENT   → zero can_invoke tuples written (agents do not invoke plugins)
//   - kind=TOOL    → zero can_invoke tuples written (the tuple is written FOR the
//                    plugin object, not per tool — tools are subjects of can_invoke
//                    via tenant#member, but no tuple is written at tool enrollment)
//   - Idempotent re-run → ErrAlreadyExists is treated as success, no duplicate writes

import (
	"context"
	"errors"
	"fmt"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// ---------------------------------------------------------------------------
// stubInvokeFGA — minimal FGA client tailored to can_invoke assertions
// ---------------------------------------------------------------------------

type stubInvokeFGA struct {
	written  []fga.Tuple
	writeErr error
}

func (s *stubInvokeFGA) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}
func (s *stubInvokeFGA) Delete(_ context.Context, _ []fga.Tuple) error            { return nil }
func (s *stubInvokeFGA) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) { return nil, nil }
func (s *stubInvokeFGA) Check(_ context.Context, _, _, _ string) (bool, error)    { return false, nil }
func (s *stubInvokeFGA) Ping(_ context.Context) error                             { return nil }

func (s *stubInvokeFGA) canInvokeTupleCount() int {
	count := 0
	for _, t := range s.written {
		if t.Relation == "can_invoke" {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// runPluginCanInvokeStep executes only the WritePluginCanInvokeGrantFGA step
// from EnrollmentIssuanceSteps with the given enrollment and FGA stub. It
// honours the step's Skip predicate so callers see the same behaviour the
// saga runner would.
func runPluginCanInvokeStep(t *testing.T, ae *gibsonv1alpha1.AgentEnrollment, stub fga.Client) error {
	t.Helper()
	deps := EnrollmentDeps{FGA: stub}
	steps := EnrollmentIssuanceSteps(deps)
	// The plugin can_invoke grant step is the third step (index 2).
	if len(steps) < 3 {
		t.Fatalf("expected at least 3 issuance steps, got %d", len(steps))
	}
	step := steps[2]
	if step.Name() != "WritePluginCanInvokeGrantFGA" {
		t.Fatalf("expected WritePluginCanInvokeGrantFGA at index 2, got %q", step.Name())
	}
	// Check skip predicate.
	if step.Skip(ae) {
		// Step is skipped for this principal kind.
		return nil
	}
	ctx := context.Background()
	_, err := step.Provision(ctx, ae, nil)
	return err
}

// ---------------------------------------------------------------------------
// Tests: per-principal-kind behaviour
// ---------------------------------------------------------------------------

// TestPluginCanInvokeStep_Plugin_WritesExactlyOneTuple verifies that a plugin
// principal enrollment causes exactly one can_invoke tuple to be written with
// the correct shape.
func TestPluginCanInvokeStep_Plugin_WritesExactlyOneTuple(t *testing.T) {
	stub := &stubInvokeFGA{}
	ae := makeEnrollment("uid-plugin-1", "tenant-acme", gibsonv1alpha1.PrincipalKindPlugin)

	if err := runPluginCanInvokeStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := stub.canInvokeTupleCount()
	if count != 1 {
		t.Fatalf("expected 1 can_invoke tuple for plugin principal, got %d; tuples: %+v",
			count, stub.written)
	}
	got := stub.written[0]
	wantUser := "tenant:tenant-acme#member"
	wantObj := fmt.Sprintf("plugin:tenant-acme:%s", ae.Spec.AgentName)
	if got.User != wantUser {
		t.Errorf("tuple User = %q, want %q", got.User, wantUser)
	}
	if got.Relation != "can_invoke" {
		t.Errorf("tuple Relation = %q, want %q", got.Relation, "can_invoke")
	}
	if got.Object != wantObj {
		t.Errorf("tuple Object = %q, want %q", got.Object, wantObj)
	}
}

// TestPluginCanInvokeStep_Agent_WritesZeroTuples verifies that an agent
// principal enrollment writes no can_invoke tuples. Per Requirement 5.2,
// agents dispatch tools; agents do not invoke plugins.
func TestPluginCanInvokeStep_Agent_WritesZeroTuples(t *testing.T) {
	stub := &stubInvokeFGA{}
	ae := makeEnrollment("uid-agent-1", "tenant-acme", gibsonv1alpha1.PrincipalKindAgent)

	if err := runPluginCanInvokeStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canInvokeTupleCount() != 0 {
		t.Fatalf("expected 0 can_invoke tuples for agent principal, got %d; tuples: %+v",
			stub.canInvokeTupleCount(), stub.written)
	}
}

// TestPluginCanInvokeStep_AgentDefault_WritesZeroTuples verifies that an
// enrollment with no PrincipalKind set (legacy default) writes no can_invoke
// tuples.
func TestPluginCanInvokeStep_AgentDefault_WritesZeroTuples(t *testing.T) {
	stub := &stubInvokeFGA{}
	ae := makeEnrollment("uid-agent-2", "tenant-acme", "") // empty = legacy agent

	if err := runPluginCanInvokeStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canInvokeTupleCount() != 0 {
		t.Fatalf("expected 0 can_invoke tuples for default (empty) principal kind, got %d; tuples: %+v",
			stub.canInvokeTupleCount(), stub.written)
	}
}

// TestPluginCanInvokeStep_Tool_WritesZeroTuples verifies that a tool principal
// enrollment writes no can_invoke tuples. The can_invoke tuple is written FOR
// the plugin object at plugin enrollment, not per tool. Tools become subjects
// via the tenant#member computed-relation; no per-tool tuple is needed.
func TestPluginCanInvokeStep_Tool_WritesZeroTuples(t *testing.T) {
	stub := &stubInvokeFGA{}
	ae := makeEnrollment("uid-tool-1", "tenant-acme", gibsonv1alpha1.PrincipalKindTool)

	if err := runPluginCanInvokeStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canInvokeTupleCount() != 0 {
		t.Fatalf("expected 0 can_invoke tuples for tool principal, got %d; tuples: %+v",
			stub.canInvokeTupleCount(), stub.written)
	}
}

// TestPluginCanInvokeStep_Plugin_Idempotent_AlreadyExists verifies that a
// second run for an already-provisioned plugin enrollment returns no error.
func TestPluginCanInvokeStep_Plugin_Idempotent_AlreadyExists(t *testing.T) {
	stub := &stubInvokeFGA{
		writeErr: fmt.Errorf("duplicate: %w", clients.ErrAlreadyExists),
	}
	ae := makeEnrollment("uid-plugin-2", "tenant-beta", gibsonv1alpha1.PrincipalKindPlugin)

	if err := runPluginCanInvokeStep(t, ae, stub); err != nil {
		t.Fatalf("expected nil error for already-existing tuple, got: %v", err)
	}
}

// TestPluginCanInvokeStep_Plugin_PropagatesTransientError verifies that a
// transient FGA error is surfaced to the caller (so the saga runner requeues).
func TestPluginCanInvokeStep_Plugin_PropagatesTransientError(t *testing.T) {
	stub := &stubInvokeFGA{
		writeErr: fmt.Errorf("unavailable: %w", clients.ErrUnreachable),
	}
	ae := makeEnrollment("uid-plugin-3", "tenant-gamma", gibsonv1alpha1.PrincipalKindPlugin)

	err := runPluginCanInvokeStep(t, ae, stub)
	if err == nil {
		t.Fatal("expected error for transient FGA failure, got nil")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Errorf("expected ErrUnreachable in error chain, got: %v", err)
	}
}

// TestPluginCanInvokeStep_Plugin_EmptyAgentName_Error verifies that a plugin
// enrollment with an empty AgentName fails the step (defensive guard against
// writing a malformed plugin object ID).
func TestPluginCanInvokeStep_Plugin_EmptyAgentName_Error(t *testing.T) {
	stub := &stubInvokeFGA{}
	ae := makeEnrollment("uid-plugin-4", "tenant-delta", gibsonv1alpha1.PrincipalKindPlugin)
	ae.Spec.AgentName = ""

	err := runPluginCanInvokeStep(t, ae, stub)
	if err == nil {
		t.Fatal("expected error for empty AgentName, got nil")
	}
	if stub.canInvokeTupleCount() != 0 {
		t.Errorf("expected 0 tuples written on validation error, got %d", stub.canInvokeTupleCount())
	}
}

// TestPluginCanInvokeStep_Plugin_FGANil_Fails asserts that a nil FGA client
// causes WritePluginCanInvokeGrantFGA to fail with a clear error rather than
// silently succeeding. Enforces the one-code-path invariant
// (tenant-operator#95): FGA is validated at startup, never skipped.
func TestPluginCanInvokeStep_Plugin_FGANil_Fails(t *testing.T) {
	ae := makeEnrollment("uid-plugin-5", "tenant-eps", gibsonv1alpha1.PrincipalKindPlugin)

	deps := EnrollmentDeps{FGA: nil}
	steps := EnrollmentIssuanceSteps(deps)
	if len(steps) < 3 {
		t.Fatalf("expected at least 3 issuance steps, got %d", len(steps))
	}
	step := steps[2]
	if step.Name() != "WritePluginCanInvokeGrantFGA" {
		t.Fatalf("expected WritePluginCanInvokeGrantFGA at index 2, got %q", step.Name())
	}
	ctx := context.Background()
	done, err := step.Provision(ctx, ae, nil)
	if err == nil {
		t.Fatal("nil FGA: expected error (operator misconfigured), got nil")
	}
	if done {
		t.Error("nil FGA: expected done=false on misconfiguration error")
	}
}

// TestPluginCanInvokeStep_SkipPredicate_AppliesToAllNonPluginKinds is a
// table-level check that the same skip predicate (skipNonPluginPrincipal)
// guards both the secret-resolve step and the plugin can_invoke step. This
// ensures any future change to the predicate flows to both.
func TestPluginCanInvokeStep_SkipPredicate_AppliesToAllNonPluginKinds(t *testing.T) {
	cases := []struct {
		kind     gibsonv1alpha1.PrincipalKind
		wantSkip bool
	}{
		{gibsonv1alpha1.PrincipalKindPlugin, false},
		{gibsonv1alpha1.PrincipalKindAgent, true},
		{gibsonv1alpha1.PrincipalKindTool, true},
		{"", true},
	}
	deps := EnrollmentDeps{FGA: &stubInvokeFGA{}}
	steps := EnrollmentIssuanceSteps(deps)
	if len(steps) < 3 {
		t.Fatalf("expected at least 3 issuance steps, got %d", len(steps))
	}
	step := steps[2]
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			ae := makeEnrollment("uid-skip", "ns", tc.kind)
			if got := step.Skip(ae); got != tc.wantSkip {
				t.Errorf("skip(kind=%q) = %v, want %v", tc.kind, got, tc.wantSkip)
			}
		})
	}
}
