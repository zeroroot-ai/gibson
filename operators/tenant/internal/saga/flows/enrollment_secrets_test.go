// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

// Tests for the per-principal-kind FGA secret-grant behaviour introduced in
// spec secrets-broker Phase 8 Task 22.
//
// Per requirements 8.3 and 8.4:
//   - kind=PLUGIN  → exactly one can_resolve tuple written for the tenant secrets object
//   - kind=AGENT   → zero can_resolve tuples written
//   - kind=TOOL    → zero can_resolve tuples written
//   - Idempotent re-run → ErrAlreadyExists is treated as success, no duplicate writes

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// ---------------------------------------------------------------------------
// stubFGA — minimal FGA client that records Write calls
// ---------------------------------------------------------------------------

type stubFGA struct {
	written  []fga.Tuple
	writeErr error
}

func (s *stubFGA) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}
func (s *stubFGA) Delete(_ context.Context, _ []fga.Tuple) error            { return nil }
func (s *stubFGA) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) { return nil, nil }
func (s *stubFGA) Check(_ context.Context, _, _, _ string) (bool, error)    { return false, nil }
func (s *stubFGA) Ping(_ context.Context) error                             { return nil }

func (s *stubFGA) canResolveTupleCount() int {
	count := 0
	for _, t := range s.written {
		if t.Relation == "can_resolve" {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeEnrollment builds an AgentEnrollment for use in tests.
func makeEnrollment(uid types.UID, namespace string, kind gibsonv1alpha1.PrincipalKind) *gibsonv1alpha1.AgentEnrollment {
	return &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-enrollment",
			Namespace: namespace,
			UID:       uid,
		},
		Spec: gibsonv1alpha1.AgentEnrollmentSpec{
			AgentName:     "test-agent",
			Mode:          gibsonv1alpha1.AgentModeAutonomous,
			PrincipalKind: kind,
		},
	}
}

// runSecretGrantStep runs only the WriteSecretResolveGrantFGA step from
// EnrollmentIssuanceSteps with the given enrollment and FGA stub.
func runSecretGrantStep(t *testing.T, ae *gibsonv1alpha1.AgentEnrollment, stub fga.Client) error {
	t.Helper()
	deps := EnrollmentDeps{FGA: stub}
	steps := EnrollmentIssuanceSteps(deps)
	// The secret grant step is the second step (index 1).
	if len(steps) < 2 {
		t.Fatalf("expected at least 2 issuance steps, got %d", len(steps))
	}
	secretStep := steps[1]
	if secretStep.Name() != "WriteSecretResolveGrantFGA" {
		t.Fatalf("expected WriteSecretResolveGrantFGA at index 1, got %q", secretStep.Name())
	}
	// Check skip predicate.
	if secretStep.Skip(ae) {
		// Step is skipped for this principal kind.
		return nil
	}
	ctx := context.Background()
	_, err := secretStep.Provision(ctx, ae, nil)
	return err
}

// ---------------------------------------------------------------------------
// Tests: per-principal-kind behaviour
// ---------------------------------------------------------------------------

// TestSecretGrantStep_Plugin_WritesExactlyOneTuple verifies that a plugin
// principal enrollment causes exactly one can_resolve tuple to be written.
func TestSecretGrantStep_Plugin_WritesExactlyOneTuple(t *testing.T) {
	stub := &stubFGA{}
	ae := makeEnrollment("uid-plugin-1", "tenant-acme", gibsonv1alpha1.PrincipalKindPlugin)

	if err := runSecretGrantStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := stub.canResolveTupleCount()
	if count != 1 {
		t.Fatalf("expected 1 can_resolve tuple for plugin principal, got %d", count)
	}
	want := fmt.Sprintf("plugin_principal:enrollment-%s", ae.UID)
	if stub.written[0].User != want {
		t.Errorf("tuple User = %q, want %q", stub.written[0].User, want)
	}
	if stub.written[0].Object != "secret:tenant-tenant-acme:*" {
		t.Errorf("tuple Object = %q, want %q", stub.written[0].Object, "secret:tenant-tenant-acme:*")
	}
}

// TestSecretGrantStep_Agent_WritesZeroTuples verifies that an agent principal
// enrollment writes no can_resolve tuples.
func TestSecretGrantStep_Agent_WritesZeroTuples(t *testing.T) {
	stub := &stubFGA{}
	ae := makeEnrollment("uid-agent-1", "tenant-acme", gibsonv1alpha1.PrincipalKindAgent)

	if err := runSecretGrantStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canResolveTupleCount() != 0 {
		t.Fatalf("expected 0 can_resolve tuples for agent principal, got %d; tuples: %+v",
			stub.canResolveTupleCount(), stub.written)
	}
}

// TestSecretGrantStep_AgentDefault_WritesZeroTuples verifies that an enrollment
// with no PrincipalKind set (legacy default) also writes no can_resolve tuples.
func TestSecretGrantStep_AgentDefault_WritesZeroTuples(t *testing.T) {
	stub := &stubFGA{}
	ae := makeEnrollment("uid-agent-2", "tenant-acme", "") // empty = legacy agent

	if err := runSecretGrantStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canResolveTupleCount() != 0 {
		t.Fatalf("expected 0 can_resolve tuples for default (empty) principal kind, got %d; tuples: %+v",
			stub.canResolveTupleCount(), stub.written)
	}
}

// TestSecretGrantStep_Tool_WritesZeroTuples verifies that a tool principal
// enrollment writes no can_resolve tuples.
func TestSecretGrantStep_Tool_WritesZeroTuples(t *testing.T) {
	stub := &stubFGA{}
	ae := makeEnrollment("uid-tool-1", "tenant-acme", gibsonv1alpha1.PrincipalKindTool)

	if err := runSecretGrantStep(t, ae, stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stub.canResolveTupleCount() != 0 {
		t.Fatalf("expected 0 can_resolve tuples for tool principal, got %d; tuples: %+v",
			stub.canResolveTupleCount(), stub.written)
	}
}

// TestSecretGrantStep_Plugin_Idempotent_AlreadyExists verifies that a second
// run for an already-provisioned plugin principal returns no error.
func TestSecretGrantStep_Plugin_Idempotent_AlreadyExists(t *testing.T) {
	stub := &stubFGA{
		writeErr: fmt.Errorf("duplicate: %w", clients.ErrAlreadyExists),
	}
	ae := makeEnrollment("uid-plugin-2", "tenant-beta", gibsonv1alpha1.PrincipalKindPlugin)

	if err := runSecretGrantStep(t, ae, stub); err != nil {
		t.Fatalf("expected nil error for already-existing tuple, got: %v", err)
	}
}

// TestSecretGrantStep_Plugin_PropagatesTransientError verifies that a transient
// FGA error is surfaced to the caller (so the saga runner requeues).
func TestSecretGrantStep_Plugin_PropagatesTransientError(t *testing.T) {
	stub := &stubFGA{
		writeErr: fmt.Errorf("unavailable: %w", clients.ErrUnreachable),
	}
	ae := makeEnrollment("uid-plugin-3", "tenant-gamma", gibsonv1alpha1.PrincipalKindPlugin)

	err := runSecretGrantStep(t, ae, stub)
	if err == nil {
		t.Fatal("expected error for transient FGA failure, got nil")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Errorf("expected ErrUnreachable in error chain, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: agentPrincipal kind-awareness
// ---------------------------------------------------------------------------

func TestAgentPrincipal_KindAwareness(t *testing.T) {
	cases := []struct {
		kind    gibsonv1alpha1.PrincipalKind
		wantPfx string
	}{
		{gibsonv1alpha1.PrincipalKindAgent, "agent_principal:"},
		{gibsonv1alpha1.PrincipalKindTool, "tool_principal:"},
		{gibsonv1alpha1.PrincipalKindPlugin, "plugin_principal:"},
		{"", "agent_principal:"}, // empty = legacy default
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			ae := makeEnrollment("uid-test", "ns", tc.kind)
			got := agentPrincipal(ae)
			if len(got) < len(tc.wantPfx) || got[:len(tc.wantPfx)] != tc.wantPfx {
				t.Errorf("agentPrincipal with kind=%q = %q, want prefix %q", tc.kind, got, tc.wantPfx)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: skipNonPluginPrincipal predicate
// ---------------------------------------------------------------------------

func TestSkipNonPluginPrincipal(t *testing.T) {
	cases := []struct {
		kind     gibsonv1alpha1.PrincipalKind
		wantSkip bool
	}{
		{gibsonv1alpha1.PrincipalKindPlugin, false}, // plugin = do NOT skip
		{gibsonv1alpha1.PrincipalKindAgent, true},   // agent = skip
		{gibsonv1alpha1.PrincipalKindTool, true},    // tool = skip
		{"", true},                                  // empty/legacy = skip
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			ae := makeEnrollment("uid-skip-test", "ns", tc.kind)
			got := skipNonPluginPrincipal(ae)
			if got != tc.wantSkip {
				t.Errorf("skipNonPluginPrincipal(%q) = %v, want %v", tc.kind, got, tc.wantSkip)
			}
		})
	}
	t.Run("wrong_type_returns_true", func(t *testing.T) {
		// Non-AgentEnrollment type should be skipped safely.
		var wrongType saga.ConditionedObject = &gibsonv1alpha1.Tenant{}
		if !skipNonPluginPrincipal(wrongType) {
			t.Error("expected skipNonPluginPrincipal to return true for non-AgentEnrollment")
		}
	})
}
