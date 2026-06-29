// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package fga_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// pluginStubFGAClient is a minimal in-memory FGA stub for plugin_grants tests.
// Independent from the secrets stub to avoid cross-file coupling.
type pluginStubFGAClient struct {
	written  []fga.Tuple
	writeErr error
}

func (s *pluginStubFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}

func (s *pluginStubFGAClient) Delete(_ context.Context, _ []fga.Tuple) error { return nil }
func (s *pluginStubFGAClient) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}
func (s *pluginStubFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
func (s *pluginStubFGAClient) Ping(_ context.Context) error { return nil }

func (s *pluginStubFGAClient) tupleCount() int { return len(s.written) }

func (s *pluginStubFGAClient) hasCanInvokeTuple(pluginName, tenantID string) bool {
	want := fga.PluginCanInvokeTuple(pluginName, tenantID)
	for _, t := range s.written {
		if t.User == want.User && t.Relation == want.Relation && t.Object == want.Object {
			return true
		}
	}
	return false
}

// ---- PluginCanInvokeTuple shape tests ----

func TestPluginCanInvokeTuple_Shape(t *testing.T) {
	got := fga.PluginCanInvokeTuple("gitlab", "acme")
	if got.User != "tenant:acme#member" {
		t.Errorf("User = %q, want %q", got.User, "tenant:acme#member")
	}
	if got.Relation != "can_invoke" {
		t.Errorf("Relation = %q, want %q", got.Relation, "can_invoke")
	}
	// Object format must match `tenant_and_field('PluginName')` deriver
	// output: <object_type>:<tenant>:<field_value>
	if got.Object != "plugin:acme/gitlab" {
		t.Errorf("Object = %q, want %q", got.Object, "plugin:acme/gitlab")
	}
}

func TestPluginCanInvokeTuple_NeverGrantsAgentPrincipal(t *testing.T) {
	// Defensive shape check: no matter the inputs, the User must be a
	// tenant#member userset, never an agent_principal:* subject. agent
	// principals are barred from invoking plugins by design.
	got := fga.PluginCanInvokeTuple("any-plugin", "any-tenant")
	if got.User == "agent_principal:any" || got.User == fmt.Sprintf("agent_principal:%s", "any-tenant") {
		t.Errorf("User must never be agent_principal, got %q", got.User)
	}
	// Sanity: the prefix must be tenant:.
	if len(got.User) < len("tenant:") || got.User[:len("tenant:")] != "tenant:" {
		t.Errorf("User must start with 'tenant:', got %q", got.User)
	}
}

// ---- WritePluginCanInvokeGrant tests ----

func TestWritePluginCanInvokeGrant_WritesExactlyOneTuple(t *testing.T) {
	ctx := context.Background()
	stub := &pluginStubFGAClient{}

	if err := fga.WritePluginCanInvokeGrant(ctx, stub, "gitlab", "tenant-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.tupleCount() != 1 {
		t.Fatalf("expected 1 tuple written, got %d", stub.tupleCount())
	}
	if !stub.hasCanInvokeTuple("gitlab", "tenant-a") {
		t.Errorf("expected can_invoke tuple for gitlab / tenant-a, got: %+v", stub.written)
	}
}

func TestWritePluginCanInvokeGrant_Idempotent_AlreadyExists(t *testing.T) {
	ctx := context.Background()
	stub := &pluginStubFGAClient{
		writeErr: fmt.Errorf("fga 400: %w", clients.ErrAlreadyExists),
	}

	// Should return nil (idempotent) when tuple already exists.
	if err := fga.WritePluginCanInvokeGrant(ctx, stub, "shodan", "tenant-b"); err != nil {
		t.Fatalf("expected nil for ErrAlreadyExists, got: %v", err)
	}
}

func TestWritePluginCanInvokeGrant_PropagatesOtherErrors(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("fga 503: %w", clients.ErrUnreachable)
	stub := &pluginStubFGAClient{writeErr: wantErr}

	err := fga.WritePluginCanInvokeGrant(ctx, stub, "hackerone", "tenant-c")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Errorf("expected ErrUnreachable in chain, got: %v", err)
	}
}

// ---- BackfillPluginCanInvokeGrants tests ----

func TestBackfillPluginCanInvokeGrants_WritesMissingTuples(t *testing.T) {
	ctx := context.Background()
	stub := &pluginStubFGAClient{}

	plugins := []fga.PluginInstall{
		{PluginName: "gitlab", TenantID: "tenant-x"},
		{PluginName: "shodan", TenantID: "tenant-y"},
	}

	results := fga.BackfillPluginCanInvokeGrants(ctx, stub, plugins)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error for %s: %v", r.EnrollmentUID, r.Err)
		}
		if !r.Written {
			t.Errorf("expected Written=true for %s", r.EnrollmentUID)
		}
	}
	if stub.tupleCount() != 2 {
		t.Fatalf("expected 2 tuples written, got %d", stub.tupleCount())
	}
	if !stub.hasCanInvokeTuple("gitlab", "tenant-x") {
		t.Error("missing tuple for gitlab/tenant-x")
	}
	if !stub.hasCanInvokeTuple("shodan", "tenant-y") {
		t.Error("missing tuple for shodan/tenant-y")
	}
}

func TestBackfillPluginCanInvokeGrants_Idempotent_NoError(t *testing.T) {
	ctx := context.Background()
	// Simulate all tuples already existing.
	stub := &pluginStubFGAClient{
		writeErr: fmt.Errorf("conflict: %w", clients.ErrAlreadyExists),
	}

	plugins := []fga.PluginInstall{
		{PluginName: "gitlab", TenantID: "tenant-x"},
		{PluginName: "shodan", TenantID: "tenant-y"},
	}

	results := fga.BackfillPluginCanInvokeGrants(ctx, stub, plugins)
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("expected nil error for already-existing tuple, got: %v", r.Err)
		}
		if r.Written {
			t.Errorf("expected Written=false for already-existing tuple %s", r.EnrollmentUID)
		}
	}
}

func TestBackfillPluginCanInvokeGrants_Empty(t *testing.T) {
	ctx := context.Background()
	stub := &pluginStubFGAClient{}
	results := fga.BackfillPluginCanInvokeGrants(ctx, stub, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil input, got %d", len(results))
	}
	if stub.tupleCount() != 0 {
		t.Errorf("expected 0 tuples written for nil input, got %d", stub.tupleCount())
	}
}
