// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// recordingAuthorizer records the tuples Write is called with and answers
// ListUsers from a configurable owner set (for dynamic owner resolution).
type recordingAuthorizer struct {
	written  []authz.Tuple
	writeErr error
	// owners is what ListUsers returns (e.g. []string{"user:u1"}); listUsersErr
	// forces an error. gotListUsers captures the last ListUsers args.
	owners       []string
	listUsersErr error
	gotListUsers [3]string
}

func (r *recordingAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (r *recordingAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}

func (r *recordingAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.written = append(r.written, tuples...)
	return nil
}

func (r *recordingAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }

func (r *recordingAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (r *recordingAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	r.gotListUsers = [3]string{objectType, object, relation}
	return r.owners, r.listUsersErr
}

func (r *recordingAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}

func (r *recordingAuthorizer) StoreID() string { return "" }
func (r *recordingAuthorizer) ModelID() string { return "" }
func (r *recordingAuthorizer) Close() error    { return nil }

// TestClientCapabilityGrants pins the kind->grant policy table (ADR-0046,
// ADR-0066): agents/tools get the drive grant (direct_execute), a plugin gets
// the receive grant (direct_receive_work) and NOT direct_execute, and any other
// kind gets nothing.
func TestClientCapabilityGrants(t *testing.T) {
	exec := authz.Tuple{User: "p", Relation: "direct_execute", Object: "component:_system"}
	recv := authz.Tuple{User: "p", Relation: "direct_receive_work", Object: "component:_system"}
	cases := map[string][]authz.Tuple{
		"agent_principal":  {exec},
		"tool_principal":   {exec},
		"plugin_principal": {recv},
		"user":             nil,
		"":                 nil,
	}
	for kind, want := range cases {
		got := ClientCapabilityGrants("p", kind)
		if len(got) != len(want) {
			t.Errorf("%q: got %v, want %v", kind, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q grant[%d] = %+v, want %+v", kind, i, got[i], want[i])
			}
		}
	}
}

// TestIsSingleUseCredential pins which enrollment credentials are one-time
// (consumed) versus re-presentable (ADR-0066).
func TestIsSingleUseCredential(t *testing.T) {
	cases := map[string]bool{
		hostReRegistrationBootstrapType: false, // host key: proof of possession, re-usable
		BootstrapTypeSPIFFESVID:         false, // SVID: re-fetched every start
		bootstrapTokenType:              true,  // bootstrap token: one-time
		"":                              true,  // unknown: treated one-time (fail safe)
		"something-else":                true,
	}
	for typ, want := range cases {
		if got := isSingleUseCredential(typ); got != want {
			t.Errorf("isSingleUseCredential(%q) = %v, want %v", typ, got, want)
		}
	}
}

// TestProvisionPluginPrincipal asserts the exact FGA identity a first-party
// plugin is provisioned with — including that the owner is RESOLVED from the
// tenant (not supplied), and that it is NEVER granted direct_execute (which
// would let it drive the platform; ADR-0066).
func TestProvisionPluginPrincipal(t *testing.T) {
	rec := &recordingAuthorizer{owners: []string{"user:u1"}}
	s := &CapabilityGrantService{authorizer: rec}

	ref, owner, err := s.ProvisionPluginPrincipal(context.Background(), "github", "acme")
	if err != nil {
		t.Fatalf("ProvisionPluginPrincipal: %v", err)
	}
	if ref != "plugin_principal:github" {
		t.Fatalf("principalRef = %q, want plugin_principal:github", ref)
	}
	if owner != "u1" {
		t.Errorf("resolved owner = %q, want u1 (from ListUsers, prefix stripped)", owner)
	}
	// The owner was resolved by querying the tenant's owner relation.
	if rec.gotListUsers != [3]string{"tenant", "tenant:acme", "owner"} {
		t.Errorf("ListUsers queried %v, want [tenant tenant:acme owner]", rec.gotListUsers)
	}

	want := []authz.Tuple{
		{User: "user:u1", Relation: "owner", Object: "plugin_principal:github"},
		{User: "tenant:acme", Relation: "belongs_to", Object: "plugin_principal:github"},
		{User: "plugin_principal:github", Relation: "member", Object: "tenant:acme"},
		{User: "plugin_principal:github", Relation: "direct_receive_work", Object: "component:_system"},
	}
	if len(rec.written) != len(want) {
		t.Fatalf("wrote %d tuples, want %d: %+v", len(rec.written), len(want), rec.written)
	}
	for i := range want {
		if rec.written[i] != want[i] {
			t.Errorf("tuple[%d] = %+v, want %+v", i, rec.written[i], want[i])
		}
	}
	for _, tp := range rec.written {
		if tp.Relation == "direct_execute" {
			t.Errorf("plugin granted direct_execute %+v — a drive privilege it must NOT hold (ADR-0066)", tp)
		}
	}
}

// TestProvisionPluginPrincipal_MultipleOwners: a tenant with >1 owner resolves
// to the lexicographically-first, deterministically (stable across re-enrols).
func TestProvisionPluginPrincipal_MultipleOwners(t *testing.T) {
	rec := &recordingAuthorizer{owners: []string{"user:zeb", "user:amy"}}
	s := &CapabilityGrantService{authorizer: rec, logger: slog.Default()}
	_, owner, err := s.ProvisionPluginPrincipal(context.Background(), "github", "acme")
	if err != nil {
		t.Fatalf("ProvisionPluginPrincipal: %v", err)
	}
	if owner != "amy" {
		t.Errorf("resolved owner = %q, want amy (lexicographically first)", owner)
	}
}

// TestProvisionPluginPrincipal_NoOwnerYet: zero owners is a RETRYABLE error
// (first-admin has not provisioned the owner yet), NOT a provisioned principal.
func TestProvisionPluginPrincipal_NoOwnerYet(t *testing.T) {
	rec := &recordingAuthorizer{owners: nil}
	s := &CapabilityGrantService{authorizer: rec}
	if _, _, err := s.ProvisionPluginPrincipal(context.Background(), "github", "acme"); err == nil {
		t.Error("no owner should error (retryable), not provision a principal")
	}
	if len(rec.written) != 0 {
		t.Errorf("no tuples should be written when the owner is unresolved: %+v", rec.written)
	}
}

// TestProvisionPluginPrincipal_Validation rejects an empty vendor, an unset
// tenant, or a nil authorizer rather than provisioning a malformed principal.
func TestProvisionPluginPrincipal_Validation(t *testing.T) {
	ctx := context.Background()
	s := &CapabilityGrantService{authorizer: &recordingAuthorizer{owners: []string{"user:u1"}}}
	if _, _, err := s.ProvisionPluginPrincipal(ctx, "  ", "t"); err == nil {
		t.Error("empty vendor should error")
	}
	if _, _, err := s.ProvisionPluginPrincipal(ctx, "github", ""); err == nil {
		t.Error("empty tenant should error")
	}
	// A nil authorizer cannot resolve the owner or write — must error, not
	// silently provision.
	sNil := &CapabilityGrantService{authorizer: nil}
	if _, _, err := sNil.ProvisionPluginPrincipal(ctx, "github", "t"); err == nil {
		t.Error("nil authorizer should error")
	}
}

// TestProvisionPluginPrincipal_WriteError surfaces an FGA write failure.
func TestProvisionPluginPrincipal_WriteError(t *testing.T) {
	s := &CapabilityGrantService{authorizer: &recordingAuthorizer{owners: []string{"user:u1"}, writeErr: errors.New("fga down")}}
	if _, _, err := s.ProvisionPluginPrincipal(context.Background(), "github", "acme"); err == nil {
		t.Error("a write failure must surface, not be swallowed")
	}
}
