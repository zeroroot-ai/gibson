// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_admin_catalog_ops_test.go
//
// Unit tests for TenantAdminServer.SetCatalogEnabled (ADR-0041).
package admin

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// fakeAuthorizerCatalog is a minimal authz.Authorizer fake for catalog tests.
// ---------------------------------------------------------------------------

type fakeAuthorizerCatalog struct {
	tuples    []authz.Tuple
	checkFn   func(user, relation, object string) (bool, error)
	writeErr  error
	deleteErr error
}

func (f *fakeAuthorizerCatalog) Check(_ context.Context, user, relation, object string) (bool, error) {
	if f.checkFn != nil {
		return f.checkFn(user, relation, object)
	}
	for _, t := range f.tuples {
		if t.User == user && t.Relation == relation && t.Object == object {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeAuthorizerCatalog) Write(_ context.Context, tuples []authz.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.tuples = append(f.tuples, tuples...)
	return nil
}

func (f *fakeAuthorizerCatalog) Delete(_ context.Context, tuples []authz.Tuple) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	remaining := f.tuples[:0]
	for _, t := range f.tuples {
		found := false
		for _, d := range tuples {
			if t == d {
				found = true
				break
			}
		}
		if !found {
			remaining = append(remaining, t)
		}
	}
	f.tuples = remaining
	return nil
}

func (f *fakeAuthorizerCatalog) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizerCatalog) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizerCatalog) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (f *fakeAuthorizerCatalog) StoreID() string { return "" }
func (f *fakeAuthorizerCatalog) ModelID() string { return "" }
func (f *fakeAuthorizerCatalog) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func catalogCtx() context.Context {
	ctx := context.Background()
	tid, _ := auth.NewTenantID("acme")
	return auth.ContextWithTenant(ctx, tid)
}

func newCatalogServer(fga *fakeAuthorizerCatalog) *TenantAdminServer {
	return &TenantAdminServer{
		authorizer: fga,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSetCatalogEnabled_Enable_WritesWhenAbsent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when tuple was absent")
	}

	// Tuple must now exist.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool/nmap")
	if !present {
		t.Error("expected tenant_enabled tuple to be present after enable")
	}
}

func TestSetCatalogEnabled_Enable_IdempotentWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{
		tuples: []authz.Tuple{
			{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:tool/nmap"},
			{User: "tenant:acme#member", Relation: "direct_read", Object: "component:tool/nmap"},
			{User: "tenant:acme#member", Relation: "direct_execute", Object: "component:tool/nmap"},
		},
	}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if resp.GetWritten() {
		t.Error("expected Written=false when tuple was already present")
	}
}

func TestSetCatalogEnabled_Disable_DeletesWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{
		tuples: []authz.Tuple{
			{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:tool/nmap"},
			{User: "tenant:acme#member", Relation: "direct_read", Object: "component:tool/nmap"},
			{User: "tenant:acme#member", Relation: "direct_execute", Object: "component:tool/nmap"},
		},
	}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      false,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetDeleted() {
		t.Error("expected Deleted=true when tuple was present")
	}
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool/nmap")
	if present {
		t.Error("expected tenant_enabled tuple to be absent after disable")
	}
}

func TestSetCatalogEnabled_Disable_IdempotentWhenAbsent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      false,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if resp.GetDeleted() {
		t.Error("expected Deleted=false when tuple was already absent")
	}
}

func TestSetCatalogEnabled_AddsComponentPrefix(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	// Verify the component: prefix was added.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool/nmap")
	if !present {
		t.Error("expected component: prefix to be added automatically")
	}
}

func TestSetCatalogEnabled_AlreadyPrefixedComponent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "component:tool/nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	// Should NOT double-prefix.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool/nmap")
	if !present {
		t.Error("expected existing component: prefix to be preserved (no double-prefix)")
	}
}

func TestSetCatalogEnabled_EmptyComponentRef(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "",
		Enabled:      true,
	})
	if err == nil {
		t.Fatal("expected error for empty component_ref")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestSetCatalogEnabled_NoTenantInContext(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(context.Background(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err == nil {
		t.Fatal("expected error when no tenant in context")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %s", st.Code())
	}
}

func TestSetCatalogEnabled_UnavailableWhenNoAuthorizer(t *testing.T) {
	srv := &TenantAdminServer{authorizer: nil}
	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err == nil {
		t.Fatal("expected error when authorizer is nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("expected Unavailable, got %s", st.Code())
	}
}

func TestSetCatalogEnabled_WriteError(t *testing.T) {
	fga := &fakeAuthorizerCatalog{writeErr: errors.New("fga failure")}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool:nmap",
		Enabled:      true,
	})
	if err == nil {
		t.Fatal("expected error on FGA write failure")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %s", st.Code())
	}
}

// ---------------------------------------------------------------------------
// SetCatalogPublished (BYO connector path — gibson#683)
// ---------------------------------------------------------------------------

func TestSetCatalogPublished_Publish_WritesWhenAbsent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector:gitlab",
		Published:    true,
	})
	if err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when tuple was absent")
	}
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_published", "component:connector/gitlab")
	if !present {
		t.Error("expected tenant_published tuple present after publish")
	}
}

func TestSetCatalogPublished_Publish_IdempotentWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{tuples: []authz.Tuple{
		{User: "tenant:acme", Relation: "tenant_published", Object: "component:connector/gitlab"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector:gitlab", Published: true,
	})
	if err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	if resp.GetWritten() {
		t.Error("expected Written=false when already published")
	}
}

func TestSetCatalogPublished_Unpublish_DeletesWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{tuples: []authz.Tuple{
		{User: "tenant:acme", Relation: "tenant_published", Object: "component:connector/gitlab"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector:gitlab", Published: false,
	})
	if err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	if !resp.GetDeleted() {
		t.Error("expected Deleted=true when tuple was present")
	}
}

func TestSetCatalogPublished_EmptyComponentRef(t *testing.T) {
	srv := newCatalogServer(&fakeAuthorizerCatalog{})
	_, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{Published: true})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty component_ref must be InvalidArgument, got %v", err)
	}
}

func TestSetCatalogPublished_AddsComponentPrefix(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)
	if _, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector:gitlab", Published: true,
	}); err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	// Writing with an already-prefixed ref must hit the same object.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_published", "component:connector/gitlab")
	if !present {
		t.Error("component: prefix not applied to the FGA object")
	}
}

// ListUsersOfType is a security gate in this package; a double that is
// not set up for it must fail the gate loudly rather than answer "nobody".
func (f *fakeAuthorizerCatalog) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}

// TestSetCatalogEnabled_Enable_AgentKind is the opt-in acceptance case: a tenant
// admin enables an agent (e.g. zerocool) and the tenant_enabled tuple lands on
// the canonical component:agent/<name> object for that tenant only (ADR-0015).
func TestSetCatalogEnabled_Enable_AgentKind(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "component:agent/zerocool",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled(agent): %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when the agent tuple was absent")
	}
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:agent/zerocool")
	if !present {
		t.Error("expected tenant_enabled on component:agent/zerocool after enable")
	}
	// A different tenant must NOT be enabled (opt-in, per-tenant).
	other, _ := fga.Check(context.Background(), "tenant:other", "tenant_enabled", "component:agent/zerocool")
	if other {
		t.Error("enable in one tenant must not enable it in another")
	}
}

// TestSetCatalogEnabled_EnableConvergesTheDefaultPosture: ADR-0067 §5. Enable
// writes tenant_enabled AND direct_read/direct_execute for tenant#member, so
// an enabled catalog agent is executable by members (it has no owner tenant
// to inherit execute from). A partially enabled item is completed.
func TestSetCatalogEnabled_EnableConvergesTheDefaultPosture(t *testing.T) {
	fga := &fakeAuthorizerCatalog{tuples: []authz.Tuple{
		{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:agent/claude"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{ComponentRef: "agent/claude", Enabled: true})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true: the member grants were missing")
	}
	got := map[string]bool{}
	for _, tu := range fga.tuples {
		if tu.Object == "component:agent/claude" {
			got[tu.User+"|"+tu.Relation] = true
		}
	}
	for _, k := range []string{"tenant:acme|tenant_enabled", "tenant:acme#member|direct_read", "tenant:acme#member|direct_execute"} {
		if !got[k] {
			t.Errorf("missing tuple %s on component:agent/claude", k)
		}
	}
	if len(fga.tuples) != 3 {
		t.Errorf("tuples = %+v, want exactly the three-tuple posture (no duplicate tenant_enabled)", fga.tuples)
	}
}

// TestSetCatalogEnabled_DisableRemovesTheWholePosture: disable takes the
// member grants away with the catalog membership.
func TestSetCatalogEnabled_DisableRemovesTheWholePosture(t *testing.T) {
	fga := &fakeAuthorizerCatalog{tuples: []authz.Tuple{
		{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:agent/claude"},
		{User: "tenant:acme#member", Relation: "direct_read", Object: "component:agent/claude"},
		{User: "tenant:acme#member", Relation: "direct_execute", Object: "component:agent/claude"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{ComponentRef: "agent/claude", Enabled: false})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetDeleted() {
		t.Error("expected Deleted=true")
	}
	for _, tu := range fga.tuples {
		if tu.Object == "component:agent/claude" {
			t.Errorf("tuple survived disable: %+v", tu)
		}
	}
}
