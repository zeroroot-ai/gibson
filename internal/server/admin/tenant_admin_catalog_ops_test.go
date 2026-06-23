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
		ComponentRef: "tool-nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when tuple was absent")
	}

	// Tuple must now exist.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool-nmap")
	if !present {
		t.Error("expected tenant_enabled tuple to be present after enable")
	}
}

func TestSetCatalogEnabled_Enable_IdempotentWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{
		tuples: []authz.Tuple{
			{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:tool-nmap"},
		},
	}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool-nmap",
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
			{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:tool-nmap"},
		},
	}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool-nmap",
		Enabled:      false,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	if !resp.GetDeleted() {
		t.Error("expected Deleted=true when tuple was present")
	}
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool-nmap")
	if present {
		t.Error("expected tenant_enabled tuple to be absent after disable")
	}
}

func TestSetCatalogEnabled_Disable_IdempotentWhenAbsent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	resp, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "tool-nmap",
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
		ComponentRef: "tool-nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	// Verify the component: prefix was added.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool-nmap")
	if !present {
		t.Error("expected component: prefix to be added automatically")
	}
}

func TestSetCatalogEnabled_AlreadyPrefixedComponent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := newCatalogServer(fga)

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "component:tool-nmap",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("SetCatalogEnabled: %v", err)
	}
	// Should NOT double-prefix.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_enabled", "component:tool-nmap")
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
		ComponentRef: "tool-nmap",
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
		ComponentRef: "tool-nmap",
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
		ComponentRef: "tool-nmap",
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
		ComponentRef: "connector-gitlab",
		Published:    true,
	})
	if err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when tuple was absent")
	}
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_published", "component:connector-gitlab")
	if !present {
		t.Error("expected tenant_published tuple present after publish")
	}
}

func TestSetCatalogPublished_Publish_IdempotentWhenPresent(t *testing.T) {
	fga := &fakeAuthorizerCatalog{tuples: []authz.Tuple{
		{User: "tenant:acme", Relation: "tenant_published", Object: "component:connector-gitlab"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector-gitlab", Published: true,
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
		{User: "tenant:acme", Relation: "tenant_published", Object: "component:connector-gitlab"},
	}}
	srv := newCatalogServer(fga)
	resp, err := srv.SetCatalogPublished(catalogCtx(), &tenantv1.SetCatalogPublishedRequest{
		ComponentRef: "connector-gitlab", Published: false,
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
		ComponentRef: "connector-gitlab", Published: true,
	}); err != nil {
		t.Fatalf("SetCatalogPublished: %v", err)
	}
	// Writing with an already-prefixed ref must hit the same object.
	present, _ := fga.Check(context.Background(), "tenant:acme", "tenant_published", "component:connector-gitlab")
	if !present {
		t.Error("component: prefix not applied to the FGA object")
	}
}
