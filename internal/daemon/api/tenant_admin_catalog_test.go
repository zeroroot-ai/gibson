package api

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantpb "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/sdk/auth"
)

// catalogStub satisfies authzIface for these tests. It records the
// requested (user, relation, objectType) triples so each test can
// assert the caller's tenant flowed through correctly.
type catalogStub struct {
	calls          []listObjectsCall
	componentRefs  []string
	pluginRefs     []string
	componentErr   error
	pluginErr      error
}

type listObjectsCall struct {
	user       string
	relation   string
	objectType string
}

func (s *catalogStub) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	s.calls = append(s.calls, listObjectsCall{user, relation, objectType})
	if objectType == "component" {
		return s.componentRefs, s.componentErr
	}
	if objectType == "plugin" {
		return s.pluginRefs, s.pluginErr
	}
	return nil, errors.New("unexpected objectType")
}

func (s *catalogStub) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *catalogStub) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, errors.New("not implemented")
}

func (s *catalogStub) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (s *catalogStub) Delete(_ context.Context, _ []authz.Tuple) error { return nil }

func (s *catalogStub) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func adminCtxForCatalog(t *testing.T, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "user:admin", Tenant: tid})
}

func newCatalogServer(stub *catalogStub) *DaemonServer {
	return &DaemonServer{
		authorizer: stub,
		logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

func TestListCatalogComponents_PlatformAndTenantPublished(t *testing.T) {
	stub := &catalogStub{
		componentRefs: []string{"component:gitlab", "component:nmap", "component:custom-scanner"},
		pluginRefs:    []string{"plugin:gitlab"},
	}
	srv := newCatalogServer(stub)
	resp, err := srv.ListCatalogComponents(adminCtxForCatalog(t, "zero-day-ai"), &tenantpb.ListCatalogComponentsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogComponents: %v", err)
	}
	if got := len(resp.GetComponents()); got != 3 {
		t.Errorf("components len = %d, want 3", got)
	}
	if got := len(resp.GetPlugins()); got != 1 {
		t.Errorf("plugins len = %d, want 1", got)
	}
	// Spot-check the projection.
	names := make([]string, 0, len(resp.GetComponents()))
	for _, c := range resp.GetComponents() {
		if c.GetRef() == "" || c.GetName() == "" {
			t.Errorf("missing ref/name: %+v", c)
		}
		names = append(names, c.GetName())
	}
	sort.Strings(names)
	if names[0] != "custom-scanner" || names[1] != "gitlab" || names[2] != "nmap" {
		t.Errorf("component names = %v, expected sorted set", names)
	}
	// Authorizer was called twice with the right tenant subject.
	if len(stub.calls) != 2 {
		t.Fatalf("expected 2 ListObjects calls, got %d", len(stub.calls))
	}
	for _, c := range stub.calls {
		if c.user != "tenant:zero-day-ai" {
			t.Errorf("user = %q, want tenant:zero-day-ai", c.user)
		}
	}
}

func TestListCatalogComponents_EmptyTenantNoError(t *testing.T) {
	stub := &catalogStub{}
	srv := newCatalogServer(stub)
	resp, err := srv.ListCatalogComponents(adminCtxForCatalog(t, "zero-day-ai"), &tenantpb.ListCatalogComponentsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogComponents: %v", err)
	}
	if len(resp.GetComponents()) != 0 || len(resp.GetPlugins()) != 0 {
		t.Errorf("expected both arrays empty, got %d / %d", len(resp.GetComponents()), len(resp.GetPlugins()))
	}
}

func TestListCatalogComponents_FGAComponentErrorIsBestEffort(t *testing.T) {
	stub := &catalogStub{
		componentErr: errors.New("fga down"),
		pluginRefs:   []string{"plugin:gitlab"},
	}
	srv := newCatalogServer(stub)
	resp, err := srv.ListCatalogComponents(adminCtxForCatalog(t, "zero-day-ai"), &tenantpb.ListCatalogComponentsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogComponents: %v", err)
	}
	// Components empty (FGA err logged), plugins still served.
	if len(resp.GetComponents()) != 0 {
		t.Errorf("expected empty components on FGA err; got %d", len(resp.GetComponents()))
	}
	if len(resp.GetPlugins()) != 1 {
		t.Errorf("expected plugins still served; got %d", len(resp.GetPlugins()))
	}
}

func TestListCatalogComponents_NoTenantInContext(t *testing.T) {
	srv := newCatalogServer(&catalogStub{})
	_, err := srv.ListCatalogComponents(context.Background(), &tenantpb.ListCatalogComponentsRequest{})
	if err == nil {
		t.Fatal("expected PermissionDenied without tenant in ctx")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

func TestListCatalogComponents_NoAuthorizer(t *testing.T) {
	srv := &DaemonServer{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	_, err := srv.ListCatalogComponents(adminCtxForCatalog(t, "zero-day-ai"), &tenantpb.ListCatalogComponentsRequest{})
	if err == nil {
		t.Fatal("expected Unavailable without authorizer wired")
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", got)
	}
}
