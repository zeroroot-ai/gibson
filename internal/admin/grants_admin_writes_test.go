package admin

import (
	"context"
	"errors"
	"testing"

	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/identity"
)

// stubAuthorizer is a minimal authz.Authorizer for the write tests:
// BatchCheck reports tuples present iff `present[user|relation|object]==true`,
// and Write/Delete record the tuples in `wrote` / `deleted` for assertions.
type stubAuthorizer struct {
	present map[string]bool
	wrote   []authz.Tuple
	deleted []authz.Tuple
}

func tupleKey(t authz.Tuple) string {
	return t.User + "|" + t.Relation + "|" + t.Object
}

func (s *stubAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, errors.New("not implemented")
}
func (s *stubAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = s.present[tupleKey(authz.Tuple{User: c.User, Relation: c.Relation, Object: c.Object})]
	}
	return out, nil
}
func (s *stubAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	s.wrote = append(s.wrote, tuples...)
	return nil
}
func (s *stubAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	s.deleted = append(s.deleted, tuples...)
	return nil
}
func (s *stubAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (s *stubAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (s *stubAuthorizer) StoreID() string { return "test" }
func (s *stubAuthorizer) ModelID() string { return "test" }
func (s *stubAuthorizer) Close() error    { return nil }

type stubLookup struct {
	records map[string]identity.PrincipalRecord
}

func (s *stubLookup) Resolve(_ context.Context, principalID string) (identity.PrincipalRecord, error) {
	rec, ok := s.records[principalID]
	if !ok {
		return identity.PrincipalRecord{}, identity.ErrPrincipalNotFound
	}
	return rec, nil
}

func adminCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "user:admin-1", Tenant: tid})
}

func newWriteServer(t *testing.T, az *stubAuthorizer, lookup *stubLookup) *GrantsAdminServer {
	t.Helper()
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader:     noopReader{},
		Authorizer: az,
		Lookup:     lookup,
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv
}

type noopReader struct{}

func (noopReader) ListActive(_ context.Context, _ auth.TenantID) ([]GrantInfo, error) {
	return nil, nil
}

func TestWriteAgentGrants_HappyPath(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_configure"},
		},
	})
	if err != nil {
		t.Fatalf("WriteAgentGrants: %v", err)
	}
	if resp.GetWritten() != 2 || resp.GetAlreadyPresent() != 0 {
		t.Errorf("counts = (%d, %d), want (2, 0)", resp.GetWritten(), resp.GetAlreadyPresent())
	}
	if len(az.wrote) != 2 {
		t.Errorf("wrote %d tuples, want 2", len(az.wrote))
	}
}

func TestWriteAgentGrants_IdempotentAlreadyPresent(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{
		"agent_principal:abc|can_read|component:gitlab": true,
	}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_execute"},
		},
	})
	if err != nil {
		t.Fatalf("WriteAgentGrants: %v", err)
	}
	if resp.GetWritten() != 1 || resp.GetAlreadyPresent() != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", resp.GetWritten(), resp.GetAlreadyPresent())
	}
}

func TestWriteAgentGrants_AgentCannotGetCanInvoke(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "plugin:gitlab", Relation: "can_invoke"},
		},
	})
	if err == nil {
		t.Fatal("expected InvalidArgument; got nil")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0 (validation should reject before write)", len(az.wrote))
	}
}

func TestWriteAgentGrants_CrossTenantRejected(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:other": {
			PrincipalID: "agent_principal:other",
			TenantID:    "OTHER-TENANT",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:other",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
		},
	})
	if err == nil {
		t.Fatal("expected PermissionDenied; got nil")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

func TestWriteAgentGrants_InvalidRelation(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:foo", Relation: "owner"},
		},
	})
	if err == nil {
		t.Fatal("expected InvalidArgument; got nil")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
}

func TestDeleteAgentGrants_HappyPath(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{
		"agent_principal:abc|can_read|component:gitlab": true,
	}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.DeleteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.DeleteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_execute"}, // not present
		},
	})
	if err != nil {
		t.Fatalf("DeleteAgentGrants: %v", err)
	}
	if resp.GetDeleted() != 1 || resp.GetNotPresent() != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", resp.GetDeleted(), resp.GetNotPresent())
	}
}
