package api

import (
	"context"
	"testing"

	"github.com/zero-day-ai/gibson/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGetAuthSchema_ReturnsFullSchema verifies the handler returns every
// role, every permission, and every RPC requirement loaded from the
// production permissions.yaml, with effective_permissions pre-computed
// so clients don't have to walk inheritance.
func TestGetAuthSchema_ReturnsFullSchema(t *testing.T) {
	reg, _, err := auth.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	srv := &DaemonServer{schemaRegistry: reg}

	resp, err := srv.GetAuthSchema(context.Background(), &GetAuthSchemaRequest{})
	if err != nil {
		t.Fatalf("GetAuthSchema: %v", err)
	}

	if resp.SchemaVersion == "" {
		t.Error("schema_version is empty")
	}
	if len(resp.Roles) != len(reg.Roles) {
		t.Errorf("roles count = %d, want %d", len(resp.Roles), len(reg.Roles))
	}
	if len(resp.Permissions) != len(reg.Permissions) {
		t.Errorf("permissions count = %d, want %d", len(resp.Permissions), len(reg.Permissions))
	}
	if len(resp.RpcRequirements) != len(reg.RPCRequirements) {
		t.Errorf("rpc_requirements count = %d, want %d", len(resp.RpcRequirements), len(reg.RPCRequirements))
	}

	// Spot-check: the admin role's effective_permissions must transitively
	// include both missions:read (from viewer via operator) AND team:manage
	// (direct on admin).
	var adminRole *AuthRole
	for _, r := range resp.Roles {
		if r.Name == "admin" {
			adminRole = r
			break
		}
	}
	if adminRole == nil {
		t.Fatal("admin role not in response")
	}

	hasMissionsRead := false
	hasTeamManage := false
	for _, p := range adminRole.EffectivePermissions {
		if p == "missions:read" {
			hasMissionsRead = true
		}
		if p == "team:manage" {
			hasTeamManage = true
		}
	}
	if !hasMissionsRead {
		t.Error("admin.effective_permissions should include missions:read (inherited from viewer)")
	}
	if !hasTeamManage {
		t.Error("admin.effective_permissions should include team:manage (direct grant)")
	}

	// admin is NOT cross_tenant (it's scoped to a single tenant).
	if adminRole.CrossTenant {
		t.Error("admin should not be cross_tenant")
	}

	// Spot-check: platform-operator IS cross_tenant.
	var platformOp *AuthRole
	for _, r := range resp.Roles {
		if r.Name == "platform-operator" {
			platformOp = r
			break
		}
	}
	if platformOp == nil || !platformOp.CrossTenant {
		t.Error("platform-operator should be cross_tenant")
	}

	// Spot-check: GetAuthSchema's own RPC requirement should have empty
	// required_permissions (bootstrap: any authenticated caller passes).
	schemaRPC, ok := resp.RpcRequirements["/gibson.daemon.admin.v1.DaemonAdminService/GetAuthSchema"]
	if !ok {
		t.Fatal("GetAuthSchema rpc requirement missing from response")
	}
	if len(schemaRPC.RequiredPermissions) != 0 {
		t.Errorf("GetAuthSchema required_permissions should be empty, got %v", schemaRPC.RequiredPermissions)
	}
	if schemaRPC.Unauthenticated {
		t.Error("GetAuthSchema should require authentication")
	}

	// Spot-check: AcceptInvitation should be unauthenticated=true (token-based).
	acceptInv, ok := resp.RpcRequirements["/gibson.daemon.admin.v1.DaemonAdminService/AcceptInvitation"]
	if !ok {
		t.Fatal("AcceptInvitation rpc requirement missing from response")
	}
	if !acceptInv.Unauthenticated {
		t.Error("AcceptInvitation should be unauthenticated (token-based flow)")
	}
}

// TestGetAuthSchema_NilRegistry_ReturnsUnavailable verifies the handler
// fails cleanly when the daemon is misconfigured with no schema registry.
func TestGetAuthSchema_NilRegistry_ReturnsUnavailable(t *testing.T) {
	srv := &DaemonServer{} // no schemaRegistry
	_, err := srv.GetAuthSchema(context.Background(), &GetAuthSchemaRequest{})
	if err == nil {
		t.Fatal("expected error when schemaRegistry is nil")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected codes.Unavailable, got %v", status.Code(err))
	}
}

// TestGetAuthSchema_Deterministic verifies the response is byte-identical
// on repeated calls (needed so the dashboard's TTL cache is meaningful).
func TestGetAuthSchema_Deterministic(t *testing.T) {
	reg, _, err := auth.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	srv := &DaemonServer{schemaRegistry: reg}

	resp1, _ := srv.GetAuthSchema(context.Background(), &GetAuthSchemaRequest{})
	resp2, _ := srv.GetAuthSchema(context.Background(), &GetAuthSchemaRequest{})

	if resp1.SchemaVersion != resp2.SchemaVersion {
		t.Error("schema_version differs between calls")
	}
	if len(resp1.Roles) != len(resp2.Roles) {
		t.Error("role count differs between calls")
	}
	for i := range resp1.Roles {
		if resp1.Roles[i].Name != resp2.Roles[i].Name {
			t.Errorf("role order differs at index %d: %q vs %q", i, resp1.Roles[i].Name, resp2.Roles[i].Name)
		}
	}
	for i := range resp1.Permissions {
		if resp1.Permissions[i].Name != resp2.Permissions[i].Name {
			t.Errorf("permission order differs at index %d: %q vs %q", i, resp1.Permissions[i].Name, resp2.Permissions[i].Name)
		}
	}
}
