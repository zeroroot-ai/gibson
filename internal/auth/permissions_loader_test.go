package auth

import (
	"strings"
	"testing"
)

// TestLoadEmbedded_ProductionYAMLLoads asserts the real embedded
// permissions.yaml parses, validates, and builds a Casbin enforcer without
// error. This is the primary smoke test — if the YAML ever becomes invalid
// this fails in CI before merge.
func TestLoadEmbedded_ProductionYAMLLoads(t *testing.T) {
	reg, enforcer, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}
	if reg == nil {
		t.Fatal("LoadEmbedded() returned nil registry")
	}
	if enforcer == nil {
		t.Fatal("LoadEmbedded() returned nil enforcer")
	}
	if reg.SchemaVersion == "" {
		t.Error("SchemaVersion is empty")
	}
	if len(reg.Roles) == 0 {
		t.Error("no roles loaded from production YAML")
	}
	if len(reg.Permissions) == 0 {
		t.Error("no permissions loaded from production YAML")
	}
	if len(reg.RPCRequirements) == 0 {
		t.Error("no RPC requirements loaded from production YAML")
	}

	// Spot-check: the daemon must define these canonical roles.
	for _, role := range []string{"viewer", "operator", "admin", "owner", "platform-operator", "provisioner", "tool-executor", "agent-executor", "plugin-executor"} {
		if _, ok := reg.Roles[role]; !ok {
			t.Errorf("production YAML is missing role %q", role)
		}
	}

	// Spot-check: GetAuthSchema must be covered and callable by any
	// authenticated identity (empty required_permissions, not unauthenticated).
	schemaRPC := reg.GetRPCRequirement("/gibson.daemon.admin.v1.DaemonAdminService/GetAuthSchema")
	if schemaRPC == nil {
		t.Fatal("GetAuthSchema is not mapped in production YAML")
	}
	if len(schemaRPC.RequiredPermissions) != 0 {
		t.Errorf("GetAuthSchema should have empty required_permissions, got %v", schemaRPC.RequiredPermissions)
	}
	if schemaRPC.Unauthenticated {
		t.Error("GetAuthSchema should require authentication (unauthenticated=false)")
	}
}

// TestLoadEmbedded_RoleClosureTransitivity asserts that inherited roles
// transitively accumulate permissions. admin inherits operator inherits
// viewer, so admin's closure contains the union of all three.
func TestLoadEmbedded_RoleClosureTransitivity(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// viewer contributes missions:read
	viewer := reg.RoleClosure["viewer"]
	if _, ok := viewer["missions:read"]; !ok {
		t.Error("viewer should have missions:read")
	}

	// operator inherits viewer and adds missions:execute
	operator := reg.RoleClosure["operator"]
	if _, ok := operator["missions:read"]; !ok {
		t.Error("operator should inherit missions:read from viewer")
	}
	if _, ok := operator["missions:execute"]; !ok {
		t.Error("operator should have missions:execute directly")
	}

	// admin inherits operator and adds team:manage
	admin := reg.RoleClosure["admin"]
	if _, ok := admin["missions:read"]; !ok {
		t.Error("admin should transitively inherit missions:read")
	}
	if _, ok := admin["missions:execute"]; !ok {
		t.Error("admin should transitively inherit missions:execute")
	}
	if _, ok := admin["team:manage"]; !ok {
		t.Error("admin should have team:manage directly")
	}

	// owner inherits admin and adds billing:write
	owner := reg.RoleClosure["owner"]
	if _, ok := owner["team:manage"]; !ok {
		t.Error("owner should transitively inherit team:manage")
	}
	if _, ok := owner["billing:write"]; !ok {
		t.Error("owner should have billing:write directly")
	}
}

// TestResolvePermissions_MultipleRoles asserts that ResolvePermissions
// returns the union of closures for a list of roles.
func TestResolvePermissions_MultipleRoles(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// A user with both viewer and tool-executor gets the union.
	got := reg.ResolvePermissions([]string{"viewer", "tool-executor"})
	if _, ok := got["missions:read"]; !ok {
		t.Error("union should include viewer's missions:read")
	}
	if _, ok := got["components:register"]; !ok {
		t.Error("union should include tool-executor's components:register")
	}

	// Unknown role is silently ignored.
	got2 := reg.ResolvePermissions([]string{"viewer", "nonexistent-role"})
	if _, ok := got2["missions:read"]; !ok {
		t.Error("unknown role should be ignored, not throw")
	}
}

// TestGetRPCRequirement_UnmappedReturnsNil asserts default-deny behavior at
// the registry level: unmapped methods return nil and the caller (interceptor)
// treats that as deny.
func TestGetRPCRequirement_UnmappedReturnsNil(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	if req := reg.GetRPCRequirement("/fake.service.v1/FakeRPC"); req != nil {
		t.Errorf("unmapped method should return nil, got %+v", req)
	}
}

// TestKnownRoles_IsSorted asserts KnownRoles returns a sorted slice
// (used by the startup helm-role-binding validator for deterministic
// error messages).
func TestKnownRoles_IsSorted(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}
	roles := reg.KnownRoles()
	for i := 1; i < len(roles); i++ {
		if roles[i-1] > roles[i] {
			t.Errorf("KnownRoles not sorted: %q > %q", roles[i-1], roles[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Validation error tests (use loadFromBytes with synthetic YAML)
// ---------------------------------------------------------------------------

func TestLoadFromBytes_ParseError(t *testing.T) {
	_, _, err := loadFromBytes([]byte("this is: not: [valid yaml"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parse, got: %v", err)
	}
}

func TestLoadFromBytes_MissingSchemaVersion(t *testing.T) {
	yaml := `
roles:
  - name: viewer
    description: v
    inherits: []
    permissions: []
permissions: []
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected schema_version required error")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should mention schema_version, got: %v", err)
	}
}

func TestLoadFromBytes_DuplicateRole(t *testing.T) {
	yaml := `
schema_version: "1"
roles:
  - name: viewer
    description: v
    inherits: []
    permissions: []
  - name: viewer
    description: v2
    inherits: []
    permissions: []
permissions: []
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected duplicate role error")
	}
	if !strings.Contains(err.Error(), "duplicate role") {
		t.Errorf("error should mention duplicate role, got: %v", err)
	}
}

func TestLoadFromBytes_DuplicatePermission(t *testing.T) {
	yaml := `
schema_version: "1"
roles: []
permissions:
  - name: foo:read
    resource: foo
    action: read
    description: d
  - name: foo:read
    resource: foo
    action: read
    description: d
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected duplicate permission error")
	}
	if !strings.Contains(err.Error(), "duplicate permission") {
		t.Errorf("error should mention duplicate permission, got: %v", err)
	}
}

func TestLoadFromBytes_PermissionNameMismatch(t *testing.T) {
	yaml := `
schema_version: "1"
roles: []
permissions:
  - name: wrong:shape
    resource: right
    action: shape
    description: d
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected permission name mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention name mismatch, got: %v", err)
	}
}

func TestLoadFromBytes_UndefinedPermissionGrant(t *testing.T) {
	yaml := `
schema_version: "1"
roles:
  - name: viewer
    description: v
    inherits: []
    permissions: [ghost:read]
permissions: []
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected undefined permission grant error")
	}
	if !strings.Contains(err.Error(), "undefined permission") {
		t.Errorf("error should mention undefined permission, got: %v", err)
	}
}

func TestLoadFromBytes_UndefinedInheritRole(t *testing.T) {
	yaml := `
schema_version: "1"
roles:
  - name: viewer
    description: v
    inherits: [ghost]
    permissions: []
permissions: []
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected undefined inherit role error")
	}
	if !strings.Contains(err.Error(), "inherits undefined role") {
		t.Errorf("error should mention inherits undefined role, got: %v", err)
	}
}

func TestLoadFromBytes_InheritanceCycle(t *testing.T) {
	yaml := `
schema_version: "1"
roles:
  - name: a
    description: a
    inherits: [b]
    permissions: []
  - name: b
    description: b
    inherits: [a]
    permissions: []
permissions: []
rpcs: {}
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected inheritance cycle error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention cycle, got: %v", err)
	}
}

func TestLoadFromBytes_RPCRequiresUndefinedPermission(t *testing.T) {
	yaml := `
schema_version: "1"
roles: []
permissions: []
rpcs:
  "/foo.v1/Bar":
    required_permissions: [ghost:read]
    tenant_scoped: false
    unauthenticated: false
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected rpc requires undefined permission error")
	}
	if !strings.Contains(err.Error(), "requires undefined permission") {
		t.Errorf("error should mention requires undefined permission, got: %v", err)
	}
}

func TestLoadFromBytes_UnauthenticatedContradiction(t *testing.T) {
	yaml := `
schema_version: "1"
roles: []
permissions:
  - name: foo:read
    resource: foo
    action: read
    description: d
rpcs:
  "/foo.v1/Bar":
    required_permissions: [foo:read]
    tenant_scoped: false
    unauthenticated: true
`
	_, _, err := loadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected unauthenticated + required_permissions contradiction error")
	}
	if !strings.Contains(err.Error(), "contradiction") {
		t.Errorf("error should mention contradiction, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyProtoCoverage
// ---------------------------------------------------------------------------

func TestVerifyProtoCoverage_AllMapped(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// Use the RPC requirement keys themselves as the "known methods" — every
	// entry in the registry is trivially covered by itself.
	known := make([]string, 0, len(reg.RPCRequirements))
	for m := range reg.RPCRequirements {
		known = append(known, m)
	}
	if err := reg.VerifyProtoCoverage(known); err != nil {
		t.Errorf("VerifyProtoCoverage with self-known methods should pass, got: %v", err)
	}
}

func TestVerifyProtoCoverage_UnmappedFails(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	known := []string{"/gibson.daemon.v1.DaemonService/Ping", "/ghost.v1.Ghost/Boo"}
	err = reg.VerifyProtoCoverage(known)
	if err == nil {
		t.Fatal("VerifyProtoCoverage with unmapped method should fail")
	}
	if !strings.Contains(err.Error(), "/ghost.v1.Ghost/Boo") {
		t.Errorf("error should name the unmapped method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "default-deny") {
		t.Errorf("error should mention default-deny, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Enforcer behavior (end-to-end: YAML -> Casbin policies -> Enforce)
// ---------------------------------------------------------------------------

func TestEnforcer_AllowsRoleWithDirectPermission(t *testing.T) {
	_, enforcer, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// To test end-to-end, we need a `g` rule binding a subject to the role.
	// Real deployments install `g` rules via the membership store; the test
	// installs them directly.
	if _, err := enforcer.AddGroupingPolicy("alice", "viewer", "tenant-a"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	allowed, err := enforcer.Enforce("alice", "tenant-a", "missions", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("alice as viewer should be allowed missions:read in tenant-a")
	}

	// viewer does NOT have missions:execute.
	allowed2, err := enforcer.Enforce("alice", "tenant-a", "missions", "execute")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed2 {
		t.Error("alice as viewer should NOT be allowed missions:execute")
	}
}

func TestEnforcer_TransitiveInheritanceWorksAtEnforceTime(t *testing.T) {
	_, enforcer, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// admin transitively inherits viewer (admin -> operator -> viewer).
	// Binding alice to admin in tenant-b should allow missions:read.
	if _, err := enforcer.AddGroupingPolicy("alice", "admin", "tenant-b"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	allowed, err := enforcer.Enforce("alice", "tenant-b", "missions", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("alice as admin should inherit viewer's missions:read")
	}

	// admin also has team:manage directly.
	allowed2, err := enforcer.Enforce("alice", "tenant-b", "team", "manage")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed2 {
		t.Error("alice as admin should have team:manage directly")
	}
}

func TestEnforcer_CrossTenantWildcardDomain(t *testing.T) {
	_, enforcer, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error: %v", err)
	}

	// system-ops is bound to provisioner with wildcard domain — the dashboard
	// signup flow's canonical binding.
	if _, err := enforcer.AddGroupingPolicy("system-ops", "provisioner", "*"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	allowed, err := enforcer.Enforce("system-ops", "*", "tenants", "provision")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("system-ops as provisioner with wildcard domain should be allowed tenants:provision")
	}
}
