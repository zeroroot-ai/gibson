package auth

import (
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"gopkg.in/yaml.v3"
)

// permissionsYAMLFS embeds the permissions.yaml source of truth into the
// daemon binary. The daemon refuses to start if this file is missing,
// malformed, or does not cover every proto-declared RPC.
//
//go:embed permissions.yaml
var permissionsYAMLFS embed.FS

// rbacModelString is the Casbin model used by the new RBAC framework.
//
// Key difference from the legacy per-tenant model in casbin.go: the matcher
// accepts a wildcard domain ("*") in policy rules, so a single `p` rule from
// permissions.yaml covers all tenants instead of requiring per-tenant
// duplication. Membership `g` rules continue to be per-tenant and come from
// the existing Redis-backed membership store (internal/membership/store.go).
//
// Semantics:
//
//	request:  r = (sub, dom, obj, act)
//	policy:   p = (sub, dom, obj, act)  where dom may be "*"
//	role:     g = (_, _, _)              (sub, role, dom)
//	effect:   allow on any matching p
//	matcher:  g(r.sub, p.sub, r.dom) AND (p.dom == "*" OR r.dom == p.dom)
//	          AND r.obj == p.obj AND r.act == p.act
const rbacModelString = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && (p.dom == "*" || r.dom == p.dom) && r.obj == p.obj && r.act == p.act
`

// SchemaRegistry is the immutable runtime representation of permissions.yaml.
// Built once at daemon startup by LoadEmbedded and shared by the
// RPCAuthzInterceptor and the GetAuthSchema RPC handler.
type SchemaRegistry struct {
	// SchemaVersion identifies the schema document version. Incremented when
	// the wire format of permissions.yaml changes in an incompatible way.
	SchemaVersion string

	// Roles is the map of role name -> Role.
	Roles map[string]*Role

	// Permissions is the map of permission name ("resource:action") -> SchemaPermission.
	Permissions map[string]*SchemaPermission

	// RPCRequirements is the map of fully-qualified gRPC method path -> requirement.
	// A method lookup miss in this map triggers default-deny in the interceptor.
	RPCRequirements map[string]*RPCRequirement

	// RoleClosure is the pre-computed transitive permission closure per role.
	// RoleClosure["admin"] contains every permission admin holds directly plus
	// everything it inherits from operator (which includes viewer). Built at
	// load time so hasSchemaPermission checks never walk the inheritance graph.
	RoleClosure map[string]map[string]struct{}
}

// Role is a named bundle of permissions, optionally inheriting from other roles.
type Role struct {
	// Name is the canonical role identifier (lowercase, kebab-case).
	Name string `yaml:"name"`

	// Description is a human-readable explanation of the role.
	Description string `yaml:"description"`

	// Inherits lists parent roles whose permissions this role transitively gains.
	// Inheritance is transitive but cycles are rejected at load time.
	Inherits []string `yaml:"inherits"`

	// CrossTenant marks roles that operate across all tenants (platform-operator,
	// provisioner, tool/agent/plugin-executor). When true, the Casbin `p` rule
	// for this role uses "*" as the domain so it applies in any tenant context.
	// When false, the role is tenant-scoped and the Casbin `g` rules from the
	// membership store bind users to this role per tenant.
	CrossTenant bool `yaml:"cross_tenant"`

	// Permissions lists the permission names granted DIRECTLY by this role.
	// Does not include transitively-inherited permissions; use RoleClosure
	// for the effective set.
	Permissions []string `yaml:"permissions"`
}

// SchemaPermission is an atomic unit of authorization, keyed by "resource:action".
type SchemaPermission struct {
	// Name is the canonical permission identifier, always in "resource:action" form.
	Name string `yaml:"name"`

	// Resource is the left side of the name (e.g. "tenants" for "tenants:provision").
	Resource string `yaml:"resource"`

	// Action is the right side of the name (e.g. "provision" for "tenants:provision").
	Action string `yaml:"action"`

	// Description is a human-readable explanation.
	Description string `yaml:"description"`
}

// RPCRequirement describes the authorization requirement for a single gRPC RPC.
type RPCRequirement struct {
	// Method is the fully-qualified gRPC method path, e.g.
	// "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant".
	// Populated from the YAML map key when the schema is loaded.
	Method string `yaml:"-"`

	// RequiredPermissions lists permissions the caller must hold ALL of. An
	// empty list means "any authenticated caller" (used for GetAuthSchema).
	RequiredPermissions []string `yaml:"required_permissions"`

	// TenantScoped determines the Casbin domain used during enforcement.
	// When true, the interceptor passes the caller's tenant context. When
	// false, the interceptor passes "*" (cross-tenant rules apply).
	TenantScoped bool `yaml:"tenant_scoped"`

	// Unauthenticated, when true, skips authorization entirely. Used for
	// token-based flows (AcceptInvitation) where the handler validates a
	// self-contained token rather than a user identity.
	Unauthenticated bool `yaml:"unauthenticated"`
}

// schemaDocument is the intermediate shape used to parse permissions.yaml.
// Kept private because the loader exposes SchemaRegistry (the validated,
// closed-over form) to the rest of the daemon.
type schemaDocument struct {
	SchemaVersion string                     `yaml:"schema_version"`
	Roles         []Role                     `yaml:"roles"`
	Permissions   []SchemaPermission               `yaml:"permissions"`
	RPCs          map[string]*RPCRequirement `yaml:"rpcs"`
}

// LoadEmbedded parses the embedded permissions.yaml, validates every
// invariant, builds a Casbin enforcer with in-memory policies, and returns
// both the registry and the enforcer. Any validation failure returns an
// error; callers are expected to log.Fatal on error.
//
// Validation rules that cause an error:
//   - YAML parse error
//   - Empty schema_version
//   - Duplicate role name
//   - Duplicate permission name
//   - SchemaPermission name does not match "resource:action" form or does not
//     match its own Resource/Action fields
//   - Role inherits an undefined role
//   - Role grants an undefined permission
//   - RPC requires an undefined permission
//   - Role inheritance contains a cycle
//   - RPC with unauthenticated=true also has required_permissions (contradiction)
func LoadEmbedded() (*SchemaRegistry, *casbin.Enforcer, error) {
	data, err := permissionsYAMLFS.ReadFile("permissions.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("permissions.yaml: read embedded file: %w", err)
	}
	return loadFromBytes(data)
}

// loadFromBytes is the testable entry point that accepts raw YAML bytes.
// Exported for tests via the companion test file.
func loadFromBytes(data []byte) (*SchemaRegistry, *casbin.Enforcer, error) {
	var doc schemaDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("permissions.yaml: parse: %w", err)
	}

	if strings.TrimSpace(doc.SchemaVersion) == "" {
		return nil, nil, fmt.Errorf("permissions.yaml: schema_version is required")
	}

	registry, err := buildRegistry(&doc)
	if err != nil {
		return nil, nil, err
	}

	enforcer, err := buildEnforcer(registry)
	if err != nil {
		return nil, nil, err
	}

	return registry, enforcer, nil
}

// buildRegistry walks the parsed document, validates every invariant, and
// produces the immutable SchemaRegistry. Called only from loadFromBytes.
func buildRegistry(doc *schemaDocument) (*SchemaRegistry, error) {
	reg := &SchemaRegistry{
		SchemaVersion:   doc.SchemaVersion,
		Roles:           make(map[string]*Role, len(doc.Roles)),
		Permissions:     make(map[string]*SchemaPermission, len(doc.Permissions)),
		RPCRequirements: make(map[string]*RPCRequirement, len(doc.RPCs)),
		RoleClosure:     make(map[string]map[string]struct{}, len(doc.Roles)),
	}

	// Step 1: register permissions and validate their names.
	for i := range doc.Permissions {
		p := doc.Permissions[i]
		if p.Name == "" {
			return nil, fmt.Errorf("permissions.yaml: permission at index %d has empty name", i)
		}
		expected := fmt.Sprintf("%s:%s", p.Resource, p.Action)
		if p.Name != expected {
			return nil, fmt.Errorf(
				"permissions.yaml: permission %q name does not match resource:action form (expected %q)",
				p.Name, expected,
			)
		}
		if _, dup := reg.Permissions[p.Name]; dup {
			return nil, fmt.Errorf("permissions.yaml: duplicate permission %q", p.Name)
		}
		reg.Permissions[p.Name] = &doc.Permissions[i]
	}

	// Step 2: register roles and validate their permission grants.
	for i := range doc.Roles {
		r := doc.Roles[i]
		if r.Name == "" {
			return nil, fmt.Errorf("permissions.yaml: role at index %d has empty name", i)
		}
		if _, dup := reg.Roles[r.Name]; dup {
			return nil, fmt.Errorf("permissions.yaml: duplicate role %q", r.Name)
		}
		for _, perm := range r.Permissions {
			if _, ok := reg.Permissions[perm]; !ok {
				return nil, fmt.Errorf(
					"permissions.yaml: role %q grants undefined permission %q",
					r.Name, perm,
				)
			}
		}
		reg.Roles[r.Name] = &doc.Roles[i]
	}

	// Step 3: validate role inheritance references and detect cycles.
	for name, role := range reg.Roles {
		for _, parent := range role.Inherits {
			if _, ok := reg.Roles[parent]; !ok {
				return nil, fmt.Errorf(
					"permissions.yaml: role %q inherits undefined role %q",
					name, parent,
				)
			}
		}
	}
	for name := range reg.Roles {
		if cycle := detectCycle(reg.Roles, name, nil, make(map[string]struct{})); cycle != nil {
			return nil, fmt.Errorf(
				"permissions.yaml: role inheritance cycle: %s",
				strings.Join(cycle, " -> "),
			)
		}
	}

	// Step 4: compute transitive permission closures.
	for name := range reg.Roles {
		closure := make(map[string]struct{})
		collectTransitive(reg.Roles, name, closure, make(map[string]struct{}))
		reg.RoleClosure[name] = closure
	}

	// Step 5: validate RPC requirements and register them.
	for method, req := range doc.RPCs {
		if req == nil {
			return nil, fmt.Errorf("permissions.yaml: rpc %q has nil entry", method)
		}
		if req.Unauthenticated && len(req.RequiredPermissions) > 0 {
			return nil, fmt.Errorf(
				"permissions.yaml: rpc %q contradiction: unauthenticated=true cannot have required_permissions",
				method,
			)
		}
		for _, perm := range req.RequiredPermissions {
			if _, ok := reg.Permissions[perm]; !ok {
				return nil, fmt.Errorf(
					"permissions.yaml: rpc %q requires undefined permission %q",
					method, perm,
				)
			}
		}
		// Denormalize: copy the map key into the struct so consumers
		// (interceptor, audit events) don't need the lookup key.
		entry := *req
		entry.Method = method
		reg.RPCRequirements[method] = &entry
	}

	return reg, nil
}

// detectCycle performs a DFS over the role inheritance graph starting at
// `start`. Returns the cycle path (including the repeated node) on detection,
// or nil if no cycle exists reachable from this starting node.
func detectCycle(roles map[string]*Role, start string, path []string, inStack map[string]struct{}) []string {
	if _, exists := inStack[start]; exists {
		// Found the repeated node; slice path from where it first appears.
		for i, n := range path {
			if n == start {
				return append(path[i:], start)
			}
		}
		return append(path, start)
	}
	role, ok := roles[start]
	if !ok {
		return nil
	}
	inStack[start] = struct{}{}
	path = append(path, start)
	for _, parent := range role.Inherits {
		if cycle := detectCycle(roles, parent, path, inStack); cycle != nil {
			return cycle
		}
	}
	delete(inStack, start)
	return nil
}

// collectTransitive walks the inheritance graph rooted at `role`, populating
// `out` with every permission directly or indirectly granted. `seen` is used
// to short-circuit already-visited nodes and must be distinct from any cycle
// detection state (cycles are rejected before this runs).
func collectTransitive(roles map[string]*Role, roleName string, out map[string]struct{}, seen map[string]struct{}) {
	if _, done := seen[roleName]; done {
		return
	}
	seen[roleName] = struct{}{}
	role, ok := roles[roleName]
	if !ok {
		return
	}
	for _, perm := range role.Permissions {
		out[perm] = struct{}{}
	}
	for _, parent := range role.Inherits {
		collectTransitive(roles, parent, out, seen)
	}
}

// buildEnforcer constructs a Casbin enforcer from the registry. Policies
// come from the YAML (via the role closures), not from Redis. Membership
// grouping rules (`g`) are installed later by internal/membership/store.go
// once the enforcer is wired in.
//
// Every role produces one `p` rule per permission it grants (directly OR
// transitively, using the pre-computed closure). Cross-tenant roles use
// "*" as the domain; tenant-scoped roles also use "*" because the domain
// in the `p` rule is the SCOPE of the rule's applicability, not the rule's
// binding. Actual per-tenant authorization comes from the `g` (membership)
// rules which ARE per-tenant. The matcher combines both at enforce time.
func buildEnforcer(reg *SchemaRegistry) (*casbin.Enforcer, error) {
	m, err := model.NewModelFromString(rbacModelString)
	if err != nil {
		return nil, fmt.Errorf("permissions: build casbin model: %w", err)
	}

	// Nil adapter: in-memory policies only. Membership (`g`) rules are added
	// later by the membership store's SetEnforcer hook.
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("permissions: build casbin enforcer: %w", err)
	}

	// Emit one `p` rule per (role, permission) pair using transitive closures.
	// Sort the iteration order for deterministic behavior (helpful for tests
	// and log output).
	roleNames := make([]string, 0, len(reg.Roles))
	for name := range reg.Roles {
		roleNames = append(roleNames, name)
	}
	sort.Strings(roleNames)

	for _, roleName := range roleNames {
		closure := reg.RoleClosure[roleName]
		permNames := make([]string, 0, len(closure))
		for perm := range closure {
			permNames = append(permNames, perm)
		}
		sort.Strings(permNames)
		for _, permName := range permNames {
			perm := reg.Permissions[permName]
			// buildRegistry already validated the reference exists.
			if _, err := enforcer.AddPolicy(roleName, "*", perm.Resource, perm.Action); err != nil {
				return nil, fmt.Errorf(
					"permissions: add policy (%s, *, %s, %s): %w",
					roleName, perm.Resource, perm.Action, err,
				)
			}
		}
	}

	slog.Info("permissions schema loaded",
		"roles", len(reg.Roles),
		"permissions", len(reg.Permissions),
		"rpcs", len(reg.RPCRequirements),
	)

	return enforcer, nil
}

// VerifyProtoCoverage asserts that every fully-qualified method path in
// `knownMethods` has an entry in the registry. Returns an error listing
// every unmapped method. Called at daemon startup after walking the
// protoregistry to enumerate compiled-in RPCs — the default-deny gate.
func (r *SchemaRegistry) VerifyProtoCoverage(knownMethods []string) error {
	var missing []string
	for _, m := range knownMethods {
		if _, ok := r.RPCRequirements[m]; !ok {
			missing = append(missing, m)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"permissions.yaml: %d proto RPC(s) have no authorization entry (default-deny would block them): %s",
		len(missing), strings.Join(missing, ", "),
	)
}

// GetRPCRequirement returns the requirement for a fully-qualified method path,
// or nil if the method is unmapped. The interceptor treats nil as default-deny
// and emits an authz_deny audit event with reason "rpc_not_in_schema".
func (r *SchemaRegistry) GetRPCRequirement(method string) *RPCRequirement {
	return r.RPCRequirements[method]
}

// ResolvePermissions returns the transitively-closed union of permissions
// granted by the given list of role names. Unknown role names are silently
// ignored (the caller likely carries roles from a stale token or an
// external identity provider mapping).
//
// Used by the daemon's GetAuthSchema handler and the dashboard's hasSchemaPermission
// helper (after fetching the schema) to resolve a session's effective
// permissions.
func (r *SchemaRegistry) ResolvePermissions(roles []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, name := range roles {
		closure, ok := r.RoleClosure[name]
		if !ok {
			continue
		}
		for perm := range closure {
			out[perm] = struct{}{}
		}
	}
	return out
}

// IsCrossTenantCaller returns true if any of the given role names refers
// to a role flagged `cross_tenant: true` in the schema. Used by RPC
// handlers that need to validate tenant-isolation on request parameters
// without hard-coding specific role names like "platform-operator".
//
// For example, UpdateTenantBilling is tenant-scoped (the interceptor
// authorized the action), but a non-cross-tenant caller may only modify
// THEIR OWN tenant's billing — not an arbitrary tenant named in the
// request. Handlers express this as:
//
//	if !auth.IsCrossTenantCaller(reg, identity.Roles) &&
//	    auth.TenantFromContext(ctx) != req.TenantId {
//	    return nil, status.Error(codes.PermissionDenied, "tenant mismatch")
//	}
//
// This check is not an authorization decision (the interceptor already
// made that). It's parameter validation: "does the request's tenant_id
// match the caller's context tenant, unless the caller is cross-tenant
// capable?"
//
// Returns false if the registry is nil (fail-closed — no cross-tenant
// bypass when the schema is not loaded, e.g. in unit tests).
func (r *SchemaRegistry) IsCrossTenantCaller(roleNames []string) bool {
	if r == nil {
		return false
	}
	for _, name := range roleNames {
		if role, ok := r.Roles[name]; ok && role.CrossTenant {
			return true
		}
	}
	return false
}

// KnownRoles returns a sorted list of defined role names. Used by the
// startup helm-role-binding validator to check that operator-configured
// claim mappings reference only known Gibson roles.
func (r *SchemaRegistry) KnownRoles() []string {
	names := make([]string, 0, len(r.Roles))
	for name := range r.Roles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
