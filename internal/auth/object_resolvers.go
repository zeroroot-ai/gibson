package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Object resolvers
//
// The YAML RPC registry (rpc_registry.yaml + rpc_registry_loader.go) refers
// to ObjectDeriver functions by string name. This file is the single
// registration site: every resolver name a YAML entry can use must be
// registered here at package init.
//
// Adding a new resolver:
//  1. Implement the ObjectDeriver function in this file.
//  2. Register it under a stable name in init() below.
//  3. Reference the name from rpc_registry.yaml.
//
// The strict YAML loader rejects unknown names at boot (fail-closed), and
// the CI drift gate (registry_drift_test.go) ensures no RPC ships without a
// registry entry. Together they guarantee every reachable code path uses
// only resolvers declared here — no string→code interpretation, no CEL,
// no template evaluation.

// ObjectDeriver constructors --------------------------------------------------
//
// constObject and tenantFromCtx live here (rather than in fga_rpc_registry.go)
// because they ARE resolvers — the RPC registry just happens to be their
// largest in-tree consumer. Other package files reference them by name, so
// they remain unexported.

// constObject returns an ObjectDeriver that always returns the given string.
// Used for cross-tenant or system-level RPCs whose object is always fixed.
func constObject(s string) ObjectDeriver {
	return func(_ any, _ context.Context) (string, error) {
		return s, nil
	}
}

// tenantFromCtx returns an ObjectDeriver that constructs "tenant:{tenantID}"
// from the request context. This is the default for tenant-scoped RPCs and is
// also invoked by FgaAuthzInterceptor as the fallback when an entry has no
// explicit ObjectFrom.
func tenantFromCtx() ObjectDeriver {
	return func(_ any, ctx context.Context) (string, error) {
		if ctx == nil {
			return "", errors.New("fga: nil context in tenantFromCtx")
		}
		tenant := TenantFromContext(ctx)
		if tenant == "" {
			return "", fmt.Errorf("fga: no tenant in context")
		}
		return "tenant:" + tenant, nil
	}
}

// Named registry --------------------------------------------------------------

var (
	resolverMu sync.RWMutex
	resolvers  = map[string]ObjectDeriver{}
)

// RegisterObjectResolver wires a named resolver into the package-level
// registry. Intended to be called from package init. Panics on duplicate
// registration to surface programmer errors at startup rather than runtime.
func RegisterObjectResolver(name string, d ObjectDeriver) {
	if name == "" {
		panic("auth: RegisterObjectResolver called with empty name")
	}
	if d == nil {
		panic("auth: RegisterObjectResolver called with nil deriver: " + name)
	}
	resolverMu.Lock()
	defer resolverMu.Unlock()
	if _, dup := resolvers[name]; dup {
		panic("auth: duplicate object resolver: " + name)
	}
	resolvers[name] = d
}

// lookupObjectResolver returns the resolver registered under name and whether
// it was found. Used by the YAML loader to translate string references in
// rpc_registry.yaml into ObjectDeriver values.
func lookupObjectResolver(name string) (ObjectDeriver, bool) {
	resolverMu.RLock()
	defer resolverMu.RUnlock()
	d, ok := resolvers[name]
	return d, ok
}

// KnownObjectResolvers returns a sorted snapshot of every registered resolver
// name. Used by the inspect CLI and tests; never mutates the underlying map.
func KnownObjectResolvers() []string {
	resolverMu.RLock()
	defer resolverMu.RUnlock()
	names := make([]string, 0, len(resolvers))
	for name := range resolvers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// init registers every name that today's RPC registry references. The set is
// deliberately minimal: only names with a concrete in-tree implementation
// appear here. Adding a new resolver requires (1) the implementation above,
// (2) a registration line below, (3) at least one YAML entry that uses it —
// otherwise the resolver is dead code and should not exist.
func init() {
	// Tenant-scoped RPCs that derive the FGA object from the request context.
	// This is also the fallback the FGA interceptor uses when an entry has no
	// ObjectFrom set, so registering it under a name is mostly for explicit
	// YAML entries that want to be self-documenting.
	RegisterObjectResolver("tenant_from_context", tenantFromCtx())

	// Platform-operator RPCs scoped to the well-known system tenant
	// (e.g. Shutdown, ImpersonateTenant).
	RegisterObjectResolver("system_tenant", constObject("system_tenant:_system"))

	// ComponentService RPCs scoped to the well-known system component
	// (every harness-callback / poll / submit-result entry uses this).
	RegisterObjectResolver("component_system", constObject("component:_system"))
}
