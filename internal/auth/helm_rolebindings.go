package auth

import (
	"fmt"
	"sort"
	"strings"
)

// VerifyHelmRoleBindings checks that every Gibson role name referenced in
// the operator-supplied claim->role mapping in AuthConfig is actually
// defined in the loaded permissions.yaml schema. If an operator sets up
// oidc[].roleBindings or kubernetes.roleBindings with a role name that
// the YAML doesn't define (typo, stale config, etc.), the daemon refuses
// to start rather than silently dropping tokens into a nonexistent role.
//
// Called from grpc.go after LoadEmbedded() and before the interceptor is
// registered. Returns nil when all role bindings reference known roles.
//
// Added by the declarative-rbac-framework spec (Requirement 6, Requirement 8.16).
func VerifyHelmRoleBindings(registry *SchemaRegistry, cfg *AuthConfig) error {
	if registry == nil || cfg == nil {
		return nil
	}

	known := make(map[string]struct{}, len(registry.Roles))
	for name := range registry.Roles {
		known[name] = struct{}{}
	}

	// Collect unique undefined role names across every binding source so we
	// report them all at once rather than failing on the first typo.
	undefined := make(map[string]struct{})
	addIfUndefined := func(roleName string) {
		if _, ok := known[roleName]; !ok {
			undefined[roleName] = struct{}{}
		}
	}

	// OIDC issuer role bindings: claim value -> list of Gibson roles.
	for _, issuer := range cfg.OIDC {
		for _, roles := range issuer.RoleBindings {
			for _, r := range roles {
				addIfUndefined(r)
			}
		}
	}

	// Kubernetes SA role bindings: namespace:sa -> list of Gibson roles.
	if cfg.Kubernetes != nil {
		for _, roles := range cfg.Kubernetes.RoleBindings {
			for _, r := range roles {
				addIfUndefined(r)
			}
		}
	}

	if len(undefined) == 0 {
		return nil
	}

	names := make([]string, 0, len(undefined))
	for n := range undefined {
		names = append(names, n)
	}
	sort.Strings(names)

	knownList := registry.KnownRoles()
	return fmt.Errorf(
		"helm config references undefined Gibson roles in oidc/kubernetes role_bindings: [%s] — valid roles from permissions.yaml: [%s]",
		strings.Join(names, ", "),
		strings.Join(knownList, ", "),
	)
}
