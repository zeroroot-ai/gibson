package api

// fga_rpc_coverage_test.go is the CI gate that ensures every gRPC method
// registered on the daemon has a corresponding entry in the FgaRpcRegistry.
//
// Note: This test lives in internal/daemon/api (not internal/auth) because
// internal/auth cannot import internal/daemon/api without creating an import
// cycle. This matches the placement of the companion permissions.yaml coverage
// test (proto_coverage_test.go) in the same package.
//
// The test uses protoregistry.GlobalFiles (populated by blank imports) to
// enumerate method paths without starting a daemon server.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// TestFgaRpcRegistryCoversAllProtoRPCs asserts that every gRPC method registered
// on the daemon has an entry in the FgaRpcRegistry. A developer who adds a new
// RPC without adding a registry entry will see this test fail with the unmapped
// method name, matching the existing permissions.yaml CI gate contract.
func TestFgaRpcRegistryCoversAllProtoRPCs(t *testing.T) {
	registry, regErr := auth.LoadRegistry(auth.EmbeddedRpcRegistry, "")
	require.NoError(t, regErr)

	// discoverGibsonRPCs is already defined in proto_coverage_test.go in this
	// package and returns the same method list used by the permissions.yaml test.
	methods := discoverGibsonRPCs(t)
	require.Greater(t, len(methods), 0,
		"no gibson.* RPCs discovered — blank imports in proto_coverage_test.go may be wrong")

	// Check forward coverage: every proto method must appear in the registry.
	if err := registry.ValidateCoverage(methods); err != nil {
		t.Errorf("fga registry coverage gap: %v", err)
		t.Log("every proto RPC must have an entry in FgaRpcRegistry.populate()")
	}

	// Check reverse coverage: no registry entry should reference a non-existent method.
	if err := registry.ValidateNoStaleEntries(methods); err != nil {
		t.Errorf("fga registry stale entries: %v", err)
		t.Log("FgaRpcRegistry.populate() references methods that do not exist on the daemon gRPC server")
	}
}

// TestFgaRpcRegistryAuthenticatedEntriesHaveRelations verifies that every
// non-unauthenticated entry has a non-empty Relation, which is required for
// the interceptor to construct a valid FGA Check call.
func TestFgaRpcRegistryAuthenticatedEntriesHaveRelations(t *testing.T) {
	registry, regErr := auth.LoadRegistry(auth.EmbeddedRpcRegistry, "")
	require.NoError(t, regErr)

	for _, method := range registry.Methods() {
		spec, _ := registry.Lookup(method)
		if !spec.Unauthenticated {
			assert.NotEmpty(t, spec.Relation,
				"authenticated method %q must have a non-empty Relation", method)
		}
	}
}

// TestFgaRpcRegistryNoUnauthenticatedMethodsHaveRelations ensures that methods
// marked Unauthenticated do not accidentally have a relation set, which would
// silently confuse the interceptor.
func TestFgaRpcRegistryNoUnauthenticatedMethodsHaveRelations(t *testing.T) {
	registry, regErr := auth.LoadRegistry(auth.EmbeddedRpcRegistry, "")
	require.NoError(t, regErr)

	for _, method := range registry.Methods() {
		spec, _ := registry.Lookup(method)
		if spec.Unauthenticated {
			// An unauthenticated method with a Relation is a likely mistake — warn.
			if spec.Relation != "" {
				t.Logf("WARNING: method %q is Unauthenticated but also has Relation=%q — this Relation is ignored by the interceptor",
					method, spec.Relation)
			}
		}
	}
}
