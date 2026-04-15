package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustLoadRegistry is the in-package test helper that replaces the old
// hand-coded registry constructor (removed in spec 21-yaml-rpc-authz-registry,
// task 4). All test sites use this so a future signature change to
// LoadRegistry only touches one line.
func mustLoadRegistry(tb testing.TB) *FgaRpcRegistry {
	tb.Helper()
	r, err := LoadRegistry(EmbeddedRpcRegistry, "")
	require.NoError(tb, err)
	require.NotNil(tb, r)
	return r
}

func TestLoadRegistry_FromEmbeddedYAML_Compiles(t *testing.T) {
	r := mustLoadRegistry(t)
	assert.Greater(t, len(r.entries), 0, "registry must have at least one entry")
}

func TestFgaRpcRegistry_Lookup_Found(t *testing.T) {
	r := mustLoadRegistry(t)

	spec, ok := r.Lookup("/gibson.daemon.v1.DaemonService/ListMissions")
	require.True(t, ok)
	assert.Equal(t, "member", spec.Relation)
	assert.False(t, spec.Unauthenticated)
}

func TestFgaRpcRegistry_Lookup_Unauthenticated(t *testing.T) {
	r := mustLoadRegistry(t)

	spec, ok := r.Lookup("/gibson.daemon.v1.DaemonService/Ping")
	require.True(t, ok)
	assert.True(t, spec.Unauthenticated)
	assert.Empty(t, spec.Relation)
}

func TestFgaRpcRegistry_Lookup_NotFound(t *testing.T) {
	r := mustLoadRegistry(t)

	_, ok := r.Lookup("/nonexistent.Service/Method")
	assert.False(t, ok)
}

func TestFgaRpcRegistry_PlatformOperatorMethods(t *testing.T) {
	r := mustLoadRegistry(t)

	platformOpMethods := []string{
		"/gibson.daemon.admin.v1.DaemonAdminService/ImpersonateTenant",
		"/gibson.daemon.admin.v1.DaemonAdminService/Shutdown",
	}
	for _, m := range platformOpMethods {
		spec, ok := r.Lookup(m)
		require.True(t, ok, "method %q not found", m)
		assert.Equal(t, "platform_operator", spec.Relation, "method %q should require platform_operator", m)
		require.NotNil(t, spec.ObjectFrom, "method %q should have a fixed object", m)
		obj, err := spec.ObjectFrom(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "system_tenant:_system", obj, "method %q should target system_tenant:_system", m)
	}
}

func TestFgaRpcRegistry_TenantScopedMethods(t *testing.T) {
	r := mustLoadRegistry(t)

	// Methods without an explicit ObjectFrom should use tenantFromCtx (nil ObjectFrom)
	spec, ok := r.Lookup("/gibson.daemon.v1.DaemonService/RunMission")
	require.True(t, ok)
	assert.Equal(t, "member", spec.Relation)
	// ObjectFrom is nil means the interceptor will use tenantFromCtx() fallback
	assert.Nil(t, spec.ObjectFrom)
}

func TestFgaRpcRegistry_Methods_Sorted(t *testing.T) {
	r := mustLoadRegistry(t)
	methods := r.Methods()
	require.NotEmpty(t, methods)

	// Verify sorted.
	for i := 1; i < len(methods); i++ {
		assert.LessOrEqual(t, methods[i-1], methods[i],
			"methods should be in sorted order at index %d", i)
	}
}

func TestConstObject(t *testing.T) {
	deriver := constObject("system_tenant:_system")
	require.NotNil(t, deriver)

	// Should work with nil request and nil context.
	obj, err := deriver(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "system_tenant:_system", obj)

	// Should work with non-nil context.
	obj, err = deriver(nil, context.Background())
	require.NoError(t, err)
	assert.Equal(t, "system_tenant:_system", obj)
}

func TestTenantFromCtx(t *testing.T) {
	deriver := tenantFromCtx()
	require.NotNil(t, deriver)

	// nil context should return error.
	_, err := deriver(nil, nil)
	assert.Error(t, err)

	// context without tenant.
	_, err = deriver(nil, context.Background())
	assert.Error(t, err)

	// context with tenant.
	ctx := ContextWithTenant(context.Background(), "acme")
	obj, err := deriver(nil, ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant:acme", obj)
}

func TestFgaRpcRegistry_ValidateCoverage(t *testing.T) {
	r := mustLoadRegistry(t)

	// All registered methods should pass coverage check.
	err := r.ValidateCoverage(r.Methods())
	assert.NoError(t, err)

	// A missing method should cause a failure.
	err = r.ValidateCoverage([]string{"/some.Service/Missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/some.Service/Missing")
}

func TestFgaRpcRegistry_ValidateNoStaleEntries(t *testing.T) {
	r := mustLoadRegistry(t)

	// All methods in the registry exist in the known list.
	err := r.ValidateNoStaleEntries(r.Methods())
	assert.NoError(t, err)

	// Stale entry in registry (registry has more than provided list).
	err = r.ValidateNoStaleEntries([]string{"/some.Other/Method"})
	require.Error(t, err)
}

func TestFgaRpcRegistry_NoDuplicates(t *testing.T) {
	// Verify that NewFgaRpcRegistry doesn't panic (duplicate detection via panic in add()).
	assert.NotPanics(t, func() {
		mustLoadRegistry(t)
	})
}

func TestFgaRpcRegistry_AllAuthenticatedEntriesHaveRelation(t *testing.T) {
	r := mustLoadRegistry(t)
	for method, spec := range r.entries {
		if !spec.Unauthenticated {
			assert.NotEmpty(t, spec.Relation,
				"authenticated method %q must have a non-empty Relation", method)
		}
	}
}
