package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKnownObjectResolvers_ContainsRegisteredNames asserts the init()-time
// registrations are visible and the snapshot is sorted.
func TestKnownObjectResolvers_ContainsRegisteredNames(t *testing.T) {
	got := KnownObjectResolvers()

	// init() registers exactly these three.
	want := []string{
		"component_system",
		"system_tenant",
		"tenant_from_context",
	}

	for _, name := range want {
		assert.Contains(t, got, name, "init() must register %q", name)
	}

	// Snapshot must be sorted (callers — including the inspect CLI — depend on it).
	sortedCopy := append([]string(nil), got...)
	sort.Strings(sortedCopy)
	assert.Equal(t, sortedCopy, got, "KnownObjectResolvers must return a sorted snapshot")
}

// TestLookupObjectResolver_RoundTrip verifies registered resolvers are
// retrievable by name and behave as expected.
func TestLookupObjectResolver_RoundTrip(t *testing.T) {
	t.Run("system_tenant returns constant", func(t *testing.T) {
		d, ok := lookupObjectResolver("system_tenant")
		require.True(t, ok)
		got, err := d(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "system_tenant:_system", got)
	})

	t.Run("component_system returns constant", func(t *testing.T) {
		d, ok := lookupObjectResolver("component_system")
		require.True(t, ok)
		got, err := d(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "component:_system", got)
	})

	t.Run("tenant_from_context reads tenant from context", func(t *testing.T) {
		d, ok := lookupObjectResolver("tenant_from_context")
		require.True(t, ok)

		ctx := ContextWithTenant(context.Background(), "acme")
		got, err := d(nil, ctx)
		require.NoError(t, err)
		assert.Equal(t, "tenant:acme", got)
	})

	t.Run("tenant_from_context falls back to system tenant when not set", func(t *testing.T) {
		// TenantFromContext always falls back to SystemTenant ("_system") when
		// no tenant is in context (see tenant.go), so the resolver succeeds and
		// returns "tenant:_system". The resolver's empty-string error branch is
		// defensive dead code today; tests document actual behavior.
		d, ok := lookupObjectResolver("tenant_from_context")
		require.True(t, ok)

		got, err := d(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "tenant:_system", got)
	})

	t.Run("tenant_from_context errors on nil context", func(t *testing.T) {
		d, ok := lookupObjectResolver("tenant_from_context")
		require.True(t, ok)

		_, err := d(nil, nil)
		require.Error(t, err)
	})

	t.Run("unknown name returns false", func(t *testing.T) {
		_, ok := lookupObjectResolver("does_not_exist")
		assert.False(t, ok)
	})
}

// TestRegisterObjectResolver_DuplicatePanics catches programming errors at
// init time rather than at first use.
func TestRegisterObjectResolver_DuplicatePanics(t *testing.T) {
	// Register a fresh name once — must succeed.
	const name = "test_duplicate_resolver_xyz"
	deriver := constObject("test:1")
	RegisterObjectResolver(name, deriver)
	t.Cleanup(func() {
		// Best-effort cleanup so subsequent test runs (in -count=N mode) don't
		// keep tripping over the same registration. We don't expose Unregister
		// in production code, so reach into the package-private map directly.
		resolverMu.Lock()
		delete(resolvers, name)
		resolverMu.Unlock()
	})

	// Re-registering the same name MUST panic with the name in the message.
	assert.PanicsWithValue(t, "auth: duplicate object resolver: "+name, func() {
		RegisterObjectResolver(name, deriver)
	})
}

// TestRegisterObjectResolver_RejectsEmptyName guards an obvious caller bug.
func TestRegisterObjectResolver_RejectsEmptyName(t *testing.T) {
	assert.Panics(t, func() {
		RegisterObjectResolver("", constObject("x:y"))
	})
}

// TestRegisterObjectResolver_RejectsNilDeriver guards an obvious caller bug.
func TestRegisterObjectResolver_RejectsNilDeriver(t *testing.T) {
	assert.Panics(t, func() {
		RegisterObjectResolver("test_nil_deriver_xyz", nil)
	})
}
