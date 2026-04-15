package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalValidYAML is the smallest valid registry: version + empty entries.
const minimalValidYAML = `
version: 1
entries: []
`

// representativeYAML covers every shape an entry can take.
const representativeYAML = `
version: 1
entries:
  - method: /pkg.Service/Health
    unauthenticated: true
    description: Health probe.
  - method: /pkg.Service/RunMission
    relation: member
    description: Tenant-scoped, falls back to tenant from context.
  - method: /pkg.Service/Shutdown
    relation: platform_operator
    object: system_tenant:_system
    description: Literal object.
  - method: /pkg.Service/Heartbeat
    relation: can_execute
    object_from: component_system
    description: Named resolver.
`

// TestLoadRegistry_Embedded_Parses confirms the embedded canonical YAML
// parses successfully and contains a non-trivial number of entries. We don't
// pin an exact count here — that responsibility belongs to the parity test
// (TestYAMLRegistryMatchesGo) and the CI drift gate (registry_drift_test.go,
// audit build tag) — but a basic sanity floor catches accidental truncation
// of the file.
func TestLoadRegistry_Embedded_Parses(t *testing.T) {
	r, err := LoadRegistry(EmbeddedRpcRegistry, "")
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Greater(t, len(r.Methods()), 50,
		"embedded rpc_registry.yaml should contain every daemon RPC; got %d",
		len(r.Methods()))
}

// TestLoadRegistry_Representative covers all four entry shapes end-to-end.
func TestLoadRegistry_Representative(t *testing.T) {
	r, err := LoadRegistry([]byte(representativeYAML), "")
	require.NoError(t, err)
	require.NotNil(t, r)

	require.Equal(t, []string{
		"/pkg.Service/Health",
		"/pkg.Service/Heartbeat",
		"/pkg.Service/RunMission",
		"/pkg.Service/Shutdown",
	}, r.Methods())

	t.Run("unauthenticated", func(t *testing.T) {
		spec, ok := r.Lookup("/pkg.Service/Health")
		require.True(t, ok)
		assert.True(t, spec.Unauthenticated)
		assert.Empty(t, spec.Relation)
		assert.Nil(t, spec.ObjectFrom)
	})

	t.Run("tenant-from-context fallback (no ObjectFrom)", func(t *testing.T) {
		spec, ok := r.Lookup("/pkg.Service/RunMission")
		require.True(t, ok)
		assert.False(t, spec.Unauthenticated)
		assert.Equal(t, "member", spec.Relation)
		assert.Nil(t, spec.ObjectFrom, "no ObjectFrom: interceptor falls back to tenant")
	})

	t.Run("literal object", func(t *testing.T) {
		spec, ok := r.Lookup("/pkg.Service/Shutdown")
		require.True(t, ok)
		assert.Equal(t, "platform_operator", spec.Relation)
		require.NotNil(t, spec.ObjectFrom)
		got, err := spec.ObjectFrom(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "system_tenant:_system", got)
	})

	t.Run("named resolver", func(t *testing.T) {
		spec, ok := r.Lookup("/pkg.Service/Heartbeat")
		require.True(t, ok)
		assert.Equal(t, "can_execute", spec.Relation)
		require.NotNil(t, spec.ObjectFrom)
		got, err := spec.ObjectFrom(nil, context.Background())
		require.NoError(t, err)
		assert.Equal(t, "component:_system", got)
	})
}

// TestLoadRegistry_Override_Wins ensures the override file replaces the
// embedded YAML entirely (no merging).
func TestLoadRegistry_Override_Wins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
version: 1
entries:
  - method: /override.Only/Method
    relation: member
    description: From override.
`), 0o600))

	r, err := LoadRegistry([]byte(representativeYAML), path)
	require.NoError(t, err)
	assert.Equal(t, []string{"/override.Only/Method"}, r.Methods())

	_, embeddedPresent := r.Lookup("/pkg.Service/Health")
	assert.False(t, embeddedPresent, "embedded entries must NOT bleed through when override is set")
}

// TestLoadRegistry_Override_Missing_Fails verifies the fail-closed contract
// — a missing override file is fatal, never a silent fallback.
func TestLoadRegistry_Override_Missing_Fails(t *testing.T) {
	r, err := LoadRegistry(EmbeddedRpcRegistry, "/path/that/does/not/exist.yaml")
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "/path/that/does/not/exist.yaml",
		"error must name the offending path")
}

// TestLoadRegistry_StrictUnknownField_Rejects ensures schema typos surface
// at boot rather than being silently ignored.
func TestLoadRegistry_StrictUnknownField_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/M
    relation: member
    typo_field_that_does_not_exist: oops
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "yaml parse")
}

// TestLoadRegistry_DuplicateMethod_Rejects names the duplicate method.
func TestLoadRegistry_DuplicateMethod_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/Same
    relation: member
  - method: /pkg/Same
    relation: admin
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate method: /pkg/Same")
}

// TestLoadRegistry_RelationAndUnauth_Rejects guards mutual exclusion.
func TestLoadRegistry_RelationAndUnauth_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/M
    relation: member
    unauthenticated: true
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated entries must not set")
}

// TestLoadRegistry_BothObjectAndObjectFrom_Rejects guards mutual exclusion.
func TestLoadRegistry_BothObjectAndObjectFrom_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/M
    relation: member
    object: tenant:foo
    object_from: tenant_from_context
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestLoadRegistry_UnknownResolver_Rejects names the bad resolver and method.
func TestLoadRegistry_UnknownResolver_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/M
    relation: member
    object_from: not_a_real_resolver_xyz
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/pkg/M")
	assert.Contains(t, err.Error(), `unknown object_from resolver "not_a_real_resolver_xyz"`)
}

// TestLoadRegistry_BadObjectLiteral_Rejects covers the regex enforcement.
func TestLoadRegistry_BadObjectLiteral_Rejects(t *testing.T) {
	cases := []string{
		"no-colon-at-all",
		":missing-type",
		"missing-id:",
		"two:colons:bad",
		"has space:foo",
	}
	for _, lit := range cases {
		t.Run(lit, func(t *testing.T) {
			yaml := `
version: 1
entries:
  - method: /pkg/M
    relation: member
    object: ` + `"` + lit + `"` + `
`
			_, err := LoadRegistry([]byte(yaml), "")
			require.Error(t, err, "literal %q should be rejected", lit)
			assert.Contains(t, err.Error(), "invalid object literal")
		})
	}
}

// TestLoadRegistry_VersionMismatch_Rejects is the forward-compat guard.
func TestLoadRegistry_VersionMismatch_Rejects(t *testing.T) {
	yaml := `
version: 99
entries: []
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version 99")
}

// TestLoadRegistry_MissingMethod_Rejects ensures empty `method` is caught.
func TestLoadRegistry_MissingMethod_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - relation: member
    description: Forgot the method.
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing method")
}

// TestLoadRegistry_MissingRelation_Rejects ensures non-unauth entries must
// have a relation.
func TestLoadRegistry_MissingRelation_Rejects(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/M
    description: Has neither relation nor unauthenticated flag.
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relation is required")
}

// TestLoadRegistry_AggregatesErrors confirms all bad rows surface together
// — not one-error-at-a-time — so an operator fixes the YAML in one pass.
func TestLoadRegistry_AggregatesErrors(t *testing.T) {
	yaml := `
version: 1
entries:
  - method: /pkg/A
    object: badliteral
    relation: member
  - method: /pkg/B
    object_from: not_real
    relation: member
  - method: /pkg/C
    relation: member
    object: tenant:ok
  - method: /pkg/A
    relation: admin
`
	_, err := LoadRegistry([]byte(yaml), "")
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "/pkg/A")
	assert.Contains(t, msg, "/pkg/B")
	assert.Contains(t, msg, "duplicate method")
	assert.Contains(t, msg, "3 error(s)")
}
