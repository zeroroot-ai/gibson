// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockAuthorizer is a test double for authz.Authorizer.
// It records calls and returns configurable responses.
type mockAuthorizer struct {
	// listObjectsFunc is called for each (user, relation, objectType) triple.
	// The key is "<user>|<relation>|<objectType>".
	listObjectsFunc func(user, relation, objectType string) ([]string, error)

	// checkFunc is called for each (user, relation, object) triple.
	checkFunc func(user, relation, object string) (bool, error)
}

func (m *mockAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if m.checkFunc != nil {
		return m.checkFunc(user, relation, object)
	}
	return false, nil
}

func (m *mockAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	results := make([]bool, len(checks))
	return results, nil
}

func (m *mockAuthorizer) Write(_ context.Context, _ []authz.Tuple) error {
	return nil
}

func (m *mockAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error {
	return nil
}

func (m *mockAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	if m.listObjectsFunc != nil {
		return m.listObjectsFunc(user, relation, objectType)
	}
	return []string{}, nil
}

func (m *mockAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return []string{}, nil
}

func (m *mockAuthorizer) StoreID() string { return "test-store" }
func (m *mockAuthorizer) ModelID() string { return "test-model" }
func (m *mockAuthorizer) Close() error    { return nil }

// ensure mockAuthorizer satisfies the interface at compile time.
var _ authz.Authorizer = (*mockAuthorizer)(nil)

// ---------------------------------------------------------------------------

// mockRegistry is a test double for component.ComponentRegistry.
type mockRegistry struct {
	discoverAllFunc func(tenant, kind string) ([]component.ComponentInfo, error)
}

func (m *mockRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}

func (m *mockRegistry) Deregister(_ context.Context, _, _, _, _ string) error {
	return nil
}

func (m *mockRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error {
	return nil
}

func (m *mockRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func (m *mockRegistry) DiscoverAll(_ context.Context, tenant, kind string) ([]component.ComponentInfo, error) {
	if m.discoverAllFunc != nil {
		return m.discoverAllFunc(tenant, kind)
	}
	return []component.ComponentInfo{}, nil
}

func (m *mockRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func (m *mockRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func (m *mockRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

// ensure mockRegistry satisfies the interface at compile time.
var _ component.ComponentRegistry = (*mockRegistry)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nilWriter{}, nil))
}

// nilWriter discards all log output in tests.
type nilWriter struct{}

func (nilWriter) Write(p []byte) (int, error) { return len(p), nil }

// ---------------------------------------------------------------------------
// Tests: NewFGABridge
// ---------------------------------------------------------------------------

func TestNewFGABridge_NilLogger_UsesDefault(t *testing.T) {
	bridge := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, nil)
	assert.NotNil(t, bridge)
	assert.NotNil(t, bridge.logger)
}

// ---------------------------------------------------------------------------
// Tests: ResolveCapabilities
// ---------------------------------------------------------------------------

func TestResolveCapabilities_UserWithThreeComponents(t *testing.T) {
	// Arrange: three components registered in the registry.
	registryComponents := []component.ComponentInfo{
		{Name: "nmap", Kind: "tool", Metadata: map[string]string{"description": "Network scanner"}},
		{Name: "recon", Kind: "agent", Metadata: map[string]string{"description": "Recon agent"}},
		{Name: "gitlab", Kind: "plugin", Metadata: map[string]string{"description": "GitLab integration"}},
	}

	// User can execute nmap, read recon, configure gitlab.
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			assert.Equal(t, "user:alice", user)
			assert.Equal(t, "component", objectType)
			switch relation {
			case "can_execute":
				return []string{"component:tool/nmap"}, nil
			case "can_read":
				return []string{"component:agent/recon"}, nil
			case "can_configure":
				return []string{"component:plugin/gitlab"}, nil
			}
			return []string{}, nil
		},
	}

	reg := &mockRegistry{
		discoverAllFunc: func(tenant, kind string) ([]component.ComponentInfo, error) {
			assert.Equal(t, "acme", tenant)
			assert.Equal(t, "", kind)
			return registryComponents, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())

	// Act.
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	// Assert.
	require.NoError(t, err)
	require.Len(t, caps, 3)

	byName := make(map[string]Capability, len(caps))
	for _, c := range caps {
		byName[c.Name] = c
	}

	execNmap, ok := byName["execute:tool:nmap"]
	require.True(t, ok, "expected execute:tool:nmap capability")
	assert.Equal(t, "component:tool/nmap", execNmap.ComponentRef)
	assert.Equal(t, "tool", execNmap.Kind)
	assert.Equal(t, "Network scanner", execNmap.Description)

	readRecon, ok := byName["read:agent:recon"]
	require.True(t, ok, "expected read:agent:recon capability")
	assert.Equal(t, "component:agent/recon", readRecon.ComponentRef)
	assert.Equal(t, "agent", readRecon.Kind)
	assert.Equal(t, "Recon agent", readRecon.Description)

	cfgGitlab, ok := byName["configure:plugin:gitlab"]
	require.True(t, ok, "expected configure:plugin:gitlab capability")
	assert.Equal(t, "component:plugin/gitlab", cfgGitlab.ComponentRef)
	assert.Equal(t, "plugin", cfgGitlab.Kind)
	assert.Equal(t, "GitLab integration", cfgGitlab.Description)
}

func TestResolveCapabilities_UserWithNoAccess_ReturnsEmptySlice(t *testing.T) {
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, _, _ string) ([]string, error) {
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "bob", "acme")

	require.NoError(t, err)
	assert.NotNil(t, caps, "should return empty slice, not nil")
	assert.Len(t, caps, 0)
}

func TestResolveCapabilities_DeduplicatesSameCapability(t *testing.T) {
	// Both can_execute and can_read return the same component.
	// The resulting capabilities must still be distinct (execute vs read).
	// Also verify that if can_execute returns the same component twice (e.g.,
	// FGA returns duplicates) we get only one entry.
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				// Simulate FGA returning duplicate entries.
				return []string{"component:tool/nmap", "component:tool/nmap"}, nil
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{
				{Name: "nmap", Kind: "tool"},
			}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	assert.Len(t, caps, 1, "duplicate FGA entries must be deduplicated")
	assert.Equal(t, "execute:tool:nmap", caps[0].Name)
}

func TestResolveCapabilities_ComponentNotInRegistry_StillEmitsCapability(t *testing.T) {
	// FGA grants access to "component:tool/ghost" but the registry has no live instance.
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"component:tool/ghost"}, nil
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	require.Len(t, caps, 1)
	assert.Equal(t, "execute:tool:ghost", caps[0].Name)
	assert.Equal(t, "component:tool/ghost", caps[0].ComponentRef)
	assert.Equal(t, "tool", caps[0].Kind)
}

func TestResolveCapabilities_KindlessObject_Skipped(t *testing.T) {
	// A kind-less ("component:ghost") or unknown-kind object cannot form a valid
	// component:<kind>/<name> ref, so no capability is emitted for it (ADR-0015:
	// never authorize against an object whose kind is unknown).
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"component:ghost", "component:sensor/x"}, nil
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	require.Empty(t, caps, "kind-less / unknown-kind objects must be skipped")
}

func TestResolveCapabilities_SystemTenantComponentsIncluded(t *testing.T) {
	// DiscoverAll already merges system + tenant components per the registry
	// contract. Verify that components returned from the (merged) registry are
	// matched against FGA objects that reference them.
	systemComponent := component.ComponentInfo{
		Name:     "subfinder",
		Kind:     "tool",
		TenantID: "_system",
		Metadata: map[string]string{"description": "Subdomain finder"},
	}

	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"component:tool/subfinder"}, nil
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			// DiscoverAll returns system-scoped components merged with tenant.
			return []component.ComponentInfo{systemComponent}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	require.Len(t, caps, 1)
	assert.Equal(t, "execute:tool:subfinder", caps[0].Name)
	assert.Equal(t, "Subdomain finder", caps[0].Description)
}

func TestResolveCapabilities_AuthorizerError_PropagatesError(t *testing.T) {
	expectedErr := errors.New("FGA unavailable")
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, _, _ string) ([]string, error) {
			return nil, expectedErr
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	_, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func TestResolveCapabilities_RegistryError_PropagatesError(t *testing.T) {
	expectedErr := errors.New("Redis connection lost")
	auth := &mockAuthorizer{}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return nil, expectedErr
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	_, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func TestResolveCapabilities_MalformedFGAObject_Skipped(t *testing.T) {
	// FGA returns an object without the "component:" prefix — must be skipped.
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"nmap", "component:tool/httpx"}, nil // "nmap" is malformed
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{
				{Name: "httpx", Kind: "tool"},
			}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	require.Len(t, caps, 1, "malformed object should be skipped, valid one retained")
	assert.Equal(t, "execute:tool:httpx", caps[0].Name)
}

func TestResolveCapabilities_MultipleInstancesSameComponent_NoDuplicateMetadata(t *testing.T) {
	// Registry returns two live instances of the same tool (e.g., two nmap pods).
	// Only one capability entry should appear.
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"component:tool/nmap"}, nil
			}
			return []string{}, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{
				{Name: "nmap", Kind: "tool", InstanceID: "inst-1"},
				{Name: "nmap", Kind: "tool", InstanceID: "inst-2"},
			}, nil
		},
	}

	bridge := NewFGABridge(auth, reg, noopLogger())
	caps, err := bridge.ResolveCapabilities(context.Background(), "alice", "acme")

	require.NoError(t, err)
	assert.Len(t, caps, 1)
}

// ---------------------------------------------------------------------------
// Tests: CheckExecution
// ---------------------------------------------------------------------------

func TestCheckExecution_Allowed_ReturnsTrue(t *testing.T) {
	auth := &mockAuthorizer{
		checkFunc: func(user, relation, object string) (bool, error) {
			assert.Equal(t, "user:alice", user)
			assert.Equal(t, "can_execute", relation)
			assert.Equal(t, "component:tool/nmap", object)
			return true, nil
		},
	}

	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	allowed, err := bridge.CheckExecution(context.Background(), "user:alice", "component:tool/nmap")

	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestCheckExecution_Denied_ReturnsFalse(t *testing.T) {
	auth := &mockAuthorizer{
		checkFunc: func(_, _, _ string) (bool, error) {
			return false, nil
		},
	}

	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	allowed, err := bridge.CheckExecution(context.Background(), "user:bob", "component:tool/nmap")

	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestCheckExecution_AuthorizerError_PropagatesError(t *testing.T) {
	expectedErr := errors.New("FGA timeout")
	auth := &mockAuthorizer{
		checkFunc: func(_, _, _ string) (bool, error) {
			return false, expectedErr
		},
	}

	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	_, err := bridge.CheckExecution(context.Background(), "user:alice", "component:tool/nmap")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func TestCheckExecution_MalformedComponentRef_ReturnsError(t *testing.T) {
	bridge := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())

	_, err := bridge.CheckExecution(context.Background(), "user:alice", "nmap") // missing "component:" prefix
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed componentRef")
}

func TestCheckExecution_EmptyComponentRef_ReturnsError(t *testing.T) {
	bridge := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())

	_, err := bridge.CheckExecution(context.Background(), "user:alice", "component:") // empty name
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed componentRef")
}

// A bare id is refused rather than silently read as a human user: turning
// whatever the caller passed into "user:<x>" is how an executing component came
// to be authorized as somebody else.
func TestCheckExecution_UntypedSubject_ReturnsError(t *testing.T) {
	auth := &mockAuthorizer{
		checkFunc: func(_, _, _ string) (bool, error) {
			t.Fatal("Check must not run for an untyped subject")
			return true, nil
		},
	}
	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())

	_, err := bridge.CheckExecution(context.Background(), "alice", "component:tool/nmap")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed subject")
}

// A component principal is checked against the narrowed component-scope
// relation, so it needs the per-component enablement written for IT — not just
// whatever its enroller can reach.
func TestCheckExecution_ComponentPrincipal_UsesComponentScopeRelation(t *testing.T) {
	for _, principal := range []string{
		"agent_principal:acct-1",
		"tool_principal:acct-2",
		"plugin_principal:acct-3",
	} {
		t.Run(principal, func(t *testing.T) {
			var gotUser, gotRelation string
			auth := &mockAuthorizer{
				checkFunc: func(user, relation, _ string) (bool, error) {
					gotUser, gotRelation = user, relation
					return true, nil
				},
			}
			bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())

			allowed, err := bridge.CheckExecution(context.Background(), principal, "component:tool/nmap")
			require.NoError(t, err)
			assert.True(t, allowed)
			assert.Equal(t, principal, gotUser)
			assert.Equal(t, "can_execute_as_component", gotRelation)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: ResolveComponentCapabilities
// ---------------------------------------------------------------------------

// resolveComponentFixture wires an authorizer where alice can execute+read two
// components and the principal holds a per-component execute enablement on one
// of them.
func resolveComponentFixture(t *testing.T, principalGrants map[string][]string) (*FGABridge, *mockAuthorizer) {
	t.Helper()
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, _ string) ([]string, error) {
			if user == "user:alice" {
				switch relation {
				case "can_execute":
					return []string{"component:tool/nmap", "component:tool/nuclei"}, nil
				case "can_read":
					return []string{"component:tool/nmap"}, nil
				}
				return nil, nil
			}
			return principalGrants[relation], nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(_, _ string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{
				{Name: "nmap", Kind: "tool", InstanceID: "i1"},
				{Name: "nuclei", Kind: "tool", InstanceID: "i2"},
			}, nil
		},
	}
	return NewFGABridge(auth, reg, noopLogger()), auth
}

// The registered component gets ITS OWN grants, not its enroller's set. Before
// the intersection, registration recorded everything the enroller could reach.
func TestResolveComponentCapabilities_RecordsPrincipalGrantsNotEnrollers(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		"component_execute_enabled": {"component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.NoError(t, err)

	names := make([]string, 0, len(caps))
	for _, c := range caps {
		names = append(names, c.Name)
	}
	assert.ElementsMatch(t, []string{"execute:tool:nmap"}, names,
		"only the principal's own execute grant may be recorded")
}

// A tuple the principal holds but its enroller cannot reach is not granted.
func TestResolveComponentCapabilities_IntersectsWithOwnerReach(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		// The owner can read nmap but NOT nuclei, and cannot configure anything.
		"component_read_enabled":  {"component:tool/nmap", "component:tool/nuclei"},
		"component_write_enabled": {"component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.NoError(t, err)

	names := make([]string, 0, len(caps))
	for _, c := range caps {
		names = append(names, c.Name)
	}
	assert.ElementsMatch(t, []string{"read:tool:nmap"}, names,
		"read:nuclei and configure:nmap are outside the owner's reach")
}

// A registration with no component principal records nothing rather than
// falling back to the enroller's capabilities.
func TestResolveComponentCapabilities_NoPrincipal_RecordsNothing(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		"component_execute_enabled": {"component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(context.Background(), "", "alice", "acme")
	require.NoError(t, err)
	assert.Empty(t, caps)
}

// A subject that is not a component principal — a human id passed by mistake —
// records nothing rather than the enroller's whole set.
func TestResolveComponentCapabilities_NonPrincipalSubject_RecordsNothing(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		"component_execute_enabled": {"component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(
		context.Background(), "user:alice", "alice", "acme")
	require.NoError(t, err)
	assert.Empty(t, caps)
}

// A failure resolving the owner's reach is reported, not treated as "the owner
// reaches nothing" or, worse, "the principal reaches everything".
func TestResolveComponentCapabilities_OwnerResolutionFailure_IsReported(t *testing.T) {
	expectedErr := errors.New("FGA timeout")
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, _, _ string) ([]string, error) {
			if user == "user:alice" {
				return nil, expectedErr
			}
			return nil, nil
		},
	}
	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())

	_, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

// A failure enumerating the principal's own grants is reported too.
func TestResolveComponentCapabilities_PrincipalResolutionFailure_IsReported(t *testing.T) {
	expectedErr := errors.New("FGA timeout")
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, _, _ string) ([]string, error) {
			if user == "user:alice" {
				return []string{"component:tool/nmap"}, nil
			}
			return nil, expectedErr
		},
	}
	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())

	_, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

// A malformed object reference from FGA is skipped rather than recorded as a
// capability nobody can name.
func TestResolveComponentCapabilities_MalformedObjectRef_IsSkipped(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		"component_execute_enabled": {"not-a-component-ref", "component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.NoError(t, err)

	require.Len(t, caps, 1)
	assert.Equal(t, "execute:tool:nmap", caps[0].Name)
}

// The same grant reachable twice is recorded once.
func TestResolveComponentCapabilities_DeduplicatesRepeatedGrants(t *testing.T) {
	bridge, _ := resolveComponentFixture(t, map[string][]string{
		"component_execute_enabled": {"component:tool/nmap", "component:tool/nmap"},
	})

	caps, err := bridge.ResolveComponentCapabilities(
		context.Background(), "agent_principal:acct-1", "alice", "acme")
	require.NoError(t, err)
	assert.Len(t, caps, 1)
}

// ---------------------------------------------------------------------------
// Tests: parseComponentRef (internal)
// ---------------------------------------------------------------------------

func TestParseComponentRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind string
		wantName string
		wantOK   bool
	}{
		{
			name:     "valid kind-qualified ref",
			input:    "component:tool/nmap",
			wantKind: "tool",
			wantName: "nmap",
			wantOK:   true,
		},
		{
			name:     "valid agent ref with hyphen",
			input:    "component:agent/scan-controller",
			wantKind: "agent",
			wantName: "scan-controller",
			wantOK:   true,
		},
		{
			name:   "kind-less object fails closed",
			input:  "component:nmap",
			wantOK: false,
		},
		{
			name:   "unknown kind fails closed",
			input:  "component:sensor/nmap",
			wantOK: false,
		},
		{
			name:   "missing prefix",
			input:  "nmap",
			wantOK: false,
		},
		{
			name:   "empty after prefix",
			input:  "component:",
			wantOK: false,
		},
		{
			name:   "empty string",
			input:  "",
			wantOK: false,
		},
		{
			name:   "wrong type prefix",
			input:  "tenant:acme",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, got, ok := parseComponentRef(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantKind, kind)
				assert.Equal(t, tc.wantName, got)
			}
		})
	}
}

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (m *mockAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
