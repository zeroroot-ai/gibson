package agentauth

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
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
				return []string{"component:nmap"}, nil
			case "can_read":
				return []string{"component:recon"}, nil
			case "can_configure":
				return []string{"component:gitlab"}, nil
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
	assert.Equal(t, "component:nmap", execNmap.ComponentRef)
	assert.Equal(t, "tool", execNmap.Kind)
	assert.Equal(t, "Network scanner", execNmap.Description)

	readRecon, ok := byName["read:agent:recon"]
	require.True(t, ok, "expected read:agent:recon capability")
	assert.Equal(t, "component:recon", readRecon.ComponentRef)
	assert.Equal(t, "agent", readRecon.Kind)
	assert.Equal(t, "Recon agent", readRecon.Description)

	cfgGitlab, ok := byName["configure:plugin:gitlab"]
	require.True(t, ok, "expected configure:plugin:gitlab capability")
	assert.Equal(t, "component:gitlab", cfgGitlab.ComponentRef)
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
				return []string{"component:nmap", "component:nmap"}, nil
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
	// FGA grants access to "component:ghost" but the registry has no live instance.
	auth := &mockAuthorizer{
		listObjectsFunc: func(_, relation, _ string) ([]string, error) {
			if relation == "can_execute" {
				return []string{"component:ghost"}, nil
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
	assert.Equal(t, "execute:unknown:ghost", caps[0].Name)
	assert.Equal(t, "component:ghost", caps[0].ComponentRef)
	assert.Equal(t, "unknown", caps[0].Kind)
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
				return []string{"component:subfinder"}, nil
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
				return []string{"nmap", "component:httpx"}, nil // "nmap" is malformed
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
				return []string{"component:nmap"}, nil
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
			assert.Equal(t, "component:nmap", object)
			return true, nil
		},
	}

	bridge := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	allowed, err := bridge.CheckExecution(context.Background(), "alice", "component:nmap")

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
	allowed, err := bridge.CheckExecution(context.Background(), "bob", "component:nmap")

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
	_, err := bridge.CheckExecution(context.Background(), "alice", "component:nmap")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func TestCheckExecution_MalformedComponentRef_ReturnsError(t *testing.T) {
	bridge := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())

	_, err := bridge.CheckExecution(context.Background(), "alice", "nmap") // missing "component:" prefix
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed componentRef")
}

func TestCheckExecution_EmptyComponentRef_ReturnsError(t *testing.T) {
	bridge := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())

	_, err := bridge.CheckExecution(context.Background(), "alice", "component:") // empty name
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed componentRef")
}

// ---------------------------------------------------------------------------
// Tests: parseComponentRef (internal)
// ---------------------------------------------------------------------------

func TestParseComponentRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantOK   bool
	}{
		{
			name:     "valid component ref",
			input:    "component:nmap",
			wantName: "nmap",
			wantOK:   true,
		},
		{
			name:     "valid component with hyphen",
			input:    "component:tool-nmap",
			wantName: "tool-nmap",
			wantOK:   true,
		},
		{
			name:   "missing prefix",
			input:  "nmap",
			wantOK: false,
		},
		{
			name:   "empty name after prefix",
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
			got, ok := parseComponentRef(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantName, got)
			}
		})
	}
}
