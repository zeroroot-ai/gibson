package resolver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component"
)

// mockComponentStore is a test double for component.ComponentStore
type mockComponentStore struct {
	components map[string]*component.Component
	err        error
}

func newMockComponentStore() *mockComponentStore {
	return &mockComponentStore{
		components: make(map[string]*component.Component),
	}
}

func (m *mockComponentStore) key(kind component.ComponentKind, name string) string {
	return string(kind) + ":" + name
}

func (m *mockComponentStore) add(comp *component.Component) {
	m.components[m.key(comp.Kind, comp.Name)] = comp
}

func (m *mockComponentStore) GetByName(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.components[m.key(kind, name)], nil
}

// Implement remaining ComponentStore interface methods (not used in tests)
func (m *mockComponentStore) Create(ctx context.Context, comp *component.Component) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) List(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
	return nil, errors.New("not implemented")
}

func (m *mockComponentStore) ListAll(ctx context.Context) (map[component.ComponentKind][]*component.Component, error) {
	return nil, errors.New("not implemented")
}

func (m *mockComponentStore) Update(ctx context.Context, comp *component.Component) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) Delete(ctx context.Context, kind component.ComponentKind, name string) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) ListInstances(ctx context.Context, kind component.ComponentKind, name string) ([]component.ComponentInfo, error) {
	return nil, errors.New("not implemented")
}

// TestNewManifestLoader tests the constructor
func TestNewManifestLoader(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)

	assert.NotNil(t, loader)
	assert.NotNil(t, loader.store)
	assert.NotNil(t, loader.cache)
	assert.Equal(t, 0, len(loader.cache))
}

// TestCacheKey tests cache key generation
func TestCacheKey(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)

	tests := []struct {
		kind     component.ComponentKind
		name     string
		expected string
	}{
		{component.ComponentKindAgent, "test-agent", "agent:test-agent"},
		{component.ComponentKindTool, "port-scanner", "tool:port-scanner"},
		{component.ComponentKindPlugin, "k8s-plugin", "plugin:k8s-plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			key := loader.cacheKey(tt.kind, tt.name)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestLoadManifest_ComponentNotFound tests graceful handling of missing components
func TestLoadManifest_ComponentNotFound(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Load manifest for non-existent component
	manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "missing-agent")

	// Should return nil, nil (graceful degradation)
	assert.NoError(t, err)
	assert.Nil(t, manifest)
}

// TestLoadManifest_ComponentNoRepoPath tests handling of components without repo paths
func TestLoadManifest_ComponentNoRepoPath(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Add component without RepoPath
	comp := &component.Component{
		Kind:    component.ComponentKindAgent,
		Name:    "binary-agent",
		Version: "1.0.0",
		BinPath: "/path/to/binary",
		Source:  component.ComponentSourceExternal,
		Status:  component.ComponentStatusAvailable,
	}
	store.add(comp)

	// Load manifest
	manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "binary-agent")

	// Should return nil, nil (no manifest to load)
	assert.NoError(t, err)
	assert.Nil(t, manifest)

	// Verify nil is cached
	key := loader.cacheKey(component.ComponentKindAgent, "binary-agent")
	assert.Contains(t, loader.cache, key)
	assert.Nil(t, loader.cache[key])
}

// TestLoadManifest_ManifestNotFound tests handling of missing manifest files
func TestLoadManifest_ManifestNotFound(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create temp directory without manifest
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Add component with RepoPath but no manifest file
	comp := &component.Component{
		Kind:     component.ComponentKindAgent,
		Name:     "no-manifest",
		Version:  "1.0.0",
		RepoPath: tmpDir,
		Source:   component.ComponentSourceExternal,
		Status:   component.ComponentStatusAvailable,
	}
	store.add(comp)

	// Load manifest
	manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "no-manifest")

	// Should return nil, nil (manifest not found is graceful)
	assert.NoError(t, err)
	assert.Nil(t, manifest)

	// Verify nil is cached
	key := loader.cacheKey(component.ComponentKindAgent, "no-manifest")
	assert.Contains(t, loader.cache, key)
	assert.Nil(t, loader.cache[key])
}

// TestLoadManifest_ValidManifest tests successful manifest loading
func TestLoadManifest_ValidManifest(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create temp directory with valid manifest
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write valid manifest YAML
	manifestContent := `name: test-agent
version: 1.0.0
description: Test agent for unit testing
runtime:
  type: go
  entrypoint: ./test-agent
  port: 5000
dependencies:
  gibson: ">=0.20.0"
  components:
    - tool-scanner@1.0.0
    - plugin-k8s@2.1.0
`
	manifestPath := filepath.Join(tmpDir, "component.yaml")
	err = os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	require.NoError(t, err)

	// Add component with RepoPath
	comp := &component.Component{
		Kind:     component.ComponentKindAgent,
		Name:     "test-agent",
		Version:  "1.0.0",
		RepoPath: tmpDir,
		Source:   component.ComponentSourceExternal,
		Status:   component.ComponentStatusAvailable,
	}
	store.add(comp)

	// Load manifest
	manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "test-agent")

	// Should load successfully
	require.NoError(t, err)
	require.NotNil(t, manifest)
	assert.Equal(t, "test-agent", manifest.Name)
	assert.Equal(t, "1.0.0", manifest.Version)
	assert.Equal(t, "Test agent for unit testing", manifest.Description)
	assert.NotNil(t, manifest.Runtime)
	assert.Equal(t, component.RuntimeTypeGo, manifest.Runtime.Type)
	assert.Equal(t, 5000, manifest.Runtime.Port)
	assert.NotNil(t, manifest.Dependencies)
	assert.Equal(t, ">=0.20.0", manifest.Dependencies.Gibson)
	assert.Len(t, manifest.Dependencies.Components, 2)

	// Verify manifest is cached
	key := loader.cacheKey(component.ComponentKindAgent, "test-agent")
	assert.Contains(t, loader.cache, key)
	assert.Equal(t, manifest, loader.cache[key])
}

// TestLoadManifest_Caching tests that cache is used on subsequent loads
func TestLoadManifest_Caching(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create temp directory with valid manifest
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write manifest
	manifestContent := `name: cached-agent
version: 1.0.0
runtime:
  type: go
  entrypoint: ./agent
`
	manifestPath := filepath.Join(tmpDir, "component.yaml")
	err = os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	require.NoError(t, err)

	// Add component
	comp := &component.Component{
		Kind:     component.ComponentKindAgent,
		Name:     "cached-agent",
		Version:  "1.0.0",
		RepoPath: tmpDir,
		Source:   component.ComponentSourceExternal,
		Status:   component.ComponentStatusAvailable,
	}
	store.add(comp)

	// First load - from disk
	manifest1, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "cached-agent")
	require.NoError(t, err)
	require.NotNil(t, manifest1)

	// Delete manifest file to verify cache is used
	err = os.Remove(manifestPath)
	require.NoError(t, err)

	// Second load - should use cache
	manifest2, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "cached-agent")
	require.NoError(t, err)
	require.NotNil(t, manifest2)

	// Should be the same instance from cache
	assert.Equal(t, manifest1, manifest2)
}

// TestLoadManifest_StoreError tests handling of store errors
func TestLoadManifest_StoreError(t *testing.T) {
	store := newMockComponentStore()
	store.err = errors.New("store connection failed")
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Load manifest when store returns error
	manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "test-agent")

	// Should return error (store errors are not graceful)
	assert.Error(t, err)
	assert.Nil(t, manifest)
	assert.Contains(t, err.Error(), "failed to query component store")
}

// TestClearCache tests cache invalidation
func TestClearCache(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create temp directory with manifest
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	manifestContent := `name: test-agent
version: 1.0.0
runtime:
  type: go
  entrypoint: ./agent
`
	manifestPath := filepath.Join(tmpDir, "component.yaml")
	err = os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	require.NoError(t, err)

	comp := &component.Component{
		Kind:     component.ComponentKindAgent,
		Name:     "test-agent",
		Version:  "1.0.0",
		RepoPath: tmpDir,
		Source:   component.ComponentSourceExternal,
		Status:   component.ComponentStatusAvailable,
	}
	store.add(comp)

	// Load manifest to populate cache
	manifest1, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "test-agent")
	require.NoError(t, err)
	require.NotNil(t, manifest1)
	assert.Len(t, loader.cache, 1)

	// Clear cache
	loader.ClearCache()

	// Cache should be empty
	assert.Len(t, loader.cache, 0)

	// Load again should read from disk and re-cache
	manifest2, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "test-agent")
	require.NoError(t, err)
	require.NotNil(t, manifest2)
	assert.Len(t, loader.cache, 1)

	// Manifests should have same content but may be different instances
	assert.Equal(t, manifest1.Name, manifest2.Name)
	assert.Equal(t, manifest1.Version, manifest2.Version)
}

// TestLoadManifest_MultipleComponents tests loading manifests for multiple components
func TestLoadManifest_MultipleComponents(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create multiple components with manifests
	components := []struct {
		kind component.ComponentKind
		name string
	}{
		{component.ComponentKindAgent, "agent1"},
		{component.ComponentKindAgent, "agent2"},
		{component.ComponentKindTool, "tool1"},
		{component.ComponentKindPlugin, "plugin1"},
	}

	for _, tc := range components {
		tmpDir, err := os.MkdirTemp("", "manifest-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		manifestContent := fmt.Sprintf(`name: %s
version: 1.0.0
runtime:
  type: go
  entrypoint: ./%s
`, tc.name, tc.name)
		manifestPath := filepath.Join(tmpDir, "component.yaml")
		err = os.WriteFile(manifestPath, []byte(manifestContent), 0644)
		require.NoError(t, err)

		comp := &component.Component{
			Kind:     tc.kind,
			Name:     tc.name,
			Version:  "1.0.0",
			RepoPath: tmpDir,
			Source:   component.ComponentSourceExternal,
			Status:   component.ComponentStatusAvailable,
		}
		store.add(comp)
	}

	// Load all manifests
	for _, tc := range components {
		manifest, err := loader.LoadManifest(ctx, tc.kind, tc.name)
		require.NoError(t, err)
		require.NotNil(t, manifest)
		assert.Equal(t, tc.name, manifest.Name)
	}

	// All should be cached
	assert.Len(t, loader.cache, len(components))
}

// TestLoadManifest_ConcurrentAccess tests thread-safety of the loader
func TestLoadManifest_ConcurrentAccess(t *testing.T) {
	store := newMockComponentStore()
	loader := NewManifestLoader(store)
	ctx := context.Background()

	// Create component with manifest
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	manifestContent := `name: concurrent-agent
version: 1.0.0
runtime:
  type: go
  entrypoint: ./agent
`
	manifestPath := filepath.Join(tmpDir, "component.yaml")
	err = os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	require.NoError(t, err)

	comp := &component.Component{
		Kind:     component.ComponentKindAgent,
		Name:     "concurrent-agent",
		Version:  "1.0.0",
		RepoPath: tmpDir,
		Source:   component.ComponentSourceExternal,
		Status:   component.ComponentStatusAvailable,
	}
	store.add(comp)

	// Load manifest concurrently from multiple goroutines
	const numGoroutines = 10
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			manifest, err := loader.LoadManifest(ctx, component.ComponentKindAgent, "concurrent-agent")
			assert.NoError(t, err)
			assert.NotNil(t, manifest)
			assert.Equal(t, "concurrent-agent", manifest.Name)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Cache should have exactly one entry
	assert.Len(t, loader.cache, 1)
}
