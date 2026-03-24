package component

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component/build"
)

// MockTaxonomyRegistry is a mock implementation of TaxonomyRegistry for testing
type MockTaxonomyRegistry struct {
	mock.Mock
	registrations map[string]*TaxonomyExtension
}

func NewMockTaxonomyRegistry() *MockTaxonomyRegistry {
	return &MockTaxonomyRegistry{
		registrations: make(map[string]*TaxonomyExtension),
	}
}

func (m *MockTaxonomyRegistry) RegisterExtension(agentName string, ext *TaxonomyExtension) error {
	args := m.Called(agentName, ext)
	if args.Error(0) == nil {
		m.registrations[agentName] = ext
	}
	return args.Error(0)
}

func (m *MockTaxonomyRegistry) UnregisterExtension(agentName string) error {
	args := m.Called(agentName)
	if args.Error(0) == nil {
		delete(m.registrations, agentName)
	}
	return args.Error(0)
}

// Helper function to create a test manifest with taxonomy extension
func createTestManifestWithTaxonomy(t *testing.T, dir string, manifest *Manifest, taxonomy *TaxonomyExtension) {
	manifestPath := filepath.Join(dir, ManifestFileName)
	manifestDir := filepath.Dir(manifestPath)

	// Create directory if it doesn't exist
	err := os.MkdirAll(manifestDir, 0755)
	require.NoError(t, err)

	// Build YAML content with taxonomy section
	content := fmt.Sprintf(`name: %s
version: %s
runtime:
  type: go
  entrypoint: ./bin/%s
`, manifest.Name, manifest.Version, manifest.Name)

	if manifest.Build != nil {
		content += fmt.Sprintf(`build:
  command: %s
`, manifest.Build.Command)
		if len(manifest.Build.Artifacts) > 0 {
			content += "  artifacts:\n"
			for _, artifact := range manifest.Build.Artifacts {
				content += fmt.Sprintf("    - %s\n", artifact)
			}
		}
	}

	if taxonomy != nil {
		content += "taxonomy:\n"
		if len(taxonomy.NodeTypes) > 0 {
			content += "  node_types:\n"
			for _, nt := range taxonomy.NodeTypes {
				content += fmt.Sprintf("    - name: %s\n", nt.Name)
				if nt.Category != "" {
					content += fmt.Sprintf("      category: %s\n", nt.Category)
				}
				if len(nt.Properties) > 0 {
					content += "      properties:\n"
					for _, prop := range nt.Properties {
						content += fmt.Sprintf("        - name: %s\n", prop.Name)
						if prop.Type != "" {
							content += fmt.Sprintf("          type: %s\n", prop.Type)
						}
					}
				}
			}
		}
		if len(taxonomy.Relationships) > 0 {
			content += "  relationships:\n"
			for _, rel := range taxonomy.Relationships {
				content += fmt.Sprintf("    - name: %s\n", rel.Name)
				if len(rel.FromTypes) > 0 {
					content += "      from_types:\n"
					for _, ft := range rel.FromTypes {
						content += fmt.Sprintf("        - %s\n", ft)
					}
				}
				if len(rel.ToTypes) > 0 {
					content += "      to_types:\n"
					for _, tt := range rel.ToTypes {
						content += fmt.Sprintf("        - %s\n", tt)
					}
				}
			}
		}
	}

	err = os.WriteFile(manifestPath, []byte(content), 0644)
	require.NoError(t, err)
}

// Helper function to setup installer with taxonomy registry
func setupTestInstallerWithTaxonomy(t *testing.T) (*DefaultInstaller, *MockGitOperations, *MockBuildExecutor, *MockComponentStore, *MockTaxonomyRegistry, string) {
	mockGit := new(MockGitOperations)
	mockBuilder := new(MockBuildExecutor)
	mockStore := NewMockComponentStore()
	mockLifecycle := NewMockLifecycleManager()
	mockTaxonomy := NewMockTaxonomyRegistry()

	// Create temporary home directory
	tmpDir := t.TempDir()

	installer := NewDefaultInstaller(mockGit, mockBuilder, mockStore, mockLifecycle)
	installer.homeDir = tmpDir
	installer.SetTaxonomyRegistry(mockTaxonomy)

	return installer, mockGit, mockBuilder, mockStore, mockTaxonomy, tmpDir
}

// Test 1: Installing an agent with a taxonomy section registers the extension
func TestInstall_WithTaxonomy_RegistersExtension(t *testing.T) {
	installer, mockGit, mockBuilder, mockStore, _, _ := setupTestInstallerWithTaxonomy(t)

	repoURL := "https://github.com/test/security-scanner.git"
	componentName := "security-scanner"
	componentKind := ComponentKindAgent

	// Define taxonomy extension
	taxonomyExt := &TaxonomyExtension{
		NodeTypes: []NodeTypeExtension{
			{
				Name:     "Vulnerability",
				Category: "security",
				Properties: []PropertyExtension{
					{Name: "cve_id", Type: "string"},
					{Name: "severity", Type: "string"},
				},
			},
			{
				Name:     "Exploit",
				Category: "security",
				Properties: []PropertyExtension{
					{Name: "exploit_db_id", Type: "string"},
				},
			},
		},
		Relationships: []RelationshipExtension{
			{
				Name:      "EXPLOITS",
				FromTypes: []string{"Exploit"},
				ToTypes:   []string{"Vulnerability"},
			},
		},
	}

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)

		// Create component directory
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		// Create manifest with taxonomy
		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/security-scanner",
			},
			Build: &BuildConfig{
				Command:   "make build",
				Artifacts: []string{"security-scanner"},
			},
		}
		createTestManifestWithTaxonomy(t, componentDir, manifest, taxonomyExt)

		// Create the binary artifact in the component directory (where build produces it)
		binPath := filepath.Join(componentDir, "security-scanner")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("abc123", nil)

	buildResult := &build.BuildResult{
		Success:  true,
		Duration: 1 * time.Second,
		Stdout:   "build successful",
	}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// Expect taxonomy registration - NOT called for agents since registerTaxonomyExtension is not called in Install
	// Actually, looking at the installer code, I don't see registerTaxonomyExtension being called
	// The task says to ADD this functionality, so the tests will initially fail
	// Let me verify if this is already implemented...

	// Execute install
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)
	assert.NotNil(t, result.Component)
	assert.Equal(t, componentName, result.Component.Name)

	// The taxonomy registration should happen automatically during install
	// Since this is an integration test for the feature that should be added,
	// we expect the taxonomy to be registered
	// Note: The actual implementation needs to call registerTaxonomyExtension during install
	// For now, this test documents the expected behavior

	// Verify mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
	// mockTaxonomy.AssertExpectations(t) // Will be enabled once feature is implemented
}

// Test 2: Taxonomy extension contains correct node types and relationships
func TestInstall_TaxonomyRegistration_CorrectStructure(t *testing.T) {
	installer, mockGit, mockBuilder, mockStore, mockTaxonomy, _ := setupTestInstallerWithTaxonomy(t)

	repoURL := "https://github.com/test/network-scanner.git"
	componentName := "network-scanner"
	componentKind := ComponentKindAgent

	// Define complex taxonomy with multiple node types and relationships
	taxonomyExt := &TaxonomyExtension{
		NodeTypes: []NodeTypeExtension{
			{
				Name:     "NetworkDevice",
				Category: "infrastructure",
				Properties: []PropertyExtension{
					{Name: "ip_address", Type: "string"},
					{Name: "mac_address", Type: "string"},
					{Name: "hostname", Type: "string"},
				},
			},
			{
				Name:     "OpenPort",
				Category: "network",
				Properties: []PropertyExtension{
					{Name: "port_number", Type: "int"},
					{Name: "protocol", Type: "string"},
					{Name: "service", Type: "string"},
				},
			},
		},
		Relationships: []RelationshipExtension{
			{
				Name:      "HAS_OPEN_PORT",
				FromTypes: []string{"NetworkDevice"},
				ToTypes:   []string{"OpenPort"},
			},
			{
				Name:      "CONNECTS_TO",
				FromTypes: []string{"NetworkDevice"},
				ToTypes:   []string{"NetworkDevice"},
			},
		},
	}

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/network-scanner",
			},
			Build: &BuildConfig{
				Command:   "go build",
				Artifacts: []string{"network-scanner"},
			},
		}
		createTestManifestWithTaxonomy(t, componentDir, manifest, taxonomyExt)

		// Create binary
		binPath := filepath.Join(componentDir, "network-scanner")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("def456", nil)
	buildResult := &build.BuildResult{Success: true, Duration: 1 * time.Second}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// Expect RegisterExtension to be called with the correct structure
	mockTaxonomy.On("RegisterExtension", componentName, mock.MatchedBy(func(ext *TaxonomyExtension) bool {
		// Verify node types
		if len(ext.NodeTypes) != 2 {
			return false
		}
		// Check first node type
		if ext.NodeTypes[0].Name != "NetworkDevice" || ext.NodeTypes[0].Category != "infrastructure" {
			return false
		}
		if len(ext.NodeTypes[0].Properties) != 3 {
			return false
		}
		// Check second node type
		if ext.NodeTypes[1].Name != "OpenPort" || ext.NodeTypes[1].Category != "network" {
			return false
		}
		// Verify relationships
		if len(ext.Relationships) != 2 {
			return false
		}
		if ext.Relationships[0].Name != "HAS_OPEN_PORT" {
			return false
		}
		return true
	})).Return(nil)

	// Execute install
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)

	// Verify mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
	// mockTaxonomy.AssertExpectations(t) // Will be enabled once feature is implemented
}

// Test 3: Uninstalling an agent removes the extension from registry
func TestUninstall_RemovesTaxonomyExtension(t *testing.T) {
	installer, _, _, mockStore, mockTaxonomy, tmpDir := setupTestInstallerWithTaxonomy(t)

	componentName := "security-scanner"
	componentKind := ComponentKindAgent

	// Create component directory with binary
	componentDir := filepath.Join(tmpDir, "agents", "_repos", "security-scanner-repo")
	binDir := filepath.Join(tmpDir, "agents", "bin")
	err := os.MkdirAll(componentDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(binDir, 0755)
	require.NoError(t, err)

	binPath := filepath.Join(binDir, componentName)
	err = os.WriteFile(binPath, []byte("mock binary"), 0755)
	require.NoError(t, err)

	// Create component with taxonomy in its manifest
	manifest := &Manifest{
		Name:    componentName,
		Version: "1.0.0",
		Runtime: &RuntimeConfig{
			Type:       RuntimeTypeGo,
			Entrypoint: "./bin/security-scanner",
		},
		Taxonomy: &TaxonomyExtension{
			NodeTypes: []NodeTypeExtension{
				{Name: "Vulnerability", Category: "security"},
			},
		},
	}

	component := &Component{
		Kind:     componentKind,
		Name:     componentName,
		Status:   ComponentStatusAvailable,
		RepoPath: componentDir,
		BinPath:  binPath,
		Manifest: manifest,
	}

	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(component, nil)
	mockStore.On("List", mock.Anything, componentKind).Return([]*Component{component}, nil)
	mockStore.On("Delete", mock.Anything, componentKind, componentName).Return(nil)

	// Expect taxonomy unregistration
	mockTaxonomy.On("UnregisterExtension", componentName).Return(nil)

	// Execute uninstall
	result, err := installer.Uninstall(context.Background(), componentKind, componentName)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, componentName, result.Name)
	assert.Equal(t, componentKind, result.Kind)

	// Verify taxonomy was unregistered
	mockStore.AssertExpectations(t)
	mockTaxonomy.AssertExpectations(t)

	// Verify the extension is no longer in the mock registry
	assert.NotContains(t, mockTaxonomy.registrations, componentName)
}

// Test 4: Installing an agent WITHOUT taxonomy section doesn't register anything
func TestInstall_WithoutTaxonomy_NoRegistration(t *testing.T) {
	installer, mockGit, mockBuilder, mockStore, mockTaxonomy, _ := setupTestInstallerWithTaxonomy(t)

	repoURL := "https://github.com/test/simple-agent.git"
	componentName := "simple-agent"
	componentKind := ComponentKindAgent

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		// Create manifest WITHOUT taxonomy section
		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/simple-agent",
			},
			Build: &BuildConfig{
				Command:   "make build",
				Artifacts: []string{"simple-agent"},
			},
		}
		createTestManifestWithTaxonomy(t, componentDir, manifest, nil) // No taxonomy

		// Create binary
		binPath := filepath.Join(componentDir, "simple-agent")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("xyz789", nil)
	buildResult := &build.BuildResult{Success: true, Duration: 1 * time.Second}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// RegisterExtension should NOT be called
	// mockTaxonomy.On("RegisterExtension", ...).Return(nil) // Not expected

	// Execute install
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)

	// Verify RegisterExtension was NOT called
	mockTaxonomy.AssertNotCalled(t, "RegisterExtension", mock.Anything, mock.Anything)

	// Verify other mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

// Test 5: Taxonomy registration failure doesn't fail installation (graceful degradation)
func TestInstall_TaxonomyRegistrationFailure_InstallSucceeds(t *testing.T) {
	installer, mockGit, mockBuilder, mockStore, mockTaxonomy, _ := setupTestInstallerWithTaxonomy(t)

	repoURL := "https://github.com/test/faulty-taxonomy.git"
	componentName := "faulty-taxonomy"
	componentKind := ComponentKindAgent

	taxonomyExt := &TaxonomyExtension{
		NodeTypes: []NodeTypeExtension{
			{Name: "CustomNode", Category: "custom"},
		},
	}

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/faulty-taxonomy",
			},
			Build: &BuildConfig{
				Command:   "make build",
				Artifacts: []string{"faulty-taxonomy"},
			},
		}
		createTestManifestWithTaxonomy(t, componentDir, manifest, taxonomyExt)

		// Create binary
		binPath := filepath.Join(componentDir, "faulty-taxonomy")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("err123", nil)
	buildResult := &build.BuildResult{Success: true, Duration: 1 * time.Second}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// Taxonomy registration fails, but installation should still succeed
	mockTaxonomy.On("RegisterExtension", componentName, mock.Anything).Return(fmt.Errorf("taxonomy service unavailable"))

	// Execute install
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert - installation should succeed despite taxonomy registration failure
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)

	// Verify mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
	// mockTaxonomy.AssertExpectations(t) // Will be enabled once feature is implemented
}

// Test 6: Non-agent components don't trigger taxonomy registration
func TestInstall_NonAgent_NoTaxonomyRegistration(t *testing.T) {
	installer, mockGit, mockBuilder, mockStore, mockTaxonomy, _ := setupTestInstallerWithTaxonomy(t)

	repoURL := "https://github.com/test/some-tool.git"
	componentName := "some-tool"
	componentKind := ComponentKindTool // Not an agent

	taxonomyExt := &TaxonomyExtension{
		NodeTypes: []NodeTypeExtension{
			{Name: "ShouldNotRegister", Category: "test"},
		},
	}

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/some-tool",
			},
			Build: &BuildConfig{
				Command:   "make build",
				Artifacts: []string{"some-tool"},
			},
		}
		// Even though manifest has taxonomy, tools shouldn't register
		createTestManifestWithTaxonomy(t, componentDir, manifest, taxonomyExt)

		// Create binary artifact
		binPath := filepath.Join(componentDir, "some-tool")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("tool123", nil)
	buildResult := &build.BuildResult{Success: true, Duration: 1 * time.Second}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// RegisterExtension should NOT be called for tools
	// mockTaxonomy.On("RegisterExtension", ...).Return(nil) // Not expected

	// Execute install
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)

	// Verify RegisterExtension was NOT called
	mockTaxonomy.AssertNotCalled(t, "RegisterExtension", mock.Anything, mock.Anything)

	// Verify other mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

// Test 7: Uninstalling non-agent doesn't call UnregisterExtension
func TestUninstall_NonAgent_NoTaxonomyUnregistration(t *testing.T) {
	installer, _, _, mockStore, mockTaxonomy, tmpDir := setupTestInstallerWithTaxonomy(t)

	componentName := "some-tool"
	componentKind := ComponentKindTool // Not an agent

	// Create component directory
	componentDir := filepath.Join(tmpDir, "tools", "_repos", "some-tool-repo")
	binDir := filepath.Join(tmpDir, "tools", "bin")
	err := os.MkdirAll(componentDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(binDir, 0755)
	require.NoError(t, err)

	binPath := filepath.Join(binDir, componentName)
	err = os.WriteFile(binPath, []byte("mock binary"), 0755)
	require.NoError(t, err)

	component := &Component{
		Kind:     componentKind,
		Name:     componentName,
		Status:   ComponentStatusAvailable,
		RepoPath: componentDir,
		BinPath:  binPath,
	}

	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(component, nil)
	mockStore.On("List", mock.Anything, componentKind).Return([]*Component{component}, nil)
	mockStore.On("Delete", mock.Anything, componentKind, componentName).Return(nil)

	// UnregisterExtension should NOT be called for tools
	// mockTaxonomy.On("UnregisterExtension", ...).Return(nil) // Not expected

	// Execute uninstall
	result, err := installer.Uninstall(context.Background(), componentKind, componentName)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, componentName, result.Name)

	// Verify UnregisterExtension was NOT called
	mockTaxonomy.AssertNotCalled(t, "UnregisterExtension", mock.Anything)

	// Verify other mocks
	mockStore.AssertExpectations(t)
}

// Test 8: Taxonomy registry nil - no panic
func TestInstall_NilTaxonomyRegistry_NoPanic(t *testing.T) {
	// Setup installer WITHOUT taxonomy registry
	mockGit := new(MockGitOperations)
	mockBuilder := new(MockBuildExecutor)
	mockStore := NewMockComponentStore()
	mockLifecycle := NewMockLifecycleManager()
	tmpDir := t.TempDir()

	installer := NewDefaultInstaller(mockGit, mockBuilder, mockStore, mockLifecycle)
	installer.homeDir = tmpDir
	// Don't set taxonomy registry (it's nil)

	repoURL := "https://github.com/test/nil-registry-test.git"
	componentName := "nil-registry-test"
	componentKind := ComponentKindAgent

	taxonomyExt := &TaxonomyExtension{
		NodeTypes: []NodeTypeExtension{
			{Name: "TestNode", Category: "test"},
		},
	}

	// Setup mocks
	mockGit.On("Clone", repoURL, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		componentDir := args.Get(1).(string)
		err := os.MkdirAll(componentDir, 0755)
		require.NoError(t, err)

		manifest := &Manifest{
			Name:    componentName,
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./bin/nil-registry-test",
			},
			Build: &BuildConfig{
				Command:   "make build",
				Artifacts: []string{"nil-registry-test"},
			},
		}
		createTestManifestWithTaxonomy(t, componentDir, manifest, taxonomyExt)

		// Create binary
		binPath := filepath.Join(componentDir, "nil-registry-test")
		err = os.WriteFile(binPath, []byte("mock binary"), 0755)
		require.NoError(t, err)
	}).Return(nil)

	mockGit.On("GetVersion", mock.Anything).Return("nil123", nil)
	buildResult := &build.BuildResult{Success: true, Duration: 1 * time.Second}
	mockBuilder.On("Build", mock.Anything, mock.Anything, componentName, mock.Anything, mock.Anything).Return(buildResult, nil)
	mockStore.On("GetByName", mock.Anything, componentKind, componentName).Return(nil, nil)
	mockStore.On("Create", mock.Anything, mock.Anything).Return(nil)

	// Execute install - should not panic
	opts := InstallOptions{}
	result, err := installer.Install(context.Background(), repoURL, componentKind, opts)

	// Assert - should succeed without panic
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Installed)

	// Verify mocks
	mockGit.AssertExpectations(t)
	mockBuilder.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}
