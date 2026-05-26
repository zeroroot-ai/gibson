package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/component"
)

// mockLifecycleManager is a test double for component.LifecycleManager
type mockLifecycleManager struct {
	statuses      map[string]component.ComponentStatus
	startedComps  []string
	startError    error
	statusError   error
	startCallback func(comp *component.Component) error
}

func newMockLifecycleManager() *mockLifecycleManager {
	return &mockLifecycleManager{
		statuses:     make(map[string]component.ComponentStatus),
		startedComps: make([]string, 0),
	}
}

func (m *mockLifecycleManager) key(comp *component.Component) string {
	return string(comp.Kind) + ":" + comp.Name
}

func (m *mockLifecycleManager) setStatus(kind component.ComponentKind, name string, status component.ComponentStatus) {
	key := string(kind) + ":" + name
	m.statuses[key] = status
}

func (m *mockLifecycleManager) StartComponent(ctx context.Context, comp *component.Component) (int, error) {
	if m.startError != nil {
		return 0, m.startError
	}

	if m.startCallback != nil {
		if err := m.startCallback(comp); err != nil {
			return 0, err
		}
	}

	m.startedComps = append(m.startedComps, m.key(comp))
	m.setStatus(comp.Kind, comp.Name, component.ComponentStatusRunning)
	return 5000, nil
}

func (m *mockLifecycleManager) StopComponent(ctx context.Context, comp *component.Component) error {
	m.setStatus(comp.Kind, comp.Name, component.ComponentStatusStopped)
	return nil
}

func (m *mockLifecycleManager) RestartComponent(ctx context.Context, comp *component.Component) (int, error) {
	m.setStatus(comp.Kind, comp.Name, component.ComponentStatusRunning)
	return 5000, nil
}

func (m *mockLifecycleManager) GetStatus(ctx context.Context, comp *component.Component) (component.ComponentStatus, error) {
	if m.statusError != nil {
		return "", m.statusError
	}

	status, ok := m.statuses[m.key(comp)]
	if !ok {
		return component.ComponentStatusStopped, nil
	}
	return status, nil
}

// mockManifestLoader is a test double for ManifestLoader
type mockManifestLoader struct {
	manifests map[string]*component.Manifest
	err       error
}

func newMockManifestLoader() *mockManifestLoader {
	return &mockManifestLoader{
		manifests: make(map[string]*component.Manifest),
	}
}

func (m *mockManifestLoader) key(kind component.ComponentKind, name string) string {
	return string(kind) + ":" + name
}

func (m *mockManifestLoader) addManifest(kind component.ComponentKind, name string, manifest *component.Manifest) {
	m.manifests[m.key(kind, name)] = manifest
}

func (m *mockManifestLoader) LoadManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.manifests[m.key(kind, name)], nil
}

// mockMissionDefinition is a test double for MissionDefinition
type mockMissionDefinition struct {
	nodes        []MissionNode
	dependencies []MissionDependency
}

func (m *mockMissionDefinition) Nodes() []MissionNode {
	return m.nodes
}

func (m *mockMissionDefinition) Dependencies() []MissionDependency {
	return m.dependencies
}

// mockMissionNode is a test double for MissionNode
type mockMissionNode struct {
	id           string
	nodeType     string
	componentRef string
}

func (m *mockMissionNode) ID() string {
	return m.id
}

func (m *mockMissionNode) Type() string {
	return m.nodeType
}

func (m *mockMissionNode) ComponentRef() string {
	return m.componentRef
}

// mockMissionDependency is a test double for MissionDependency
type mockMissionDependency struct {
	kind    component.ComponentKind
	name    string
	version string
}

func (m *mockMissionDependency) Kind() component.ComponentKind {
	return m.kind
}

func (m *mockMissionDependency) Name() string {
	return m.name
}

func (m *mockMissionDependency) Version() string {
	return m.version
}

// Helper functions for creating test components and manifests
func createTestComponent(kind component.ComponentKind, name, version string, status component.ComponentStatus) *component.Component {
	return &component.Component{
		Kind:     kind,
		Name:     name,
		Version:  version,
		Status:   status,
		RepoPath: "/test/repo/" + name,
		BinPath:  "/test/bin/" + name,
		Source:   component.ComponentSourceExternal,
	}
}

func createManifestWithDeps(deps []string) *component.Manifest {
	return &component.Manifest{
		Dependencies: &component.ComponentDependencies{
			Components: deps,
		},
	}
}

// TestNewResolver tests the constructor
func TestNewResolver(t *testing.T) {
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	resolver := NewResolver(store, lifecycle, loader)

	assert.NotNil(t, resolver)
}

// TestResolveFromMission_SingleAgent tests resolving a mission with a single agent node
func TestResolveFromMission_SingleAgent(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add agent to store
	agent := createTestComponent(component.ComponentKindAgent, "test-agent", "1.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "test-agent", component.ComponentStatusRunning)

	// Create mission with single agent node
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{
				id:           "node1",
				nodeType:     "agent",
				componentRef: "test-agent",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 1, len(tree.Nodes))
	assert.Equal(t, 1, len(tree.Agents))
	assert.Equal(t, 0, len(tree.Tools))
	assert.Equal(t, 0, len(tree.Plugins))

	// Check the agent node
	agentNode := tree.GetNode(component.ComponentKindAgent, "test-agent")
	require.NotNil(t, agentNode)
	assert.Equal(t, component.ComponentKindAgent, agentNode.Kind)
	assert.Equal(t, "test-agent", agentNode.Name)
	assert.Equal(t, SourceMissionNode, agentNode.Source)
	assert.Equal(t, "node1", agentNode.SourceRef)
	assert.True(t, agentNode.Installed)
	assert.True(t, agentNode.Running)
}

// TestResolveFromMission_AgentWithToolDependencies tests resolving an agent that depends on tools
func TestResolveFromMission_AgentWithToolDependencies(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add components to store
	agent := createTestComponent(component.ComponentKindAgent, "recon-agent", "1.0.0", component.ComponentStatusRunning)
	tool1 := createTestComponent(component.ComponentKindTool, "port-scanner", "1.0.0", component.ComponentStatusRunning)
	tool2 := createTestComponent(component.ComponentKindTool, "nmap", "2.0.0", component.ComponentStatusRunning)

	store.add(agent)
	store.add(tool1)
	store.add(tool2)

	lifecycle.setStatus(component.ComponentKindAgent, "recon-agent", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindTool, "port-scanner", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindTool, "nmap", component.ComponentStatusRunning)

	// Add manifest for agent with tool dependencies
	agentManifest := createManifestWithDeps([]string{
		"tool:port-scanner@^1.0.0",
		"tool:nmap@>=2.0.0",
	})
	loader.addManifest(component.ComponentKindAgent, "recon-agent", agentManifest)

	// Create mission
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{
				id:           "recon",
				nodeType:     "agent",
				componentRef: "recon-agent",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 3, len(tree.Nodes), "Should have agent + 2 tools")
	assert.Equal(t, 1, len(tree.Agents))
	assert.Equal(t, 2, len(tree.Tools))
	assert.Equal(t, 0, len(tree.Plugins))

	// Check agent node has dependencies
	agentNode := tree.GetNode(component.ComponentKindAgent, "recon-agent")
	require.NotNil(t, agentNode)
	assert.Equal(t, 2, len(agentNode.DependsOn), "Agent should depend on 2 tools")

	// Check tool nodes
	tool1Node := tree.GetNode(component.ComponentKindTool, "port-scanner")
	require.NotNil(t, tool1Node)
	assert.Equal(t, "^1.0.0", tool1Node.Version)
	assert.Equal(t, SourceManifest, tool1Node.Source)
	assert.Equal(t, "recon-agent", tool1Node.SourceRef)

	tool2Node := tree.GetNode(component.ComponentKindTool, "nmap")
	require.NotNil(t, tool2Node)
	assert.Equal(t, ">=2.0.0", tool2Node.Version)
}

// TestResolveFromMission_TransitiveDependencies tests resolving transitive dependencies (agent -> tool -> plugin)
func TestResolveFromMission_TransitiveDependencies(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add components
	agent := createTestComponent(component.ComponentKindAgent, "k8s-agent", "1.0.0", component.ComponentStatusRunning)
	tool := createTestComponent(component.ComponentKindTool, "kubectl", "1.0.0", component.ComponentStatusRunning)
	plugin := createTestComponent(component.ComponentKindPlugin, "k8s-plugin", "1.0.0", component.ComponentStatusRunning)

	store.add(agent)
	store.add(tool)
	store.add(plugin)

	lifecycle.setStatus(component.ComponentKindAgent, "k8s-agent", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindTool, "kubectl", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindPlugin, "k8s-plugin", component.ComponentStatusRunning)

	// Agent depends on tool
	agentManifest := createManifestWithDeps([]string{"tool:kubectl@^1.0.0"})
	loader.addManifest(component.ComponentKindAgent, "k8s-agent", agentManifest)

	// Tool depends on plugin
	toolManifest := createManifestWithDeps([]string{"plugin:k8s-plugin@^1.0.0"})
	loader.addManifest(component.ComponentKindTool, "kubectl", toolManifest)

	// Create mission
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{
				id:           "k8s-scan",
				nodeType:     "agent",
				componentRef: "k8s-agent",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 3, len(tree.Nodes), "Should have agent + tool + plugin")
	assert.Equal(t, 1, len(tree.Agents))
	assert.Equal(t, 1, len(tree.Tools))
	assert.Equal(t, 1, len(tree.Plugins))

	// Check dependency chain: agent -> tool -> plugin
	agentNode := tree.GetNode(component.ComponentKindAgent, "k8s-agent")
	require.NotNil(t, agentNode)
	assert.Equal(t, 1, len(agentNode.DependsOn))

	toolNode := tree.GetNode(component.ComponentKindTool, "kubectl")
	require.NotNil(t, toolNode)
	assert.Equal(t, 1, len(toolNode.DependsOn))
	assert.Equal(t, 1, len(toolNode.RequiredBy))

	pluginNode := tree.GetNode(component.ComponentKindPlugin, "k8s-plugin")
	require.NotNil(t, pluginNode)
	assert.Equal(t, 0, len(pluginNode.DependsOn))
	assert.Equal(t, 1, len(pluginNode.RequiredBy))

	// Verify topological order
	order, err := tree.TopologicalOrder()
	require.NoError(t, err)
	assert.Equal(t, 3, len(order))
	// Plugin should come first (no dependencies), then tool, then agent
	assert.Equal(t, "plugin", string(order[0].Kind))
	assert.Equal(t, "tool", string(order[1].Kind))
	assert.Equal(t, "agent", string(order[2].Kind))
}

// TestResolveFromMission_ParallelNodes tests resolving a mission with parallel nodes
func TestResolveFromMission_ParallelNodes(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add multiple agents
	agent1 := createTestComponent(component.ComponentKindAgent, "agent-1", "1.0.0", component.ComponentStatusRunning)
	agent2 := createTestComponent(component.ComponentKindAgent, "agent-2", "1.0.0", component.ComponentStatusRunning)
	agent3 := createTestComponent(component.ComponentKindAgent, "agent-3", "1.0.0", component.ComponentStatusRunning)

	store.add(agent1)
	store.add(agent2)
	store.add(agent3)

	// Create mission with parallel agent nodes
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{id: "node1", nodeType: "agent", componentRef: "agent-1"},
			&mockMissionNode{id: "node2", nodeType: "agent", componentRef: "agent-2"},
			&mockMissionNode{id: "node3", nodeType: "agent", componentRef: "agent-3"},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 3, len(tree.Nodes))
	assert.Equal(t, 3, len(tree.Agents))
	assert.Equal(t, 3, len(tree.Roots), "All agents should be root nodes")
}

// TestResolveFromMission_CircularDependencies tests that circular dependencies are detected
func TestResolveFromMission_CircularDependencies(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add components
	agent := createTestComponent(component.ComponentKindAgent, "agent-a", "1.0.0", component.ComponentStatusRunning)
	tool := createTestComponent(component.ComponentKindTool, "tool-b", "1.0.0", component.ComponentStatusRunning)
	plugin := createTestComponent(component.ComponentKindPlugin, "plugin-c", "1.0.0", component.ComponentStatusRunning)

	store.add(agent)
	store.add(tool)
	store.add(plugin)

	// Create circular dependency: agent -> tool -> plugin -> agent
	agentManifest := createManifestWithDeps([]string{"tool:tool-b@1.0.0"})
	toolManifest := createManifestWithDeps([]string{"plugin:plugin-c@1.0.0"})
	pluginManifest := createManifestWithDeps([]string{"agent:agent-a@1.0.0"})

	loader.addManifest(component.ComponentKindAgent, "agent-a", agentManifest)
	loader.addManifest(component.ComponentKindTool, "tool-b", toolManifest)
	loader.addManifest(component.ComponentKindPlugin, "plugin-c", pluginManifest)

	// Create mission
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{
				id:           "start",
				nodeType:     "agent",
				componentRef: "agent-a",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert - should return error for circular dependency
	require.Error(t, err)
	assert.Nil(t, tree)
	var depErr *DependencyError
	require.ErrorAs(t, err, &depErr)
	assert.Equal(t, ErrCircularDependency, depErr.Code)
}

// TestResolveFromMission_MissingManifest tests that missing manifests continue with warning
func TestResolveFromMission_MissingManifest(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add agent to store but no manifest
	agent := createTestComponent(component.ComponentKindAgent, "test-agent", "1.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "test-agent", component.ComponentStatusRunning)

	// Don't add manifest to loader - it will return nil

	// Create mission
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{
				id:           "node1",
				nodeType:     "agent",
				componentRef: "test-agent",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert - should succeed but with incomplete tree
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 1, len(tree.Nodes))

	agentNode := tree.GetNode(component.ComponentKindAgent, "test-agent")
	require.NotNil(t, agentNode)
	assert.Equal(t, 0, len(agentNode.DependsOn), "Agent should have no dependencies without manifest")
}

// TestResolveFromMission_ExplicitDependencies tests resolving explicit mission dependencies
func TestResolveFromMission_ExplicitDependencies(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add components
	agent := createTestComponent(component.ComponentKindAgent, "required-agent", "2.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "required-agent", component.ComponentStatusRunning)

	// Create mission with explicit dependency
	mission := &mockMissionDefinition{
		dependencies: []MissionDependency{
			&mockMissionDependency{
				kind:    component.ComponentKindAgent,
				name:    "required-agent",
				version: ">=2.0.0",
			},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 1, len(tree.Nodes))

	agentNode := tree.GetNode(component.ComponentKindAgent, "required-agent")
	require.NotNil(t, agentNode)
	assert.Equal(t, ">=2.0.0", agentNode.Version)
	assert.Equal(t, SourceMissionExplicit, agentNode.Source)
}

// TestValidateState_AllComponentsHealthy tests validation when all components are healthy
func TestValidateState_AllComponentsHealthy(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with healthy components
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "test-agent", "1.0.0", component.ComponentStatusRunning)
	tool := createTestComponent(component.ComponentKindTool, "test-tool", "1.0.0", component.ComponentStatusRunning)

	store.add(agent)
	store.add(tool)
	lifecycle.setStatus(component.ComponentKindAgent, "test-agent", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindTool, "test-tool", component.ComponentStatusRunning)

	agentNode := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "test-agent",
		Version: "", // No version constraint - should pass
	}
	toolNode := &DependencyNode{
		Kind:    component.ComponentKindTool,
		Name:    "test-tool",
		Version: "", // No version constraint - should pass
	}

	tree.AddNode(agentNode)
	tree.AddNode(toolNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	result, err := resolver.ValidateState(ctx, tree)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, 2, result.TotalComponents)
	assert.Equal(t, 2, result.InstalledCount)
	assert.Equal(t, 2, result.RunningCount)
	assert.Equal(t, 2, result.HealthyCount)
	assert.Equal(t, 0, len(result.NotInstalled))
	assert.Equal(t, 0, len(result.NotRunning))
	assert.Equal(t, 0, len(result.Unhealthy))
	assert.Equal(t, 0, len(result.VersionMismatch))
	assert.Contains(t, result.Summary, "All 2 components")
}

// TestValidateState_SomeNotInstalled tests validation when some components are not installed
func TestValidateState_SomeNotInstalled(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with one installed and one missing component
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "installed-agent", "1.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "installed-agent", component.ComponentStatusRunning)

	// Don't add "missing-tool" to store

	agentNode := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "installed-agent",
		Version: "^1.0.0",
	}
	toolNode := &DependencyNode{
		Kind:    component.ComponentKindTool,
		Name:    "missing-tool",
		Version: "^1.0.0",
	}

	tree.AddNode(agentNode)
	tree.AddNode(toolNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	result, err := resolver.ValidateState(ctx, tree)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.Equal(t, 2, result.TotalComponents)
	assert.Equal(t, 1, result.InstalledCount)
	assert.Equal(t, 1, result.RunningCount)
	assert.Equal(t, 1, result.HealthyCount)
	assert.Equal(t, 1, len(result.NotInstalled))
	assert.Equal(t, 0, len(result.NotRunning))
	assert.Equal(t, "missing-tool", result.NotInstalled[0].Name)
	assert.Contains(t, result.Summary, "1 not installed")
}

// TestValidateState_SomeNotRunning tests validation when some components are not running
func TestValidateState_SomeNotRunning(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with one running and one stopped component
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "running-agent", "1.0.0", component.ComponentStatusRunning)
	tool := createTestComponent(component.ComponentKindTool, "stopped-tool", "1.0.0", component.ComponentStatusStopped)

	store.add(agent)
	store.add(tool)
	lifecycle.setStatus(component.ComponentKindAgent, "running-agent", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindTool, "stopped-tool", component.ComponentStatusStopped)

	agentNode := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "running-agent",
		Version: "^1.0.0",
	}
	toolNode := &DependencyNode{
		Kind:    component.ComponentKindTool,
		Name:    "stopped-tool",
		Version: "^1.0.0",
	}

	tree.AddNode(agentNode)
	tree.AddNode(toolNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	result, err := resolver.ValidateState(ctx, tree)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.Equal(t, 2, result.TotalComponents)
	assert.Equal(t, 2, result.InstalledCount)
	assert.Equal(t, 1, result.RunningCount)
	assert.Equal(t, 1, result.HealthyCount)
	assert.Equal(t, 0, len(result.NotInstalled))
	assert.Equal(t, 1, len(result.NotRunning))
	assert.Equal(t, "stopped-tool", result.NotRunning[0].Name)
	assert.Contains(t, result.Summary, "1 not running")
}

// TestValidateState_VersionMismatch tests validation with version constraint violations
func TestValidateState_VersionMismatch(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with version constraint
	tree := NewDependencyTree("test-mission")

	// Agent installed with version 1.0.0 but requires ^2.0.0
	agent := createTestComponent(component.ComponentKindAgent, "test-agent", "1.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "test-agent", component.ComponentStatusRunning)

	agentNode := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "test-agent",
		Version: "^2.0.0", // Requires 2.x but installed 1.0.0
	}

	tree.AddNode(agentNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	result, err := resolver.ValidateState(ctx, tree)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.TotalComponents)
	assert.Equal(t, 1, result.InstalledCount)
	assert.Equal(t, 1, result.RunningCount)
	assert.Equal(t, 1, len(result.VersionMismatch))
	assert.Equal(t, "test-agent", result.VersionMismatch[0].Node.Name)
	assert.Equal(t, "^2.0.0", result.VersionMismatch[0].RequiredVersion)
	assert.Equal(t, "1.0.0", result.VersionMismatch[0].ActualVersion)
	assert.Contains(t, result.Summary, "1 version mismatches")
}

// TestValidateState_NilTree tests validation with nil tree
func TestValidateState_NilTree(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	result, err := resolver.ValidateState(ctx, nil)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.TotalComponents)
	assert.Contains(t, result.Summary, "No dependencies")
}

// TestEnsureRunning_StartsStoppedComponents tests that EnsureRunning starts stopped components
func TestEnsureRunning_StartsStoppedComponents(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with one running and one stopped component
	tree := NewDependencyTree("test-mission")

	runningAgent := createTestComponent(component.ComponentKindAgent, "running-agent", "1.0.0", component.ComponentStatusRunning)
	stoppedAgent := createTestComponent(component.ComponentKindAgent, "stopped-agent", "1.0.0", component.ComponentStatusStopped)

	store.add(runningAgent)
	store.add(stoppedAgent)
	lifecycle.setStatus(component.ComponentKindAgent, "running-agent", component.ComponentStatusRunning)
	lifecycle.setStatus(component.ComponentKindAgent, "stopped-agent", component.ComponentStatusStopped)

	runningNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "running-agent",
		Installed: true,
		Running:   true,
		Healthy:   true,
		Component: runningAgent,
	}
	stoppedNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "stopped-agent",
		Installed: true,
		Running:   false,
		Healthy:   false,
		Component: stoppedAgent,
	}

	tree.AddNode(runningNode)
	tree.AddNode(stoppedNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	err := resolver.EnsureRunning(ctx, tree)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 1, len(lifecycle.startedComps), "Should have started only the stopped component")
	assert.Contains(t, lifecycle.startedComps, "agent:stopped-agent")
	assert.True(t, stoppedNode.Running)
	assert.True(t, stoppedNode.Healthy)
}

// TestEnsureRunning_RespectsTopologicalOrder tests that components are started in dependency order
func TestEnsureRunning_RespectsTopologicalOrder(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with dependencies: agent -> tool -> plugin
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "agent-a", "1.0.0", component.ComponentStatusStopped)
	tool := createTestComponent(component.ComponentKindTool, "tool-b", "1.0.0", component.ComponentStatusStopped)
	plugin := createTestComponent(component.ComponentKindPlugin, "plugin-c", "1.0.0", component.ComponentStatusStopped)

	store.add(agent)
	store.add(tool)
	store.add(plugin)

	pluginNode := &DependencyNode{
		Kind:      component.ComponentKindPlugin,
		Name:      "plugin-c",
		Installed: true,
		Running:   false,
		Component: plugin,
	}
	toolNode := &DependencyNode{
		Kind:      component.ComponentKindTool,
		Name:      "tool-b",
		Installed: true,
		Running:   false,
		Component: tool,
	}
	agentNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "agent-a",
		Installed: true,
		Running:   false,
		Component: agent,
	}

	tree.AddNode(pluginNode)
	tree.AddNode(toolNode)
	tree.AddNode(agentNode)

	// Set up dependency chain
	agentNode.AddDependency(toolNode)
	toolNode.AddDependency(pluginNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	err := resolver.EnsureRunning(ctx, tree)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 3, len(lifecycle.startedComps))

	// Verify order: plugin first, then tool, then agent
	assert.Equal(t, "plugin:plugin-c", lifecycle.startedComps[0])
	assert.Equal(t, "tool:tool-b", lifecycle.startedComps[1])
	assert.Equal(t, "agent:agent-a", lifecycle.startedComps[2])
}

// TestEnsureRunning_SkipsAlreadyRunning tests that already-running components are not restarted
func TestEnsureRunning_SkipsAlreadyRunning(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with all components already running
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "running-agent", "1.0.0", component.ComponentStatusRunning)
	store.add(agent)
	lifecycle.setStatus(component.ComponentKindAgent, "running-agent", component.ComponentStatusRunning)

	agentNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "running-agent",
		Installed: true,
		Running:   true,
		Healthy:   true,
		Component: agent,
	}

	tree.AddNode(agentNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	err := resolver.EnsureRunning(ctx, tree)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 0, len(lifecycle.startedComps), "Should not start any components")
}

// TestEnsureRunning_FailsFastOnStartError tests that EnsureRunning fails fast on start error
func TestEnsureRunning_FailsFastOnStartError(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Configure lifecycle manager to fail on start
	lifecycle.startError = errors.New("failed to start component")

	// Create tree with stopped component
	tree := NewDependencyTree("test-mission")

	agent := createTestComponent(component.ComponentKindAgent, "failing-agent", "1.0.0", component.ComponentStatusStopped)
	store.add(agent)

	agentNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "failing-agent",
		Installed: true,
		Running:   false,
		Component: agent,
	}

	tree.AddNode(agentNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	err := resolver.EnsureRunning(ctx, tree)

	// Assert
	require.Error(t, err)
	var depErr *DependencyError
	require.ErrorAs(t, err, &depErr)
	assert.Equal(t, ErrStartFailed, depErr.Code)
	assert.Equal(t, "failing-agent", depErr.Node.Name)
}

// TestEnsureRunning_SkipsNotInstalledComponents tests that not-installed components are skipped
func TestEnsureRunning_SkipsNotInstalledComponents(t *testing.T) {
	ctx := context.Background()

	// Setup
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Create tree with not-installed component
	tree := NewDependencyTree("test-mission")

	agentNode := &DependencyNode{
		Kind:      component.ComponentKindAgent,
		Name:      "not-installed-agent",
		Installed: false,
		Running:   false,
		Component: nil,
	}

	tree.AddNode(agentNode)

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	err := resolver.EnsureRunning(ctx, tree)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 0, len(lifecycle.startedComps), "Should not attempt to start not-installed components")
}

// TestResolveFromMission_ComplexScenario tests a complex mission with multiple dependencies
func TestResolveFromMission_ComplexScenario(t *testing.T) {
	ctx := context.Background()

	// Setup: Complex mission with:
	// - 2 agents in parallel
	// - Each agent has different tool dependencies
	// - Tools share a common plugin dependency
	store := newMockComponentStore()
	lifecycle := newMockLifecycleManager()
	loader := newMockManifestLoader()

	// Add components
	agent1 := createTestComponent(component.ComponentKindAgent, "recon-agent", "1.0.0", component.ComponentStatusRunning)
	agent2 := createTestComponent(component.ComponentKindAgent, "exploit-agent", "1.0.0", component.ComponentStatusRunning)
	tool1 := createTestComponent(component.ComponentKindTool, "nmap", "1.0.0", component.ComponentStatusRunning)
	tool2 := createTestComponent(component.ComponentKindTool, "metasploit", "1.0.0", component.ComponentStatusRunning)
	plugin := createTestComponent(component.ComponentKindPlugin, "network-plugin", "1.0.0", component.ComponentStatusRunning)

	store.add(agent1)
	store.add(agent2)
	store.add(tool1)
	store.add(tool2)
	store.add(plugin)

	// Set up manifests
	// recon-agent -> nmap -> network-plugin
	// exploit-agent -> metasploit -> network-plugin
	agent1Manifest := createManifestWithDeps([]string{"tool:nmap@^1.0.0"})
	agent2Manifest := createManifestWithDeps([]string{"tool:metasploit@^1.0.0"})
	tool1Manifest := createManifestWithDeps([]string{"plugin:network-plugin@^1.0.0"})
	tool2Manifest := createManifestWithDeps([]string{"plugin:network-plugin@^1.0.0"})

	loader.addManifest(component.ComponentKindAgent, "recon-agent", agent1Manifest)
	loader.addManifest(component.ComponentKindAgent, "exploit-agent", agent2Manifest)
	loader.addManifest(component.ComponentKindTool, "nmap", tool1Manifest)
	loader.addManifest(component.ComponentKindTool, "metasploit", tool2Manifest)

	// Create mission
	mission := &mockMissionDefinition{
		nodes: []MissionNode{
			&mockMissionNode{id: "recon", nodeType: "agent", componentRef: "recon-agent"},
			&mockMissionNode{id: "exploit", nodeType: "agent", componentRef: "exploit-agent"},
		},
	}

	// Execute
	resolver := NewResolver(store, lifecycle, loader)
	tree, err := resolver.ResolveFromMission(ctx, mission)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tree)
	assert.Equal(t, 5, len(tree.Nodes), "Should have 2 agents + 2 tools + 1 plugin")
	assert.Equal(t, 2, len(tree.Agents))
	assert.Equal(t, 2, len(tree.Tools))
	assert.Equal(t, 1, len(tree.Plugins))

	// Check that plugin is shared between both tools
	pluginNode := tree.GetNode(component.ComponentKindPlugin, "network-plugin")
	require.NotNil(t, pluginNode)
	assert.Equal(t, 2, len(pluginNode.RequiredBy), "Plugin should be required by both tools")

	// Verify topological order
	order, err := tree.TopologicalOrder()
	require.NoError(t, err)
	assert.Equal(t, 5, len(order))
	// Plugin should come first (no dependencies)
	assert.Equal(t, "plugin", string(order[0].Kind))
	assert.Equal(t, "network-plugin", order[0].Name)
}

// TestParseComponentDependency tests the parseComponentDependency helper function
func TestParseComponentDependency(t *testing.T) {
	tests := []struct {
		name            string
		depStr          string
		expectedKind    component.ComponentKind
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "explicit kind with version",
			depStr:          "tool:nmap@^1.0.0",
			expectedKind:    component.ComponentKindTool,
			expectedName:    "nmap",
			expectedVersion: "^1.0.0",
		},
		{
			name:            "implicit kind (agent) with version",
			depStr:          "test-agent@>=2.0.0",
			expectedKind:    component.ComponentKindAgent,
			expectedName:    "test-agent",
			expectedVersion: ">=2.0.0",
		},
		{
			name:            "plugin with version",
			depStr:          "plugin:k8s-plugin@~1.5.0",
			expectedKind:    component.ComponentKindPlugin,
			expectedName:    "k8s-plugin",
			expectedVersion: "~1.5.0",
		},
		{
			name:            "invalid format no version",
			depStr:          "tool:nmap",
			expectedKind:    "",
			expectedName:    "",
			expectedVersion: "",
		},
		{
			name:            "invalid format no name",
			depStr:          "@1.0.0",
			expectedKind:    component.ComponentKindAgent, // Parser treats "@1.0.0" as "agent:@1.0.0" -> agent with version 1.0.0
			expectedName:    "",                           // Empty name before @
			expectedVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, name, version := parseComponentDependency(tt.depStr)
			assert.Equal(t, tt.expectedKind, kind)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}
