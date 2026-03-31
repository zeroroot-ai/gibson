package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/component/resolver"
	"github.com/zero-day-ai/gibson/internal/mission"
	"gopkg.in/yaml.v3"
)

var missionPlanCmd = &cobra.Command{
	Use:   "plan -f workflow.yaml",
	Short: "Analyze mission dependencies without executing",
	Long: `Plan a mission by analyzing its dependency tree without executing it.

This command resolves all component dependencies required by a mission workflow
and displays them in a structured format. It shows:
  - All agents, tools, and plugins required by the mission
  - Transitive dependencies (components required by other components)
  - Current installation and runtime status of each component
  - Which components require each dependency

The plan command is useful for:
  - Understanding mission requirements before execution
  - Verifying all dependencies are installed and running
  - Generating dependency manifests for GitOps pipelines
  - Troubleshooting missing or unhealthy components

OUTPUT FORMATS:
  - text (default): Human-readable grouped by component kind
  - yaml: Structured YAML suitable for automation
  - json: Structured JSON for programmatic processing

The plan command does NOT:
  - Execute the mission or any of its components
  - Start or stop any components
  - Modify any state in the system
  - Require the daemon to be running`,
	Example: `  # Plan a mission and see all dependencies
  gibson mission plan -f workflows/recon.yaml

  # Output as YAML for GitOps pipeline
  gibson mission plan -f workflows/scan.yaml --output yaml > deps.yaml

  # Output as JSON for scripting
  gibson mission plan -f workflows/audit.yaml --output json | jq '.agents'`,
	RunE: runMissionPlan,
}

var (
	missionPlanFile   string
	missionPlanOutput string
)

func init() {
	missionCmd.AddCommand(missionPlanCmd)

	missionPlanCmd.Flags().StringVarP(&missionPlanFile, "file", "f", "", "Workflow YAML file path (required)")
	missionPlanCmd.Flags().StringVar(&missionPlanOutput, "output", "text", "Output format: text, yaml, json")
	missionPlanCmd.MarkFlagRequired("file")
}

// runMissionPlan implements the mission plan command
func runMissionPlan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Validate output format
	switch missionPlanOutput {
	case "text", "yaml", "json":
		// valid
	default:
		return internal.WrapError(internal.ExitConfigError,
			fmt.Sprintf("invalid output format: %s (must be text, yaml, or json)", missionPlanOutput), nil)
	}

	// Validate workflow file exists
	if missionPlanFile == "" {
		return internal.WrapError(internal.ExitConfigError,
			"workflow file path required: use -f flag", nil)
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(missionPlanFile)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError,
			fmt.Sprintf("failed to resolve workflow path: %s", missionPlanFile), err)
	}

	// Check file exists
	if _, err := os.Stat(absPath); err != nil {
		return internal.WrapError(internal.ExitConfigError,
			fmt.Sprintf("workflow file not found: %s", absPath), err)
	}

	// Parse workflow file
	workflowDef, err := mission.ParseDefinition(absPath)
	if err != nil {
		return internal.WrapError(internal.ExitError,
			fmt.Sprintf("failed to parse workflow file: %s", absPath), err)
	}

	// Get Gibson home directory (for loading manifests)
	homeDir := os.Getenv("GIBSON_HOME")
	if homeDir == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to get home directory", err)
		}
		homeDir = filepath.Join(userHome, ".gibson")
	}

	// Create stub component store (planning mode doesn't query components)
	componentStore := &stubComponentStore{homeDir: homeDir}

	// Create manifest loader that loads from the component store
	manifestLoader := &storeManifestLoader{
		store:   componentStore,
		homeDir: homeDir,
	}

	// Create lifecycle manager (stubbed - we're not starting/stopping anything)
	lifecycleManager := &stubLifecycleManager{
		store: componentStore,
	}

	// Create dependency resolver
	depResolver := resolver.NewResolver(componentStore, lifecycleManager, manifestLoader)

	// Create mission definition adapter
	missionAdapter := &missionDefinitionAdapter{def: workflowDef}

	// Resolve dependencies from mission
	tree, err := depResolver.ResolveFromMission(ctx, missionAdapter)
	if err != nil {
		return internal.WrapError(internal.ExitError,
			"failed to resolve mission dependencies", err)
	}

	// Format and output the dependency tree
	return formatDependencyTree(cmd, tree, missionPlanOutput)
}

// formatDependencyTree outputs the dependency tree in the requested format
func formatDependencyTree(cmd *cobra.Command, tree *resolver.DependencyTree, outputFormat string) error {
	switch outputFormat {
	case "json":
		return outputTreeJSON(cmd, tree)
	case "yaml":
		return outputTreeYAML(cmd, tree)
	case "text":
		return outputTreeText(cmd, tree)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

// outputTreeJSON outputs the tree as JSON
func outputTreeJSON(cmd *cobra.Command, tree *resolver.DependencyTree) error {
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

// outputTreeYAML outputs the tree as YAML
func outputTreeYAML(cmd *cobra.Command, tree *resolver.DependencyTree) error {
	data, err := yaml.Marshal(tree)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

// outputTreeText outputs the tree in human-readable text format
func outputTreeText(cmd *cobra.Command, tree *resolver.DependencyTree) error {
	out := cmd.OutOrStdout()

	// Header
	fmt.Fprintf(out, "Mission: %s\n", tree.MissionRef)
	fmt.Fprintf(out, "Resolved at: %s\n\n", tree.ResolvedAt.Format("2006-01-02T15:04:05Z07:00"))

	// Output agents
	if len(tree.Agents) > 0 {
		fmt.Fprintf(out, "Agents (%d):\n", len(tree.Agents))
		for _, node := range tree.Agents {
			outputNodeText(out, node, "  ")
		}
		fmt.Fprintln(out)
	}

	// Output tools
	if len(tree.Tools) > 0 {
		fmt.Fprintf(out, "Tools (%d):\n", len(tree.Tools))
		for _, node := range tree.Tools {
			outputNodeText(out, node, "  ")
		}
		fmt.Fprintln(out)
	}

	// Output plugins
	if len(tree.Plugins) > 0 {
		fmt.Fprintf(out, "Plugins (%d):\n", len(tree.Plugins))
		for _, node := range tree.Plugins {
			outputNodeText(out, node, "  ")
		}
		fmt.Fprintln(out)
	}

	// Summary
	if len(tree.Nodes) == 0 {
		fmt.Fprintln(out, "No dependencies found")
	}

	return nil
}

// outputNodeText outputs a single dependency node in text format
func outputNodeText(out io.Writer, node *resolver.DependencyNode, indent string) {
	// Node header with version and status
	versionStr := node.Version
	if versionStr == "" {
		versionStr = "*"
	}
	statusStr := getNodeStatusText(node)

	fmt.Fprintf(out, "%s%s (%s) - %s\n", indent, node.Name, versionStr, statusStr)

	// Show actual version if installed and different from required
	if node.Installed && node.ActualVersion != "" && node.ActualVersion != node.Version {
		fmt.Fprintf(out, "%s  Actual version: %s\n", indent, node.ActualVersion)
	}

	// Show what requires this component
	if len(node.RequiredBy) > 0 {
		requiredByNames := make([]string, 0, len(node.RequiredBy))
		for _, parent := range node.RequiredBy {
			requiredByNames = append(requiredByNames, parent.Name)
		}
		if len(requiredByNames) == 1 && requiredByNames[0] == "" {
			// Root dependency from mission
			fmt.Fprintf(out, "%s  Required by: mission\n", indent)
		} else {
			fmt.Fprintf(out, "%s  Required by: %v\n", indent, requiredByNames)
		}
	} else {
		fmt.Fprintf(out, "%s  Required by: mission\n", indent)
	}

	// Show dependencies if any
	if len(node.DependsOn) > 0 {
		dependencyNames := make([]string, 0, len(node.DependsOn))
		for _, dep := range node.DependsOn {
			dependencyNames = append(dependencyNames, dep.Name)
		}
		fmt.Fprintf(out, "%s  Depends on: %v\n", indent, dependencyNames)
	}

	fmt.Fprintln(out)
}

// getNodeStatusText returns a human-readable status string for a node
func getNodeStatusText(node *resolver.DependencyNode) string {
	if !node.Installed {
		return "not-installed"
	}
	if !node.Running {
		return "installed-not-running"
	}
	if !node.Healthy {
		return "running-unhealthy"
	}
	return "running"
}

// missionDefinitionAdapter adapts mission.MissionDefinition to resolver.MissionDefinition
type missionDefinitionAdapter struct {
	def *mission.MissionDefinition
}

func (m *missionDefinitionAdapter) Nodes() []resolver.MissionNode {
	nodes := make([]resolver.MissionNode, 0, len(m.def.Nodes))
	for _, node := range m.def.Nodes {
		nodes = append(nodes, &missionNodeAdapter{node: node})
	}
	return nodes
}

func (m *missionDefinitionAdapter) Dependencies() []resolver.MissionDependency {
	deps := make([]resolver.MissionDependency, 0)

	if m.def.Dependencies == nil {
		return deps
	}

	// Add agent dependencies
	for _, agentName := range m.def.Dependencies.Agents {
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindAgent,
			name:    agentName,
			version: "",
		})
	}

	// Add tool dependencies
	for _, toolName := range m.def.Dependencies.Tools {
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindTool,
			name:    toolName,
			version: "",
		})
	}

	// Add plugin dependencies
	for _, pluginName := range m.def.Dependencies.Plugins {
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindPlugin,
			name:    pluginName,
			version: "",
		})
	}

	return deps
}

// missionNodeAdapter adapts mission.MissionNode to resolver.MissionNode
type missionNodeAdapter struct {
	node *mission.MissionNode
}

func (n *missionNodeAdapter) ID() string {
	return n.node.ID
}

func (n *missionNodeAdapter) Type() string {
	return string(n.node.Type)
}

func (n *missionNodeAdapter) ComponentRef() string {
	// Extract component reference based on node type
	switch n.node.Type {
	case mission.NodeTypeAgent:
		if n.node.AgentName != "" {
			return n.node.AgentName
		}
	case mission.NodeTypeTool:
		if n.node.ToolName != "" {
			return n.node.ToolName
		}
	case mission.NodeTypePlugin:
		if n.node.PluginName != "" {
			return n.node.PluginName
		}
	}
	return ""
}

// missionDependencyAdapter adapts dependency information to resolver.MissionDependency
type missionDependencyAdapter struct {
	kind    component.ComponentKind
	name    string
	version string
}

func (d *missionDependencyAdapter) Kind() component.ComponentKind {
	return d.kind
}

func (d *missionDependencyAdapter) Name() string {
	return d.name
}

func (d *missionDependencyAdapter) Version() string {
	return d.version
}

// storeManifestLoader loads component manifests from the component store
type storeManifestLoader struct {
	store   component.ComponentStore
	homeDir string
}

func (l *storeManifestLoader) LoadManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error) {
	// Get component from store
	comp, err := l.store.GetByName(ctx, kind, name)
	if err != nil {
		return nil, err
	}
	if comp == nil {
		// Component not found
		return nil, nil
	}

	// Load manifest from component directory
	manifestPath := filepath.Join(l.homeDir, "components", kind.String(), name, "component.yaml")
	manifest, err := component.LoadManifest(manifestPath)
	if err != nil {
		// Manifest load failed - return nil without error
		// This allows resolution to continue even if manifests are missing
		return nil, nil
	}

	return manifest, nil
}

// stubComponentStore is a no-op component store for planning
type stubComponentStore struct {
	homeDir string
}

func (s *stubComponentStore) Create(ctx context.Context, comp *component.Component) error {
	return fmt.Errorf("not implemented: planning mode does not create components")
}

func (s *stubComponentStore) GetByName(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
	// Return nil to indicate component not found
	// This allows dependency resolution to continue even if components aren't installed
	return nil, nil
}

func (s *stubComponentStore) List(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
	return []*component.Component{}, nil
}

func (s *stubComponentStore) ListAll(ctx context.Context) (map[component.ComponentKind][]*component.Component, error) {
	return make(map[component.ComponentKind][]*component.Component), nil
}

func (s *stubComponentStore) Update(ctx context.Context, comp *component.Component) error {
	return fmt.Errorf("not implemented: planning mode does not update components")
}

func (s *stubComponentStore) Delete(ctx context.Context, kind component.ComponentKind, name string) error {
	return fmt.Errorf("not implemented: planning mode does not delete components")
}

func (s *stubComponentStore) ListInstances(ctx context.Context, kind component.ComponentKind, name string) ([]component.ComponentInfo, error) {
	return []component.ComponentInfo{}, nil
}

// stubLifecycleManager is a no-op lifecycle manager for planning
type stubLifecycleManager struct {
	store component.ComponentStore
}

func (l *stubLifecycleManager) StartComponent(ctx context.Context, comp *component.Component) (int, error) {
	// Not implemented - planning doesn't start components
	return 0, fmt.Errorf("not implemented: planning mode does not start components")
}

func (l *stubLifecycleManager) StopComponent(ctx context.Context, comp *component.Component) error {
	// Not implemented - planning doesn't stop components
	return fmt.Errorf("not implemented: planning mode does not stop components")
}

func (l *stubLifecycleManager) RestartComponent(ctx context.Context, comp *component.Component) (int, error) {
	// Not implemented - planning doesn't restart components
	return 0, fmt.Errorf("not implemented: planning mode does not restart components")
}

func (l *stubLifecycleManager) GetStatus(ctx context.Context, comp *component.Component) (component.ComponentStatus, error) {
	// Return status from component metadata
	// In planning mode, we read the stored status without checking actual runtime state
	return comp.Status, nil
}
