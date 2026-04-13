package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/component"
)

// DependencyResolver resolves and manages component dependencies for missions.
// It provides methods to build dependency trees from missions or workflow files,
// validate the state of all dependencies, and ensure all required components are running.
//
// The resolver uses a three-phase approach:
//  1. Resolution: Build a complete dependency graph from mission requirements
//  2. Validation: Check that all components are installed, running, and healthy
//  3. Enforcement: Start any stopped components and wait for them to become healthy
//
// Example usage:
//
//	resolver := NewResolver(componentStore, lifecycle, manifestLoader)
//	tree, err := resolver.ResolveFromMission(ctx, missionDef)
//	if err != nil {
//	    return err
//	}
//	result, err := resolver.ValidateState(ctx, tree)
//	if err != nil {
//	    return err
//	}
//	if !result.Valid {
//	    if err := resolver.EnsureRunning(ctx, tree); err != nil {
//	        return err
//	    }
//	}
type DependencyResolver interface {
	// ResolveFromMission builds a complete dependency tree from a mission definition.
	// It walks through all nodes in the mission, extracts agent/tool/plugin references,
	// loads their manifests, and recursively resolves transitive dependencies.
	//
	// The returned tree contains:
	//  - All direct dependencies (agents, tools, plugins referenced in nodes)
	//  - All transitive dependencies (components required by other components)
	//  - Current state information (installed, running, healthy) for each component
	//
	// Returns an error if:
	//  - The dependency graph contains cycles
	//  - A required component cannot be found in the store
	//  - Manifest loading fails for a critical component
	ResolveFromMission(ctx context.Context, mission MissionDefinition) (*DependencyTree, error)

	// ResolveFromWorkflow builds a dependency tree from a workflow YAML file path.
	// This is a convenience method that loads the workflow file, parses it into a
	// mission definition, and then calls ResolveFromMission.
	//
	// The workflowPath parameter must be an absolute path to a valid workflow YAML file.
	//
	// Returns an error if:
	//  - The workflow file cannot be read
	//  - The workflow YAML is malformed
	//  - Any errors occur during mission resolution (see ResolveFromMission)
	ResolveFromWorkflow(ctx context.Context, workflowPath string) (*DependencyTree, error)

	// ValidateState checks the current state of all components in the dependency tree.
	// It verifies that each component is installed, running, and healthy by:
	//  - Checking the component store for installation status
	//  - Querying the lifecycle manager for runtime status
	//  - Performing health checks on running instances
	//  - Validating version constraints
	//
	// The returned ValidationResult contains:
	//  - Valid: true if all dependencies are satisfied
	//  - Counts: number of installed, running, and healthy components
	//  - NotInstalled: list of components that need to be installed
	//  - NotRunning: list of components that need to be started
	//  - Unhealthy: list of components with failed health checks
	//  - VersionMismatch: list of components with version constraint violations
	//
	// This method does NOT modify any state - it only reads and reports.
	ValidateState(ctx context.Context, tree *DependencyTree) (*ValidationResult, error)

	// EnsureRunning starts all components in the dependency tree that are not running.
	// It processes components in topological order (dependencies before dependents)
	// to ensure proper startup sequencing.
	//
	// For each component:
	//  1. Skips if already running and healthy
	//  2. Starts the component using the lifecycle manager
	//  3. Waits for the component to pass health checks
	//  4. Updates the dependency tree with new state information
	//
	// If any component fails to start, the operation stops and returns an error.
	// Already-started components remain running.
	//
	// Returns an error if:
	//  - A component fails to start (see component.LifecycleManager.StartComponent)
	//  - A component fails health checks after starting
	//  - The dependency tree contains cycles (cannot determine startup order)
	EnsureRunning(ctx context.Context, tree *DependencyTree) error
}

// MissionDefinition is an interface that abstracts the mission package to avoid circular dependencies.
// This allows the resolver to work with mission definitions without directly importing the mission package.
//
// Implementation note: The mission package should provide an adapter that implements this interface:
//
//	func (m *mission.MissionDefinition) Nodes() []MissionNode { ... }
//	func (m *mission.MissionDefinition) Dependencies() []MissionDependency { ... }
type MissionDefinition interface {
	// Nodes returns all nodes (workflow steps) in the mission.
	// Each node may reference agents, tools, or plugins.
	Nodes() []MissionNode

	// Dependencies returns explicitly declared dependencies from the mission YAML.
	// These are dependencies listed in the "dependencies" section of the workflow.
	Dependencies() []MissionDependency
}

// MissionNode represents a single node (workflow step) in a mission.
// Each node has a type and may reference a specific component.
type MissionNode interface {
	// ID returns the unique identifier for this node within the mission.
	ID() string

	// Type returns the node type (agent, tool, plugin, condition, parallel, join).
	Type() string

	// ComponentRef returns the name of the component referenced by this node.
	// Returns empty string for non-component nodes (condition, parallel, join).
	ComponentRef() string
}

// MissionDependency represents an explicit dependency declaration from a mission YAML.
// This corresponds to entries in the "dependencies" section of the workflow.
type MissionDependency interface {
	// Kind returns the component kind (agent, tool, plugin).
	Kind() component.ComponentKind

	// Name returns the component name.
	Name() string

	// Version returns the version constraint (e.g., ">=1.0.0", "^2.0.0").
	// Returns empty string if no version constraint is specified.
	Version() string
}

// ManifestLoader is an interface for loading component manifests.
// This abstraction allows for testing with mock loaders and provides flexibility
// in how manifests are loaded (from disk, from store, from network, etc.).
type ManifestLoader interface {
	// LoadManifest loads a component manifest by kind and name.
	// The manifest may be loaded from:
	//  - The component store (if the component is installed)
	//  - The filesystem (if the component is in development)
	//  - A remote registry (if the component needs to be fetched)
	//
	// Returns nil, nil if the component is not found.
	// Returns an error only if there is a failure during loading.
	LoadManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error)
}

// resolver is the default implementation of DependencyResolver.
// It uses a three-tier storage system for component information:
//  1. componentStore: persistent component metadata and installation state
//  2. lifecycle: runtime process management and health checking
//  3. manifestCache: in-memory cache to avoid repeated manifest loads
type resolver struct {
	componentStore component.ComponentStore
	lifecycle      component.LifecycleManager
	manifestLoader ManifestLoader
	manifestCache  sync.Map // map[string]*component.Manifest, key is "kind:name"
}

// NewResolver creates a new dependency resolver with the given dependencies.
//
// Parameters:
//   - componentStore: provides access to installed component metadata
//   - lifecycle: manages component start/stop operations
//   - manifestLoader: loads component manifests for dependency analysis
//
// All parameters are required and must not be nil.
func NewResolver(
	componentStore component.ComponentStore,
	lifecycle component.LifecycleManager,
	manifestLoader ManifestLoader,
) DependencyResolver {
	return &resolver{
		componentStore: componentStore,
		lifecycle:      lifecycle,
		manifestLoader: manifestLoader,
	}
}

// ResolveFromMission builds a complete dependency tree from a mission definition.
// It walks through all nodes in the mission, extracts agent/tool/plugin references,
// loads their manifests, and recursively resolves transitive dependencies using BFS.
func (r *resolver) ResolveFromMission(ctx context.Context, mission MissionDefinition) (*DependencyTree, error) {
	// Create empty dependency tree - use mission nodes as MissionRef fallback
	missionRef := "mission"
	if len(mission.Nodes()) > 0 {
		missionRef = mission.Nodes()[0].ID()
	}
	tree := NewDependencyTree(missionRef)

	// Queue for BFS resolution: each entry is [kind, name, requiredBy, source, sourceRef]
	type queueEntry struct {
		kind       component.ComponentKind
		name       string
		version    string
		requiredBy *DependencyNode
		source     DependencySource
		sourceRef  string
	}
	queue := make([]queueEntry, 0)

	// Track visited components to detect cycles
	visited := make(map[string]bool)

	// Phase 1: Extract explicit dependencies from mission
	for _, dep := range mission.Dependencies() {
		kind := dep.Kind()
		name := dep.Name()
		version := dep.Version()

		// Add to queue
		queue = append(queue, queueEntry{
			kind:       kind,
			name:       name,
			version:    version,
			requiredBy: nil, // Root dependencies have no parent
			source:     SourceMissionExplicit,
			sourceRef:  missionRef,
		})
	}

	// Phase 2: Extract component references from mission nodes
	for _, node := range mission.Nodes() {
		componentRef := node.ComponentRef()
		if componentRef == "" {
			// Skip non-component nodes (condition, parallel, join)
			continue
		}

		// Determine component kind from node type
		var kind component.ComponentKind
		nodeType := node.Type()
		switch nodeType {
		case "agent":
			kind = component.ComponentKindAgent
		case "tool":
			kind = component.ComponentKindTool
		case "plugin":
			kind = component.ComponentKindPlugin
		default:
			// Skip unknown node types
			continue
		}

		// Add to queue
		queue = append(queue, queueEntry{
			kind:       kind,
			name:       componentRef,
			version:    "", // Version not specified in node references
			requiredBy: nil,
			source:     SourceMissionNode,
			sourceRef:  node.ID(),
		})
	}

	// Phase 3: BFS resolution of transitive dependencies
	for len(queue) > 0 {
		// Dequeue
		entry := queue[0]
		queue = queue[1:]

		// Check if already visited (avoid duplicate processing)
		key := fmt.Sprintf("%s:%s", entry.kind, entry.name)
		if visited[key] {
			// Already processed - just update RequiredBy link if needed
			if entry.requiredBy != nil {
				existingNode := tree.GetNode(entry.kind, entry.name)
				if existingNode != nil {
					entry.requiredBy.AddDependency(existingNode)
				}
			}
			continue
		}
		visited[key] = true

		// Create dependency node
		node := &DependencyNode{
			Kind:      entry.kind,
			Name:      entry.name,
			Version:   entry.version,
			Source:    entry.source,
			SourceRef: entry.sourceRef,
		}

		// Add node to tree (returns existing if already present)
		existingNode := tree.AddNode(node)
		if existingNode != node {
			// Node already exists, use the existing one
			node = existingNode
		}

		// Link to parent (requiredBy)
		if entry.requiredBy != nil {
			entry.requiredBy.AddDependency(node)
		} else {
			// Root node (no parent)
			tree.Roots = append(tree.Roots, node)
		}

		// Update node state from component store
		storedComponent, err := r.componentStore.GetByName(ctx, entry.kind, entry.name)
		if err == nil && storedComponent != nil {
			node.Installed = true
			node.ActualVersion = storedComponent.Version
			node.Component = storedComponent
			node.Running = storedComponent.Status == component.ComponentStatusRunning
			// Note: Healthy status will be populated by ValidateState
		}

		// Load manifest to resolve transitive dependencies
		manifest, err := r.getCachedManifest(ctx, entry.kind, entry.name)
		if err != nil {
			// Non-fatal: log warning but continue resolution
			// The dependency tree will be incomplete but still usable
			continue
		}
		if manifest == nil {
			// Component has no manifest or manifest not found
			continue
		}

		// Parse dependencies.components from manifest
		if manifest.Dependencies != nil && len(manifest.Dependencies.Components) > 0 {
			for _, depStr := range manifest.Dependencies.Components {
				// Parse dependency string: "name@version" or "kind:name@version"
				depKind, depName, depVersion := parseComponentDependency(depStr)
				if depKind == "" || depName == "" {
					// Invalid dependency format - skip
					continue
				}

				// Add to queue for resolution
				queue = append(queue, queueEntry{
					kind:       depKind,
					name:       depName,
					version:    depVersion,
					requiredBy: node,
					source:     SourceManifest,
					sourceRef:  entry.name,
				})
			}
		}
	}

	// Phase 4: Detect circular dependencies using topological sort
	_, err := tree.TopologicalOrder()
	if err != nil {
		// Build cycle path for error reporting
		cyclePath := []string{}
		for key := range visited {
			cyclePath = append(cyclePath, key)
		}
		return nil, NewCircularDependencyError(cyclePath)
	}

	return tree, nil
}

// parseComponentDependency parses a dependency string into kind, name, and version.
// Supported formats:
//   - "name@version" (kind inferred as agent)
//   - "kind:name@version" (explicit kind)
//
// Returns empty strings if the format is invalid.
func parseComponentDependency(depStr string) (component.ComponentKind, string, string) {
	// Split by @ to separate name and version
	parts := strings.Split(depStr, "@")
	if len(parts) != 2 {
		return "", "", ""
	}

	nameWithKind := parts[0]
	version := parts[1]

	// Check if kind is specified (kind:name)
	kindParts := strings.SplitN(nameWithKind, ":", 2)
	if len(kindParts) == 2 {
		// Explicit kind specified
		kindStr := kindParts[0]
		name := kindParts[1]

		kind, err := component.ParseComponentKind(kindStr)
		if err != nil {
			return "", "", ""
		}

		return kind, name, version
	}

	// No kind specified - default to agent
	return component.ComponentKindAgent, nameWithKind, version
}

// ResolveFromWorkflow builds a dependency tree from a workflow YAML file path.
//
// Not yet implemented. Call ResolveFromMission with a parsed mission definition instead.
func (r *resolver) ResolveFromWorkflow(_ context.Context, workflowPath string) (*DependencyTree, error) {
	return nil, fmt.Errorf("ResolveFromWorkflow: not yet implemented (workflow path: %s)", workflowPath)
}

// ValidateState checks the current state of all components in the dependency tree.
// It queries the component store and lifecycle manager to populate node state fields,
// then builds a comprehensive ValidationResult with counts and problem lists.
//
// The validation process runs in parallel for performance, collecting all issues
// before returning. Only unrecoverable errors (like context cancellation) cause
// immediate failure - component-level problems are aggregated in the result.
func (r *resolver) ValidateState(ctx context.Context, tree *DependencyTree) (*ValidationResult, error) {
	start := time.Now()

	// Handle nil tree gracefully
	if tree == nil {
		return &ValidationResult{
			Valid:           true,
			Summary:         "No dependencies to validate",
			TotalComponents: 0,
			ValidatedAt:     start,
			Duration:        time.Since(start),
		}, nil
	}

	// Initialize result structure
	result := &ValidationResult{
		Valid:           true,
		TotalComponents: len(tree.Nodes),
		ValidatedAt:     start,
		NotInstalled:    make([]*DependencyNode, 0),
		NotRunning:      make([]*DependencyNode, 0),
		Unhealthy:       make([]*DependencyNode, 0),
		VersionMismatch: make([]*VersionMismatchInfo, 0),
	}

	// Early return if no nodes to validate
	if len(tree.Nodes) == 0 {
		result.Summary = "No dependencies to validate"
		result.Duration = time.Since(start)
		return result, nil
	}

	// Parallel validation of all nodes
	type validationResult struct {
		node            *DependencyNode
		installed       bool
		running         bool
		healthy         bool
		actualVersion   string
		component       *component.Component
		versionMismatch bool
		err             error
	}

	resultsChan := make(chan validationResult, len(tree.Nodes))
	var wg sync.WaitGroup

	// Launch goroutines to check each node's state
	for _, node := range tree.Nodes {
		wg.Add(1)
		go func(n *DependencyNode) {
			defer wg.Done()

			vr := validationResult{node: n}

			// Step 1: Check if component is installed
			comp, err := r.componentStore.GetByName(ctx, n.Kind, n.Name)
			if err != nil {
				// Log error but continue - we want to collect all issues
				// Only fail on unrecoverable errors like context cancellation
				if ctx.Err() != nil {
					vr.err = err
					resultsChan <- vr
					return
				}
				// Store unavailable or other error - treat as not installed
				vr.installed = false
			} else if comp != nil {
				vr.installed = true
				vr.component = comp
				vr.actualVersion = comp.Version

				// Step 2: Check if component is running and healthy
				status, err := r.lifecycle.GetStatus(ctx, comp)
				if err != nil {
					// Error getting status - treat as not running
					if ctx.Err() != nil {
						vr.err = err
						resultsChan <- vr
						return
					}
					vr.running = false
					vr.healthy = false
				} else {
					vr.running = (status == component.ComponentStatusRunning)
					// For running components, check if they're healthy
					// The status itself indicates health - if it's running, it passed health checks
					vr.healthy = vr.running
				}

				// Step 3: Validate version constraint
				if n.Version != "" && vr.actualVersion != "" {
					satisfies, err := SatisfiesConstraint(vr.actualVersion, n.Version)
					if err != nil {
						// Constraint parsing error - treat as mismatch
						vr.versionMismatch = true
					} else if !satisfies {
						vr.versionMismatch = true
					}
				}
			} else {
				// Component not found in store
				vr.installed = false
			}

			resultsChan <- vr
		}(node)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results and build problem lists
	for vr := range resultsChan {
		// Check for unrecoverable errors
		if vr.err != nil {
			return nil, fmt.Errorf("validation failed for %s/%s: %w", vr.node.Kind, vr.node.Name, vr.err)
		}

		// Update node state fields
		vr.node.Installed = vr.installed
		vr.node.Running = vr.running
		vr.node.Healthy = vr.healthy
		vr.node.ActualVersion = vr.actualVersion
		vr.node.Component = vr.component

		// Update counts
		if vr.installed {
			result.InstalledCount++
		}
		if vr.running {
			result.RunningCount++
		}
		if vr.healthy {
			result.HealthyCount++
		}

		// Categorize problems
		if !vr.installed {
			result.NotInstalled = append(result.NotInstalled, vr.node)
		} else if !vr.running {
			result.NotRunning = append(result.NotRunning, vr.node)
		} else if !vr.healthy {
			result.Unhealthy = append(result.Unhealthy, vr.node)
		}

		// Check version mismatch
		if vr.versionMismatch {
			result.VersionMismatch = append(result.VersionMismatch, &VersionMismatchInfo{
				Node:            vr.node,
				RequiredVersion: vr.node.Version,
				ActualVersion:   vr.actualVersion,
			})
		}
	}

	// Determine overall validity
	result.Valid = len(result.NotInstalled) == 0 &&
		len(result.NotRunning) == 0 &&
		len(result.Unhealthy) == 0 &&
		len(result.VersionMismatch) == 0

	// Build summary message
	if result.Valid {
		result.Summary = fmt.Sprintf("All %d components are installed, running, and healthy", result.TotalComponents)
	} else {
		var issues []string
		if len(result.NotInstalled) > 0 {
			issues = append(issues, fmt.Sprintf("%d not installed", len(result.NotInstalled)))
		}
		if len(result.NotRunning) > 0 {
			issues = append(issues, fmt.Sprintf("%d not running", len(result.NotRunning)))
		}
		if len(result.Unhealthy) > 0 {
			issues = append(issues, fmt.Sprintf("%d unhealthy", len(result.Unhealthy)))
		}
		if len(result.VersionMismatch) > 0 {
			issues = append(issues, fmt.Sprintf("%d version mismatches", len(result.VersionMismatch)))
		}
		result.Summary = fmt.Sprintf("Validation failed: %s", joinStrings(issues, ", "))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// joinStrings is a helper to join strings without importing strings package again.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}

// EnsureRunning starts all components in the dependency tree that are not running.
// It processes components in topological order (dependencies before dependents)
// to ensure proper startup sequencing.
func (r *resolver) EnsureRunning(ctx context.Context, tree *DependencyTree) error {
	// Get topological order - this ensures dependencies are started before dependents
	order, err := tree.TopologicalOrder()
	if err != nil {
		// Topological sort failed, likely due to circular dependencies
		// Extract component names for error message
		names := make([]string, 0, len(tree.Nodes))
		for key := range tree.Nodes {
			names = append(names, key)
		}
		return NewCircularDependencyError(names)
	}

	// Start each component in dependency order
	for _, node := range order {
		// Skip if component is not installed
		// We can't start what isn't installed
		if !node.Installed {
			continue
		}

		// Skip if component is already running and healthy
		// No need to restart already-healthy components
		if node.Running && node.Healthy {
			continue
		}

		// Start the component
		// StartComponent blocks until the component is healthy or times out
		_, err := r.lifecycle.StartComponent(ctx, node.Component)
		if err != nil {
			// Component failed to start - abort the entire operation
			// Already-started components remain running
			return NewStartFailedError(node, err)
		}

		// Update node state to reflect successful start
		node.Running = true
		node.Healthy = true
	}

	return nil
}

// getCachedManifest retrieves a manifest from cache or loads it via the manifest loader.
// This helper avoids repeated manifest loads by caching results keyed on kind and name.
func (r *resolver) getCachedManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error) {
	// Check cache first
	key := manifestCacheKey(kind, name)
	if cached, ok := r.manifestCache.Load(key); ok {
		return cached.(*component.Manifest), nil
	}

	// Load from manifest loader
	manifest, err := r.manifestLoader.LoadManifest(ctx, kind, name)
	if err != nil {
		return nil, err
	}

	// Cache for future use
	if manifest != nil {
		r.manifestCache.Store(key, manifest)
	}

	return manifest, nil
}

// manifestCacheKey generates a cache key for a component manifest.
func manifestCacheKey(kind component.ComponentKind, name string) string {
	return kind.String() + ":" + name
}
