package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/component"
)

// InventoryBuilder queries the registry for all components and builds a ComponentInventory.
//
// The builder supports:
//   - Timeout control via context
//   - In-memory caching with TTL
//   - Graceful degradation on partial failures
//   - Thread-safe concurrent access
//
// Example usage:
//
//	builder := NewInventoryBuilder(registryAdapter,
//	    WithInventoryTimeout(5*time.Second),
//	    WithCacheTTL(30*time.Second),
//	)
//	inventory, err := builder.Build(ctx)
//	if err != nil {
//	    // Handle error - partial inventory may still be available
//	}
type InventoryBuilder struct {
	// registry provides component discovery
	registry component.ComponentDiscovery

	// Configuration
	timeout  time.Duration
	cacheTTL time.Duration

	// Caching layer
	cachedInventory *ComponentInventory
	cacheTime       time.Time
	mu              sync.RWMutex
}

// InventoryBuilderOption is a functional option for configuring InventoryBuilder.
type InventoryBuilderOption func(*InventoryBuilder)

// WithInventoryTimeout sets the timeout for registry queries.
// Default is 5 seconds if not specified.
func WithInventoryTimeout(d time.Duration) InventoryBuilderOption {
	return func(b *InventoryBuilder) {
		b.timeout = d
	}
}

// WithCacheTTL sets the time-to-live for cached inventory.
// Default is 30 seconds if not specified.
//
// When using BuildWithCache(), the cached inventory will be returned
// if it's younger than the TTL, avoiding repeated registry queries.
func WithCacheTTL(d time.Duration) InventoryBuilderOption {
	return func(b *InventoryBuilder) {
		b.cacheTTL = d
	}
}

// NewInventoryBuilder creates a new InventoryBuilder with the given registry.
//
// The registry parameter should implement the ComponentDiscovery interface,
// typically a registry.RegistryAdapter.
//
// Options:
//   - WithInventoryTimeout(duration) - sets query timeout (default: 5s)
//   - WithCacheTTL(duration) - sets cache TTL (default: 30s)
//
// Example:
//
//	builder := NewInventoryBuilder(adapter,
//	    WithInventoryTimeout(10*time.Second),
//	    WithCacheTTL(1*time.Minute),
//	)
func NewInventoryBuilder(reg component.ComponentDiscovery, opts ...InventoryBuilderOption) *InventoryBuilder {
	b := &InventoryBuilder{
		registry: reg,
		timeout:  5 * time.Second,  // Default timeout
		cacheTTL: 30 * time.Second, // Default cache TTL
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

// Build queries the registry and builds a complete ComponentInventory.
//
// This method:
//  1. Queries registry for all agents, tools, and plugins in parallel
//  2. Converts registry types to summary types with rich metadata
//  3. Handles timeouts via the provided context
//  4. Handles partial failures gracefully (some queries may fail)
//  5. Updates the internal cache for use by BuildWithCache()
//
// The method respects context cancellation and the builder's timeout setting.
//
// Partial Failures:
// If some component queries fail (e.g., agents succeed but tools fail),
// the method returns a partial inventory with a wrapped error describing
// which queries failed. This allows the orchestrator to continue with
// partial information rather than failing completely.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	inventory, err := builder.Build(ctx)
//	if err != nil {
//	    log.Warnf("inventory build had errors: %v", err)
//	    // inventory may still be partially populated
//	}
func (b *InventoryBuilder) Build(ctx context.Context) (*ComponentInventory, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	// Query registry in parallel using goroutines
	var (
		agents  []component.AgentInfo
		tools   []component.ToolInfo
		plugins []component.PluginInfo

		agentsErr  error
		toolsErr   error
		pluginsErr error

		wg sync.WaitGroup
	)

	// Query agents
	wg.Add(1)
	go func() {
		defer wg.Done()
		agents, agentsErr = b.registry.ListAgents(ctx)
	}()

	// Query tools
	wg.Add(1)
	go func() {
		defer wg.Done()
		tools, toolsErr = b.registry.ListTools(ctx)
	}()

	// Query plugins
	wg.Add(1)
	go func() {
		defer wg.Done()
		plugins, pluginsErr = b.registry.ListPlugins(ctx)
	}()

	// Wait for all queries to complete
	wg.Wait()

	// Build inventory from results
	inventory := &ComponentInventory{
		Agents:     make([]AgentSummary, 0, len(agents)),
		Tools:      make([]ToolSummary, 0, len(tools)),
		Plugins:    make([]PluginSummary, 0, len(plugins)),
		GatheredAt: time.Now(),
		IsStale:    false,
	}

	// Convert agents
	for _, agentInfo := range agents {
		inventory.Agents = append(inventory.Agents, b.convertAgentInfo(agentInfo))
	}

	// Convert tools
	for _, toolInfo := range tools {
		inventory.Tools = append(inventory.Tools, b.convertToolInfo(toolInfo))
	}

	// Convert plugins
	for _, pluginInfo := range plugins {
		inventory.Plugins = append(inventory.Plugins, b.convertPluginInfo(pluginInfo))
	}

	// Set total components count
	inventory.TotalComponents = len(inventory.Agents) + len(inventory.Tools) + len(inventory.Plugins)

	// Sort components by name for consistent output
	sort.Slice(inventory.Agents, func(i, j int) bool {
		return inventory.Agents[i].Name < inventory.Agents[j].Name
	})
	sort.Slice(inventory.Tools, func(i, j int) bool {
		return inventory.Tools[i].Name < inventory.Tools[j].Name
	})
	sort.Slice(inventory.Plugins, func(i, j int) bool {
		return inventory.Plugins[i].Name < inventory.Plugins[j].Name
	})

	// Cache the result
	b.mu.Lock()
	b.cachedInventory = inventory
	b.cacheTime = time.Now()
	b.mu.Unlock()

	// Check for errors and build error message
	var errorParts []string
	if agentsErr != nil {
		errorParts = append(errorParts, fmt.Sprintf("agents: %v", agentsErr))
	}
	if toolsErr != nil {
		errorParts = append(errorParts, fmt.Sprintf("tools: %v", toolsErr))
	}
	if pluginsErr != nil {
		errorParts = append(errorParts, fmt.Sprintf("plugins: %v", pluginsErr))
	}

	if len(errorParts) > 0 {
		return inventory, fmt.Errorf("partial inventory build failures: %s", strings.Join(errorParts, "; "))
	}

	return inventory, nil
}

// BuildWithCache returns cached inventory if available and fresh, otherwise builds new inventory.
//
// This method provides resilience when the registry is temporarily unavailable:
//  1. If cached inventory exists and is younger than cacheTTL, returns it immediately
//  2. If cache is expired or empty, calls Build() to get fresh inventory
//  3. If Build() fails and stale cache exists, returns cache with IsStale=true
//  4. If Build() fails and no cache exists, returns the error
//
// Thread Safety:
// This method is thread-safe and can be called concurrently from multiple goroutines.
//
// Example usage:
//
//	// First call - builds fresh inventory
//	inv1, _ := builder.BuildWithCache(ctx)
//
//	// Second call within TTL - returns cached
//	inv2, _ := builder.BuildWithCache(ctx)
//
//	// Registry goes down - returns stale cache
//	inv3, _ := builder.BuildWithCache(ctx) // IsStale will be true
func (b *InventoryBuilder) BuildWithCache(ctx context.Context) (*ComponentInventory, error) {
	b.mu.RLock()
	cached := b.cachedInventory
	cacheAge := time.Since(b.cacheTime)
	b.mu.RUnlock()

	// Return cached inventory if it's fresh
	if cached != nil && cacheAge < b.cacheTTL {
		// Return a copy to avoid concurrent modification
		cachedCopy := *cached
		return &cachedCopy, nil
	}

	// Cache expired or doesn't exist - build fresh inventory
	inventory, err := b.Build(ctx)

	// If build succeeded, return the fresh inventory
	if err == nil {
		return inventory, nil
	}

	// Build failed - check if we have stale cache to fall back to
	b.mu.RLock()
	staleCache := b.cachedInventory
	b.mu.RUnlock()

	if staleCache != nil {
		// Return stale cache as fallback
		staleCopy := *staleCache
		staleCopy.IsStale = true
		return &staleCopy, fmt.Errorf("using stale inventory (age: %v) due to build error: %w", cacheAge, err)
	}

	// No cache available and build failed
	return nil, fmt.Errorf("failed to build inventory and no cache available: %w", err)
}

// convertAgentInfo converts component.AgentInfo to AgentSummary.
//
// This method maps the basic registry metadata to the richer summary format
// used by the orchestrator. It includes capability matching, health status,
// and resource requirements.
func (b *InventoryBuilder) convertAgentInfo(info component.AgentInfo) AgentSummary {
	// Determine health status based on instance count
	healthStatus := "healthy"
	if info.Instances == 0 {
		healthStatus = "unavailable"
	}

	return AgentSummary{
		Name:           info.Name,
		Version:        info.Version,
		Description:    info.Description,
		Capabilities:   info.Capabilities,
		TargetTypes:    info.TargetTypes,
		TechniqueTypes: info.TechniqueTypes,
		Slots:          b.extractSlots(info),
		Instances:      info.Instances,
		HealthStatus:   healthStatus,
		Endpoints:      info.Endpoints,
		IsExternal:     len(info.Endpoints) > 0, // External if gRPC endpoints exist
	}
}

// extractSlots extracts slot summaries from agent info.
// LLM slot requirements are declared in agent source code and are not propagated
// through the component registry metadata, so this always returns an empty slice.
// Slot resolution happens at runtime via the LLM registry, not at inventory time.
func (b *InventoryBuilder) extractSlots(info component.AgentInfo) []SlotSummary {
	return []SlotSummary{}
}

// convertToolInfo converts component.ToolInfo to ToolSummary.
//
// This method maps basic tool metadata from the registry to the summary format.
// Schema information is summarized to keep prompt size manageable.
func (b *InventoryBuilder) convertToolInfo(info component.ToolInfo) ToolSummary {
	// Determine health status based on instance count
	healthStatus := "healthy"
	if info.Instances == 0 {
		healthStatus = "unavailable"
	}

	// Convert capabilities if present
	var capabilities *CapabilitiesSummary
	if info.Capabilities != nil {
		capabilities = &CapabilitiesSummary{
			HasRoot:         info.Capabilities.HasRoot,
			HasSudo:         info.Capabilities.HasSudo,
			CanRawSocket:    info.Capabilities.CanRawSocket,
			Features:        info.Capabilities.Features,
			BlockedArgs:     info.Capabilities.BlockedArgs,
			ArgAlternatives: info.Capabilities.ArgAlternatives,
		}
	}

	return ToolSummary{
		Name:          info.Name,
		Version:       info.Version,
		Description:   info.Description,
		Tags:          b.extractTags(info),
		InputSummary:  b.generateToolInputSummary(info),
		OutputSummary: b.generateToolOutputSummary(info),
		Capabilities:  capabilities,
		Instances:     info.Instances,
		HealthStatus:  healthStatus,
		IsExternal:    len(info.Endpoints) > 0,
	}
}

// extractTags extracts tags from tool info.
// Tags are stored in component metadata as "tag:<name>=true" entries by tools
// that register with tag metadata. This mirrors the method:* convention used
// for plugins.
func (b *InventoryBuilder) extractTags(info component.ToolInfo) []string {
	// Tags are not directly on ToolInfo; they would need to come from the raw
	// ComponentInfo metadata. ToolInfo is already an aggregated view and does
	// not carry the raw metadata map, so tags are not available at this level.
	// Return empty — callers should use capabilities or description for classification.
	return []string{}
}

// generateToolInputSummary generates a human-readable summary of tool input schema.
// Schema definitions are embedded in tool proto files and are not propagated through
// the component registry metadata. Returns empty string; the tool description
// field is the primary source of usage information at inventory time.
func (b *InventoryBuilder) generateToolInputSummary(info component.ToolInfo) string {
	return ""
}

// generateToolOutputSummary generates a human-readable summary of tool output schema.
// Schema definitions are embedded in tool proto files and are not propagated through
// the component registry metadata. Returns empty string; the tool description
// field is the primary source of usage information at inventory time.
func (b *InventoryBuilder) generateToolOutputSummary(info component.ToolInfo) string {
	return ""
}

// convertPluginInfo converts component.PluginInfo to PluginSummary.
//
// This method maps basic plugin metadata from the registry to the summary format.
// Method information is included for LLM reasoning about plugin capabilities.
func (b *InventoryBuilder) convertPluginInfo(info component.PluginInfo) PluginSummary {
	// Determine health status based on instance count
	healthStatus := "healthy"
	if info.Instances == 0 {
		healthStatus = "unavailable"
	}

	return PluginSummary{
		Name:         info.Name,
		Version:      info.Version,
		Description:  info.Description,
		Methods:      b.extractMethods(info),
		Instances:    info.Instances,
		HealthStatus: healthStatus,
		IsExternal:   len(info.Endpoints) > 0,
	}
}

// extractMethods extracts method summaries from plugin info.
// Plugin methods are stored as "method:<name>=true" entries in ComponentInfo.Metadata
// during registration, but ComponentDiscovery.ListPlugins aggregates instances into
// PluginInfo which does not carry the raw metadata map. Method discovery requires
// the PluginAccessStore.ListAvailablePlugins path which returns PluginCatalogEntry
// with the Methods field populated. At this level we only have PluginInfo, so
// we return an empty slice; the plugin description remains the primary metadata source.
func (b *InventoryBuilder) extractMethods(info component.PluginInfo) []MethodSummary {
	return []MethodSummary{}
}

// summarizeSchema converts a JSON schema map to a human-readable summary string.
//
// The summary format is designed to be concise and LLM-readable:
//
//	"port: int, host: string, timeout: int"
//
// This is used for tool input/output schemas and plugin method schemas.
// The summary is kept under 100 characters to manage prompt size.
//
// If the schema is nil or empty, returns an empty string.
func (b *InventoryBuilder) summarizeSchema(schema map[string]any) string {
	if schema == nil || len(schema) == 0 {
		return ""
	}

	// Extract properties from JSON schema
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return "schema format unknown"
	}

	// Build summary of field: type pairs
	var parts []string
	for name, prop := range properties {
		propMap, ok := prop.(map[string]any)
		if !ok {
			continue
		}

		propType, ok := propMap["type"].(string)
		if !ok {
			propType = "any"
		}

		parts = append(parts, fmt.Sprintf("%s: %s", name, propType))
	}

	// Sort for consistent output
	sort.Strings(parts)

	// Join with commas and truncate if too long
	summary := strings.Join(parts, ", ")
	if len(summary) > 100 {
		summary = summary[:97] + "..."
	}

	return summary
}
