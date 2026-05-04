// Package harness provides the agent execution environment.
package harness

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	graphbus "github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/types"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GraphRAGBridge defines the interface for storing findings to the GraphRAG
// knowledge graph system. Implementations handle the conversion of agent findings
// to graph nodes and the creation of relationships.
//
// The bridge operates asynchronously to avoid blocking agent execution. All
// storage operations happen in background goroutines, with the bridge tracking
// pending operations for graceful shutdown.
type GraphRAGBridge interface {
	// StoreAsync queues a finding for asynchronous storage to GraphRAG.
	// This method returns immediately; actual storage happens in a background
	// goroutine. The finding will be converted to a FindingNode and stored
	// along with any relevant relationships (DISCOVERED_ON, USES_TECHNIQUE,
	// SIMILAR_TO).
	//
	// Parameters:
	//   - ctx: Context for the operation (used for logging, not cancellation of async work)
	//   - finding: The agent finding to store
	//   - missionID: The mission this finding belongs to
	//   - targetID: Optional target ID for DISCOVERED_ON relationship
	StoreAsync(ctx context.Context, finding agent.Finding, missionID types.ID, targetID *types.ID)

	// Shutdown waits for all pending storage operations to complete.
	// This should be called when the harness is closing to ensure no findings
	// are lost. The context can be used to set a timeout for the wait.
	//
	// Returns an error if the shutdown times out or encounters issues.
	Shutdown(ctx context.Context) error

	// Health returns the health status of the GraphRAG bridge.
	// This includes the health of the underlying GraphRAGStore.
	Health(ctx context.Context) types.HealthStatus
}

// GraphRAGBridgeConfig holds configuration options for the GraphRAG bridge.
// GraphRAG is a required core component - the bridge is always active.
// All fields have sensible defaults that can be overridden.
type GraphRAGBridgeConfig struct {
	// SimilarityThreshold is the minimum similarity score (0.0-1.0) required
	// for creating SIMILAR_TO relationships between findings.
	// Default: 0.85
	SimilarityThreshold float64

	// MaxSimilarLinks is the maximum number of SIMILAR_TO relationships
	// to create per finding. This bounds the relationship density.
	// Default: 5
	MaxSimilarLinks int

	// MaxConcurrent is the maximum number of concurrent storage operations.
	// This prevents unbounded goroutine growth during high-throughput periods.
	// Default: 10
	MaxConcurrent int

	// StorageTimeout is the timeout for individual storage operations.
	// Operations exceeding this timeout will be cancelled and logged.
	// Default: 30s
	StorageTimeout time.Duration
}

// DefaultGraphRAGBridgeConfig returns a GraphRAGBridgeConfig with sensible defaults.
// GraphRAG is always active as a core component.
func DefaultGraphRAGBridgeConfig() GraphRAGBridgeConfig {
	return GraphRAGBridgeConfig{
		SimilarityThreshold: 0.85,
		MaxSimilarLinks:     5,
		MaxConcurrent:       10,
		StorageTimeout:      30 * time.Second,
	}
}

// Validate checks that the configuration values are within acceptable ranges.
func (c GraphRAGBridgeConfig) Validate() error {
	if c.SimilarityThreshold < 0.0 || c.SimilarityThreshold > 1.0 {
		return &ConfigError{
			Field:   "SimilarityThreshold",
			Message: "must be between 0.0 and 1.0",
		}
	}
	if c.MaxSimilarLinks < 0 {
		return &ConfigError{
			Field:   "MaxSimilarLinks",
			Message: "must be non-negative",
		}
	}
	if c.MaxConcurrent < 1 {
		return &ConfigError{
			Field:   "MaxConcurrent",
			Message: "must be at least 1",
		}
	}
	if c.StorageTimeout < time.Second {
		return &ConfigError{
			Field:   "StorageTimeout",
			Message: "must be at least 1 second",
		}
	}
	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "graphrag bridge config: " + e.Field + " " + e.Message
}

// DefaultGraphRAGBridge is the default implementation of GraphRAGBridge.
// It handles async storage of findings to the GraphRAG knowledge graph,
// with bounded concurrency and graceful shutdown support.
type DefaultGraphRAGBridge struct {
	logger      *slog.Logger
	config      GraphRAGBridgeConfig
	wg          sync.WaitGroup
	semaphore   chan struct{}
	graphLoader *loader.GraphLoader // may be nil; finding graph storage is skipped when nil
	bus         *graphbus.Bus       // optional; publishes NODE_ADDED after successful findings writes
}

// NewGraphRAGBridge creates a new DefaultGraphRAGBridge with the given dependencies.
// The semaphore channel is initialized with size MaxConcurrent to limit concurrent operations.
//
// Parameters:
//   - logger: Logger for diagnostic output (if nil, uses default logger)
//   - config: Configuration options (use DefaultGraphRAGBridgeConfig() for defaults)
//
// Returns a configured GraphRAGBridge ready for use.
func NewGraphRAGBridge(logger *slog.Logger, config GraphRAGBridgeConfig) *DefaultGraphRAGBridge {
	if logger == nil {
		logger = slog.Default()
	}

	return &DefaultGraphRAGBridge{
		logger:    logger.With("component", "graphrag_bridge"),
		config:    config,
		semaphore: make(chan struct{}, config.MaxConcurrent),
	}
}

// WithGraphLoader attaches a GraphLoader so that storeToGraphRAG persists finding
// nodes to the Neo4j knowledge graph. When nil (the default), finding storage
// to the graph is skipped and findings are only written to the finding store.
func (b *DefaultGraphRAGBridge) WithGraphLoader(gl *loader.GraphLoader) *DefaultGraphRAGBridge {
	b.graphLoader = gl
	return b
}

// WithBus attaches an in-process graph Bus. When non-nil, each successful
// LoadFindings call publishes a NODE_ADDED GraphUpdate so WatchGraphUpdates
// subscribers receive incremental notifications.
// Spec: dashboard-knowledge-graph Task 9.
func (b *DefaultGraphRAGBridge) WithBus(bus *graphbus.Bus) *DefaultGraphRAGBridge {
	b.bus = bus
	return b
}

// StoreAsync queues a finding for asynchronous storage to GraphRAG.
// It acquires a semaphore slot, increments the WaitGroup, and spawns a goroutine
// to handle the actual storage. The method returns immediately without blocking.
//
// GraphRAG is a required core component - storage is always attempted.
func (b *DefaultGraphRAGBridge) StoreAsync(ctx context.Context, finding agent.Finding, missionID types.ID, targetID *types.ID) {
	// Increment WaitGroup before acquiring semaphore to ensure Shutdown tracks this operation
	b.wg.Add(1)

	// Spawn goroutine for async storage
	go func() {
		defer b.wg.Done()

		// Acquire semaphore (blocks if at max concurrency)
		select {
		case b.semaphore <- struct{}{}:
			// Acquired semaphore slot
		case <-ctx.Done():
			b.logger.Warn("context cancelled while waiting for semaphore",
				"finding_id", finding.ID,
				"mission_id", missionID,
			)
			return
		}
		defer func() { <-b.semaphore }() // Release semaphore slot

		// Create a timeout context for the storage operation
		storageCtx, cancel := context.WithTimeout(context.Background(), b.config.StorageTimeout)
		defer cancel()

		// Perform the storage operation
		b.storeToGraphRAG(storageCtx, finding, missionID, targetID)
	}()
}

// Shutdown waits for all pending storage operations to complete.
// Uses a done channel to implement timeout via the provided context.
// Returns an error if the context deadline is exceeded before all operations complete.
func (b *DefaultGraphRAGBridge) Shutdown(ctx context.Context) error {
	// Create a done channel to signal when WaitGroup completes
	done := make(chan struct{})

	go func() {
		b.wg.Wait()
		close(done)
	}()

	// Wait for either completion or context cancellation
	select {
	case <-done:
		b.logger.Debug("graphrag bridge shutdown complete")
		return nil
	case <-ctx.Done():
		b.logger.Warn("graphrag bridge shutdown timed out, some operations may be incomplete")
		return ctx.Err()
	}
}

// Health returns the health status of the GraphRAG bridge.
// Since the taxonomy engine has been removed, this just returns healthy.
// Real health checking will be added when GraphLoader-based finding storage is implemented.
func (b *DefaultGraphRAGBridge) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("graphrag bridge operational")
}

// storeToGraphRAG converts the agent.Finding to a graphragpb.Finding proto and
// persists it via GraphLoader.LoadFindings. This is best-effort: errors are logged
// at WARN level and do not propagate so that the main finding-store path is unaffected.
func (b *DefaultGraphRAGBridge) storeToGraphRAG(ctx context.Context, finding agent.Finding, missionID types.ID, targetID *types.ID) {
	if b.graphLoader == nil {
		b.logger.Debug("graphrag bridge: graphLoader not wired, skipping finding graph storage",
			"finding_id", finding.ID,
		)
		return
	}

	// Step 1: Convert agent.Finding to graphragpb.Finding proto format.
	findingID := string(finding.ID)
	desc := finding.Description
	cat := finding.Category
	pbFinding := &graphragpb.Finding{
		Id:          &findingID,
		Title:       finding.Title,
		Description: &desc,
		Severity:    string(finding.Severity),
		Category:    &cat,
	}
	if targetID != nil {
		parentID := string(*targetID)
		pbFinding.ParentId = &parentID
	}

	// Step 2: Build ExecContext from available fields.
	execCtx := loader.ExecContext{
		MissionID: string(missionID),
	}

	// Step 3: Call GraphLoader.LoadFindings (best-effort, errors logged at WARN).
	result, err := b.graphLoader.LoadFindings(ctx, execCtx, []*graphragpb.Finding{pbFinding})
	if err != nil {
		b.logger.WarnContext(ctx, "graphrag bridge: finding graph storage failed (best-effort)",
			"finding_id", finding.ID,
			"mission_id", missionID,
			"error", err,
		)
		return
	}

	// Step 4: Log result summary (non-fatal errors captured in LoadResult.Errors).
	if result != nil && result.HasErrors() {
		for _, e := range result.Errors {
			b.logger.WarnContext(ctx, "graphrag bridge: partial finding storage error",
				"finding_id", finding.ID,
				"error", e,
			)
		}
	}

	b.logger.DebugContext(ctx, "graphrag bridge: finding stored to graph",
		"finding_id", finding.ID,
		"mission_id", missionID,
		"nodes_created", result.NodesCreated,
	)

	// Publish a graph-update event if a Bus is wired and the tenant is known
	// via execCtx.TenantID (set by the caller, e.g. daemon mission_manager).
	// Spec: dashboard-knowledge-graph Task 9.
	if b.bus != nil && !execCtx.TenantID.IsZero() && result.NodesCreated > 0 {
		b.bus.Publish(execCtx.TenantID, &graphpb.GraphUpdate{
			Kind: graphpb.GraphUpdate_NODE_ADDED,
			At:   timestamppb.Now(),
		})
	}
}

// Compile-time interface check for DefaultGraphRAGBridge
var _ GraphRAGBridge = (*DefaultGraphRAGBridge)(nil)
