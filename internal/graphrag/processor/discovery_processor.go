package processor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
)

// DiscoveryProcessor orchestrates the storage of discovered entities from proto DiscoveryResult.
// It delegates directly to GraphLoader.LoadDiscovery() which persists proto nodes and relationships
// into the knowledge graph with proper mission scoping and provenance tracking.
//
// The processor follows a best-effort storage model:
//   - Storage errors are logged but not propagated to the caller
//   - Individual node failures don't prevent other nodes from being stored
//   - The tool response returns immediately while storage happens asynchronously
//
// Example usage:
//
//	processor := NewDiscoveryProcessor(graphLoader, graphClient, logger)
//	result, err := processor.Process(ctx, execCtx, discoveryResult)
//	if result.HasErrors() {
//	    for _, err := range result.Errors {
//	        log.Printf("Storage error: %v", err)
//	    }
//	}
type DiscoveryProcessor interface {
	// Process stores discovered nodes from a proto DiscoveryResult in the graph.
	//
	// The process:
	//  1. Validates the discovery result is non-empty
	//  2. Calls loader.LoadDiscovery() to persist all proto entities directly
	//  3. Returns ProcessResult with statistics and any errors encountered
	//
	// Parameters:
	//  - ctx: Context for cancellation and timeouts
	//  - execCtx: Execution context containing mission run ID, agent name, etc.
	//  - discovery: The proto DiscoveryResult containing discovered entities
	//
	// Returns:
	//  - ProcessResult with statistics about nodes/relationships created
	//  - Error only for catastrophic failures (nil GraphLoader, etc.)
	//    Storage errors are captured in ProcessResult.Errors
	Process(ctx context.Context, execCtx loader.ExecContext, discovery *graphragpb.DiscoveryResult) (*ProcessResult, error)
}

// ProcessResult contains statistics and errors from a discovery processing operation.
type ProcessResult struct {
	// NodesCreated is the count of new nodes created in the graph.
	NodesCreated int

	// NodesUpdated is the count of existing nodes that were updated.
	// Currently always 0 (we CREATE not MERGE), but included for future use.
	NodesUpdated int

	// RelationshipsCreated is the count of relationships created (parent, BELONGS_TO, DISCOVERED).
	RelationshipsCreated int

	// Errors contains any errors encountered during processing.
	// Storage errors are logged and captured here but don't fail the operation.
	Errors []error

	// Duration is the total time spent processing and storing the discovery.
	Duration time.Duration
}

// HasErrors returns true if any errors were encountered during processing.
func (r *ProcessResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// AddError adds an error to the result and returns the result for chaining.
func (r *ProcessResult) AddError(err error) *ProcessResult {
	r.Errors = append(r.Errors, err)
	return r
}

// discoveryProcessor is the default implementation of DiscoveryProcessor.
type discoveryProcessor struct {
	loader *loader.GraphLoader
	client graph.GraphClient
	logger *slog.Logger
}

// NewDiscoveryProcessor creates a new DiscoveryProcessor with the given dependencies.
//
// Parameters:
//   - loader: GraphLoader for persisting nodes and relationships
//   - client: GraphClient for direct graph queries (used for explicit relationships)
//   - logger: Structured logger for diagnostic output
//
// Returns:
//   - DiscoveryProcessor instance ready to process discoveries
func NewDiscoveryProcessor(loader *loader.GraphLoader, client graph.GraphClient, logger *slog.Logger) DiscoveryProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	return &discoveryProcessor{
		loader: loader,
		client: client,
		logger: logger,
	}
}

// Process implements DiscoveryProcessor.Process.
func (p *discoveryProcessor) Process(ctx context.Context, execCtx loader.ExecContext, discovery *graphragpb.DiscoveryResult) (*ProcessResult, error) {
	startTime := time.Now()
	result := &ProcessResult{}

	// Validate inputs
	if p.loader == nil {
		return nil, fmt.Errorf("GraphLoader is nil")
	}
	if discovery == nil {
		return result, nil // Nothing to process
	}

	// Calculate node count from proto directly
	nodeCount := countProtoNodes(discovery)
	if nodeCount == 0 {
		p.logger.DebugContext(ctx, "Discovery result is empty, skipping storage")
		return result, nil
	}

	// Log discovery summary
	p.logger.InfoContext(ctx, "Processing discovery result",
		"node_count", nodeCount,
		"mission_run_id", execCtx.MissionRunID,
		"agent_name", execCtx.AgentName,
		"agent_run_id", execCtx.AgentRunID,
		"tool_execution_id", execCtx.ToolExecutionID,
	)

	// Store discovery result using proto-native loader
	// This creates all nodes, parent relationships, BELONGS_TO, and DISCOVERED relationships
	loadResult, err := p.loader.LoadDiscovery(ctx, execCtx, discovery)
	if err != nil {
		// Storage failed - log error but don't propagate
		p.logger.ErrorContext(ctx, "Failed to store discovery result",
			"error", err,
			"node_count", nodeCount,
			"mission_run_id", execCtx.MissionRunID,
		)
		result.AddError(fmt.Errorf("discovery storage failed: %w", err))
	} else {
		// Storage succeeded - update result statistics
		result.NodesCreated = loadResult.NodesCreated
		result.NodesUpdated = loadResult.NodesUpdated
		result.RelationshipsCreated = loadResult.RelationshipsCreated

		// If the LoadResult has errors, capture them (non-critical failures)
		if loadResult.HasErrors() {
			for _, loadErr := range loadResult.Errors {
				result.AddError(loadErr)
			}
		}

		p.logger.InfoContext(ctx, "Successfully stored discovery result",
			"nodes_created", result.NodesCreated,
			"relationships_created", result.RelationshipsCreated,
			"errors", len(result.Errors),
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
	}

	// Calculate total duration
	result.Duration = time.Since(startTime)

	return result, nil
}

// countProtoNodes returns the total count of all discovered entities in a proto DiscoveryResult.
func countProtoNodes(discovery *graphragpb.DiscoveryResult) int {
	if discovery == nil {
		return 0
	}

	count := len(discovery.Hosts) +
		len(discovery.Ports) +
		len(discovery.Services) +
		len(discovery.Endpoints) +
		len(discovery.Domains) +
		len(discovery.Subdomains) +
		len(discovery.Technologies) +
		len(discovery.Certificates) +
		len(discovery.Findings) +
		len(discovery.Evidence) +
		len(discovery.CustomNodes)

	return count
}
