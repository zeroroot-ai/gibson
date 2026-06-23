package graphrag

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracedGraphRAGProvider wraps a GraphRAGProvider with OpenTelemetry tracing.
// Creates spans for all provider operations and records GraphRAG-specific attributes.
//
// All operations are traced with appropriate span names:
//   - StoreNode: "gibson.graphrag.store"
//   - StoreRelationship: "gibson.graphrag.store"
//   - QueryNodes: "gibson.graphrag.query"
//   - QueryRelationships: "gibson.graphrag.query"
//   - TraverseGraph: "gibson.graphrag.traverse"
//   - VectorSearch: "gibson.graphrag.find_similar"
//
// Thread-safety: Safe for concurrent access (delegates to inner provider).
type TracedGraphRAGProvider struct {
	inner        GraphRAGProvider
	tracer       trace.Tracer
	providerType ProviderType
}

// TracedProviderOption is a functional option for configuring TracedGraphRAGProvider.
type TracedProviderOption func(*TracedGraphRAGProvider)

// NewTracedGraphRAGProvider creates a new traced GraphRAG provider.
// Wraps the inner provider with OpenTelemetry tracing for observability.
//
// Parameters:
//   - inner: The underlying GraphRAGProvider to wrap
//   - tracer: The OpenTelemetry tracer to use for creating spans
//   - opts: Optional configuration options
//
// Returns:
//   - *TracedGraphRAGProvider: A traced provider ready for use
//
// Example:
//
//	traced := NewTracedGraphRAGProvider(
//	    innerProvider,
//	    otel.Tracer("gibson.graphrag"),
//	    WithProviderType(ProviderTypeLocal),
//	)
func NewTracedGraphRAGProvider(inner GraphRAGProvider, tracer trace.Tracer, opts ...TracedProviderOption) *TracedGraphRAGProvider {
	p := &TracedGraphRAGProvider{
		inner:        inner,
		tracer:       tracer,
		providerType: ProviderTypeLocal, // Default
	}

	// Apply options
	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Initialize establishes connections to underlying storage systems with tracing.
// Creates a span named "gibson.graphrag.initialize".
func (p *TracedGraphRAGProvider) Initialize(ctx context.Context) error {
	ctx, span := p.tracer.Start(ctx, "gibson.graphrag.initialize")
	defer span.End()

	// Add provider attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)

	// Record start time
	startTime := time.Now()

	// Call inner provider
	err := p.inner.Initialize(ctx)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.init_duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return err
	}

	span.SetStatus(codes.Ok, "initialization succeeded")
	return nil
}

// StoreNode stores a graph node with optional embedding vector.
// Creates a span named "gibson.graphrag.store" with node attributes.
func (p *TracedGraphRAGProvider) StoreNode(ctx context.Context, node GraphNode) error {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGStore)
	defer span.End()

	// Add provider and node attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(NodeAttributes(node)...)

	// Record start time
	startTime := time.Now()

	// Call inner provider
	err := p.inner.StoreNode(ctx, node)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return err
	}

	span.SetStatus(codes.Ok, "node stored successfully")
	return nil
}

// StoreRelationship creates a relationship between two nodes.
// Creates a span named "gibson.graphrag.store" with relationship attributes.
func (p *TracedGraphRAGProvider) StoreRelationship(ctx context.Context, rel Relationship) error {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGStore)
	defer span.End()

	// Add provider and relationship attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(RelationshipAttributes(rel)...)

	// Record start time
	startTime := time.Now()

	// Call inner provider
	err := p.inner.StoreRelationship(ctx, rel)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return err
	}

	span.SetStatus(codes.Ok, "relationship stored successfully")
	return nil
}

// QueryNodes performs exact property-based node lookup.
// Creates a span named "gibson.graphrag.query" with query parameters.
func (p *TracedGraphRAGProvider) QueryNodes(ctx context.Context, query NodeQuery) ([]GraphNode, error) {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGQuery)
	defer span.End()

	// Add provider attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(attribute.String(AttrGraphRAGQueryType, "node"))

	// Add query parameters
	if len(query.NodeTypes) > 0 {
		nodeTypes := make([]string, len(query.NodeTypes))
		for i, nt := range query.NodeTypes {
			nodeTypes[i] = nt.String()
		}
		span.SetAttributes(attribute.StringSlice("gibson.graphrag.node_types", nodeTypes))
	}
	span.SetAttributes(attribute.Int("gibson.graphrag.limit", query.Limit))
	span.SetAttributes(attribute.Int("gibson.graphrag.property_count", len(query.Properties)))

	// Record start time
	startTime := time.Now()

	// Call inner provider
	nodes, err := p.inner.QueryNodes(ctx, query)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return nil, err
	}

	// Add result count
	span.SetAttributes(attribute.Int(AttrGraphRAGResultCount, len(nodes)))
	span.SetStatus(codes.Ok, fmt.Sprintf("found %d nodes", len(nodes)))
	return nodes, nil
}

// QueryRelationships retrieves relationships matching the given criteria.
// Creates a span named "gibson.graphrag.query" with query parameters.
func (p *TracedGraphRAGProvider) QueryRelationships(ctx context.Context, query RelQuery) ([]Relationship, error) {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGQuery)
	defer span.End()

	// Add provider attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(attribute.String(AttrGraphRAGQueryType, "relationship"))

	// Add query parameters
	if query.FromID != nil {
		span.SetAttributes(attribute.String("gibson.graphrag.from_id", query.FromID.String()))
	}
	if query.ToID != nil {
		span.SetAttributes(attribute.String("gibson.graphrag.to_id", query.ToID.String()))
	}
	if len(query.Types) > 0 {
		relTypes := make([]string, len(query.Types))
		for i, rt := range query.Types {
			relTypes[i] = rt.String()
		}
		span.SetAttributes(attribute.StringSlice("gibson.graphrag.relation_types", relTypes))
	}
	span.SetAttributes(attribute.Int("gibson.graphrag.limit", query.Limit))

	// Record start time
	startTime := time.Now()

	// Call inner provider
	rels, err := p.inner.QueryRelationships(ctx, query)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return nil, err
	}

	// Add result count
	span.SetAttributes(attribute.Int(AttrGraphRAGResultCount, len(rels)))
	span.SetStatus(codes.Ok, fmt.Sprintf("found %d relationships", len(rels)))
	return rels, nil
}

// TraverseGraph performs graph traversal starting from a node.
// Creates a span named "gibson.graphrag.traverse" with traversal parameters.
func (p *TracedGraphRAGProvider) TraverseGraph(ctx context.Context, startID string, maxHops int, filters TraversalFilters) ([]GraphNode, error) {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGTraverse)
	defer span.End()

	// Add provider and traversal attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(TraverseAttributes(startID, maxHops, filters)...)

	// Record start time
	startTime := time.Now()

	// Call inner provider
	nodes, err := p.inner.TraverseGraph(ctx, startID, maxHops, filters)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return nil, err
	}

	// Add result metrics
	span.SetAttributes(
		attribute.Int(AttrGraphRAGNodesVisited, len(nodes)),
		attribute.Int(AttrGraphRAGResultCount, len(nodes)),
	)
	span.SetStatus(codes.Ok, fmt.Sprintf("traversed %d nodes", len(nodes)))
	return nodes, nil
}

// VectorSearch performs pure vector similarity search.
// Creates a span named "gibson.graphrag.find_similar" with search parameters.
func (p *TracedGraphRAGProvider) VectorSearch(ctx context.Context, embedding []float64, topK int, filters map[string]any) ([]VectorResult, error) {
	ctx, span := p.tracer.Start(ctx, SpanGraphRAGFindSimilar)
	defer span.End()

	// Add provider and search attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)
	span.SetAttributes(VectorSearchAttributes(embedding, topK)...)

	// Add filter count
	span.SetAttributes(attribute.Int("gibson.graphrag.filter_count", len(filters)))

	// Record start time
	startTime := time.Now()

	// Call inner provider
	results, err := p.inner.VectorSearch(ctx, embedding, topK, filters)

	// Record duration
	duration := time.Since(startTime)
	span.SetAttributes(attribute.Float64("gibson.graphrag.duration_ms", float64(duration.Milliseconds())))

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return nil, err
	}

	// Add result metrics
	span.SetAttributes(attribute.Int(AttrGraphRAGResultCount, len(results)))
	if len(results) > 0 {
		// Add top result similarity score
		span.SetAttributes(attribute.Float64(AttrGraphRAGVectorScore, results[0].Similarity))
	}

	span.SetStatus(codes.Ok, fmt.Sprintf("found %d similar nodes", len(results)))
	return results, nil
}

// Health returns the current health status of the provider.
// This is a pass-through operation without additional tracing to avoid overhead.
func (p *TracedGraphRAGProvider) Health(ctx context.Context) types.HealthStatus {
	return p.inner.Health(ctx)
}

// Close releases all resources and closes connections.
// Creates a span named "gibson.graphrag.close".
func (p *TracedGraphRAGProvider) Close() error {
	// Create a background context for the close operation
	ctx := context.Background()
	ctx, span := p.tracer.Start(ctx, "gibson.graphrag.close")
	defer span.End()

	// Add provider attributes
	span.SetAttributes(ProviderAttributes(p.providerType)...)

	// Call inner provider
	err := p.inner.Close()

	// Handle error
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("error", true))
		span.SetAttributes(attribute.String("error.message", err.Error()))
		return err
	}

	span.SetStatus(codes.Ok, "provider closed successfully")
	return nil
}

// Ensure TracedGraphRAGProvider implements GraphRAGProvider at compile time
var _ GraphRAGProvider = (*TracedGraphRAGProvider)(nil)
