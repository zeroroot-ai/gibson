package graphrag

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// GraphRAGProvider is the low-level graph + vector storage abstraction consumed
// by DefaultGraphRAGStore. There is exactly one production implementation
// (LocalGraphRAGProvider in provider/local.go), backed by Neo4j + a vector
// store. The previous "cloud" and "hybrid" providers were deleted on
// 2026-04-28 (spec internal-package-restructure / Phase B); they proxied to a
// non-existent Gibson Cloud GraphRAG API.
//
// Thread-safety: All implementations must be safe for concurrent access.
type GraphRAGProvider interface {
	// Initialize establishes connections to underlying storage systems.
	// Must be called before any other operations.
	Initialize(ctx context.Context) error

	// StoreNode stores a graph node with optional embedding vector.
	// Creates or updates the node in both graph and vector stores.
	StoreNode(ctx context.Context, node GraphNode) error

	// StoreRelationship creates a relationship between two nodes.
	StoreRelationship(ctx context.Context, rel Relationship) error

	// QueryNodes performs exact property-based node lookup.
	QueryNodes(ctx context.Context, query NodeQuery) ([]GraphNode, error)

	// QueryRelationships retrieves relationships matching the given criteria.
	QueryRelationships(ctx context.Context, query RelQuery) ([]Relationship, error)

	// TraverseGraph performs graph traversal up to maxHops depth, applying filters.
	TraverseGraph(ctx context.Context, startID string, maxHops int, filters TraversalFilters) ([]GraphNode, error)

	// VectorSearch performs pure vector similarity search.
	VectorSearch(ctx context.Context, embedding []float64, topK int, filters map[string]any) ([]VectorResult, error)

	// Health returns the current health status of the provider.
	Health(ctx context.Context) types.HealthStatus

	// Close releases all resources and closes connections.
	Close() error
}

// ProviderType is a tracing/observability label distinguishing provider
// implementations. With the cloud/hybrid impls deleted, only one value is
// valid in production. Retained because traced_store emits it as a span attr.
type ProviderType string

const (
	// ProviderTypeLocal is the Neo4j-backed implementation. The name "local"
	// is a historical artifact (it once contrasted with cloud/hybrid) — in
	// production this is the real graph store.
	ProviderTypeLocal ProviderType = "local"
)

// String returns the string representation of ProviderType.
func (pt ProviderType) String() string { return string(pt) }

// RelQuery represents a query for relationships.
// Used to filter relationships by type, node connections, and properties.
type RelQuery struct {
	FromID     *types.ID      `json:"from_id,omitempty"`
	ToID       *types.ID      `json:"to_id,omitempty"`
	Types      []RelationType `json:"types,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	MinWeight  float64        `json:"min_weight,omitempty"`
	Limit      int            `json:"limit,omitempty"`
}

// NewRelQuery creates a new RelQuery with default values.
func NewRelQuery() *RelQuery {
	return &RelQuery{
		Properties: make(map[string]any),
		Limit:      100,
	}
}

// WithFromID filters relationships from a specific node.
func (rq *RelQuery) WithFromID(fromID types.ID) *RelQuery {
	rq.FromID = &fromID
	return rq
}

// WithToID filters relationships to a specific node.
func (rq *RelQuery) WithToID(toID types.ID) *RelQuery {
	rq.ToID = &toID
	return rq
}

// WithTypes filters by relationship types.
func (rq *RelQuery) WithTypes(types ...RelationType) *RelQuery {
	rq.Types = types
	return rq
}

// WithProperty adds a property filter.
func (rq *RelQuery) WithProperty(key string, value any) *RelQuery {
	rq.Properties[key] = value
	return rq
}

// WithMinWeight filters by minimum relationship weight.
func (rq *RelQuery) WithMinWeight(minWeight float64) *RelQuery {
	rq.MinWeight = minWeight
	return rq
}

// WithLimit sets the maximum number of results.
func (rq *RelQuery) WithLimit(limit int) *RelQuery {
	rq.Limit = limit
	return rq
}
