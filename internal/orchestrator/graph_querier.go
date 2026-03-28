package orchestrator

import (
	"context"
	"time"
)

// GraphQuerier defines the interface for querying the GraphRAG knowledge graph
// in the context of memory recall. It provides methods for entity lookup,
// relationship traversal, pattern matching, and semantic search.
//
// All methods accept a context for cancellation and timeout control.
// Results are limited and paginated to prevent overwhelming the recall system.
type GraphQuerier interface {
	// EntityLookup retrieves entities matching specified criteria.
	// Supports filtering by entity type, properties, and mission scope.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout (500ms recommended)
	//   - query: EntityQuery with filters and pagination
	//
	// Returns matched entities with their properties and relationships.
	EntityLookup(ctx context.Context, query EntityQuery) ([]EntityMatch, error)

	// RelationshipTraversal traverses relationships from a starting entity.
	// Supports depth-limited traversal with relationship type filtering.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - query: RelationshipQuery specifying start entity and traversal options
	//
	// Returns related entities with path information.
	RelationshipTraversal(ctx context.Context, query RelationshipQuery) ([]RelatedEntity, error)

	// PatternMatch finds subgraph patterns in the knowledge graph.
	// Useful for finding assets matching specific structural patterns
	// (e.g., "hosts with open port 22 running SSH").
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - query: PatternQuery specifying the pattern to match
	//
	// Returns matched patterns with bound variables.
	PatternMatch(ctx context.Context, query PatternQuery) ([]PatternMatchResult, error)

	// SemanticSearch performs vector similarity search on entity descriptions.
	// Requires entities to have embeddings stored.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - query: SemanticQuery with search text and options
	//
	// Returns entities ranked by semantic similarity.
	SemanticSearch(ctx context.Context, query SemanticQuery) ([]EntityMatch, error)
}

// EntityQuery defines parameters for entity lookup queries.
type EntityQuery struct {
	// EntityTypes filters by entity types (e.g., ["host", "port", "service"])
	// Empty means all types.
	EntityTypes []string

	// Filters are property filters (e.g., {"ip": "192.168.1.1"})
	// Supports exact match only.
	Filters map[string]interface{}

	// MissionRunID scopes results to a specific mission run.
	// Empty means cross-mission search.
	MissionRunID string

	// TimeRange filters by discovery time.
	// Zero values mean no time filtering.
	TimeRange TimeRange

	// MaxResults limits the number of results (default 100, max 1000).
	MaxResults int

	// Offset for pagination.
	Offset int
}

// RelationshipQuery defines parameters for relationship traversal.
type RelationshipQuery struct {
	// StartEntityID is the starting point for traversal.
	StartEntityID string

	// StartEntityType is the type of the starting entity (for validation).
	StartEntityType string

	// RelationshipTypes filters by relationship types to traverse.
	// Empty means all relationship types.
	RelationshipTypes []string

	// Direction specifies traversal direction: "outgoing", "incoming", or "both".
	Direction string

	// MaxDepth limits traversal depth (default 2, max 5).
	MaxDepth int

	// MaxResults limits total results (default 100, max 1000).
	MaxResults int

	// IncludeProperties includes entity properties in results.
	IncludeProperties bool
}

// PatternQuery defines a graph pattern to match.
type PatternQuery struct {
	// Pattern is a simplified pattern specification.
	// Format: "entity_type:alias -[relationship]-> entity_type:alias"
	// Example: "host:h -[HAS_PORT]-> port:p -[RUNS_SERVICE]-> service:s"
	Pattern string

	// Filters are property filters per alias.
	// Example: {"p": {"number": 22}, "s": {"name": "ssh"}}
	Filters map[string]map[string]interface{}

	// MissionRunID scopes to a specific mission run.
	MissionRunID string

	// MaxResults limits results (default 100, max 1000).
	MaxResults int
}

// SemanticQuery defines parameters for semantic similarity search.
type SemanticQuery struct {
	// Query is the natural language query text.
	Query string

	// EntityTypes filters by entity types.
	EntityTypes []string

	// MissionRunID scopes to a specific mission run.
	MissionRunID string

	// MinSimilarity is the minimum similarity score (0.0-1.0).
	// Default is 0.7.
	MinSimilarity float64

	// MaxResults limits results (default 20, max 100).
	MaxResults int
}

// TimeRange specifies a time window for filtering.
type TimeRange struct {
	// Start is the beginning of the time range (inclusive).
	Start time.Time

	// End is the end of the time range (inclusive).
	End time.Time
}

// IsZero returns true if the time range is not set.
func (tr TimeRange) IsZero() bool {
	return tr.Start.IsZero() && tr.End.IsZero()
}

// EntityMatch represents an entity returned from a query.
type EntityMatch struct {
	// ID is the entity's unique identifier.
	ID string

	// Type is the entity type (e.g., "host", "port", "finding").
	Type string

	// Properties contains the entity's properties.
	Properties map[string]interface{}

	// Score is the relevance score (0.0-1.0) for ranked queries.
	// For non-ranked queries, this is 1.0.
	Score float64

	// MissionRunID is the mission run this entity belongs to.
	MissionRunID string

	// DiscoveredAt is when this entity was discovered.
	DiscoveredAt time.Time

	// DiscoveredBy is the tool/agent that discovered this entity.
	DiscoveredBy string
}

// RelatedEntity represents an entity found through relationship traversal.
type RelatedEntity struct {
	// Entity is the matched entity.
	Entity EntityMatch

	// Relationship describes the relationship to this entity.
	Relationship RelationshipInfo

	// Depth is the traversal depth from the start entity.
	Depth int

	// Path describes the traversal path from start to this entity.
	// Format: "start_id -[REL_TYPE]-> intermediate_id -[REL_TYPE]-> this_id"
	Path string
}

// RelationshipInfo describes a relationship between entities.
type RelationshipInfo struct {
	// Type is the relationship type (e.g., "HAS_PORT", "RUNS_SERVICE").
	Type string

	// FromID is the source entity ID.
	FromID string

	// ToID is the target entity ID.
	ToID string

	// Properties contains relationship properties.
	Properties map[string]interface{}
}

// PatternMatchResult represents a matched graph pattern.
type PatternMatchResult struct {
	// Bindings maps alias names to matched entities.
	// Example: {"h": EntityMatch{...}, "p": EntityMatch{...}}
	Bindings map[string]EntityMatch

	// Relationships contains the relationships in the match.
	Relationships []RelationshipInfo

	// Score is the match relevance score (0.0-1.0).
	Score float64
}

// MissionScope specifies how to scope graph queries across missions.
type MissionScope string

const (
	// MissionScopeCurrent limits queries to the current mission run.
	MissionScopeCurrent MissionScope = "current"

	// MissionScopeCrossMission allows queries across all mission runs.
	MissionScopeCrossMission MissionScope = "cross_mission"
)

// NoOpGraphQuerier is a GraphQuerier implementation that returns empty results.
// Used when no graph database is available.
type NoOpGraphQuerier struct{}

// NewNoOpGraphQuerier creates a new no-op GraphQuerier.
func NewNoOpGraphQuerier() *NoOpGraphQuerier {
	return &NoOpGraphQuerier{}
}

// EntityLookup returns empty results.
func (q *NoOpGraphQuerier) EntityLookup(ctx context.Context, query EntityQuery) ([]EntityMatch, error) {
	return []EntityMatch{}, nil
}

// RelationshipTraversal returns empty results.
func (q *NoOpGraphQuerier) RelationshipTraversal(ctx context.Context, query RelationshipQuery) ([]RelatedEntity, error) {
	return []RelatedEntity{}, nil
}

// PatternMatch returns empty results.
func (q *NoOpGraphQuerier) PatternMatch(ctx context.Context, query PatternQuery) ([]PatternMatchResult, error) {
	return []PatternMatchResult{}, nil
}

// SemanticSearch returns empty results.
func (q *NoOpGraphQuerier) SemanticSearch(ctx context.Context, query SemanticQuery) ([]EntityMatch, error) {
	return []EntityMatch{}, nil
}

// Ensure NoOpGraphQuerier implements GraphQuerier.
var _ GraphQuerier = (*NoOpGraphQuerier)(nil)
