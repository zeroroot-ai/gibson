package observability

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
)

// CorrelationID is a unique identifier that links Neo4j graph nodes with Langfuse observability traces.
// It enables bidirectional lookup between graph data and tracing data for comprehensive observability.
type CorrelationID string

// GenerateCorrelationID creates a new unique correlation ID.
// Uses UUID v4 for uniqueness and cryptographic randomness.
func GenerateCorrelationID() CorrelationID {
	return CorrelationID(uuid.New().String())
}

// String returns the string representation of the correlation ID.
func (c CorrelationID) String() string {
	return string(c)
}

// IsZero checks if the correlation ID is empty or zero-valued.
func (c CorrelationID) IsZero() bool {
	return c == ""
}

// Validate checks if the correlation ID is a valid UUID format.
func (c CorrelationID) Validate() error {
	if c.IsZero() {
		return NewObservabilityError(ErrSpanContextMissing, "correlation ID cannot be empty")
	}

	if _, err := uuid.Parse(string(c)); err != nil {
		return WrapObservabilityError(ErrSpanContextMissing, "invalid correlation ID format", err)
	}

	return nil
}

// CorrelationStore provides bidirectional mapping between Neo4j nodes and Langfuse spans.
// It enables linking graph data with observability traces for comprehensive analysis.
//
// Thread-safety: All implementations must be safe for concurrent access.
type CorrelationStore interface {
	// StoreCorrelation stores the association between a Neo4j node and a Langfuse span.
	// If a correlation already exists for the node, it will be overwritten.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - nodeID: Neo4j node identifier (typically internal node ID or node property)
	//   - spanID: Langfuse span identifier from OpenTelemetry span context
	//
	// Returns:
	//   - error: Any error encountered during storage
	StoreCorrelation(ctx context.Context, nodeID string, spanID string) error

	// GetSpanForNode retrieves the Langfuse span ID associated with a Neo4j node.
	// Returns an error if no correlation exists for the given node.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - nodeID: Neo4j node identifier
	//
	// Returns:
	//   - string: Langfuse span ID
	//   - error: ErrSpanContextMissing if correlation not found, other errors for failures
	GetSpanForNode(ctx context.Context, nodeID string) (string, error)

	// GetNodeForSpan retrieves the Neo4j node ID associated with a Langfuse span.
	// Returns an error if no correlation exists for the given span.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - spanID: Langfuse span identifier
	//
	// Returns:
	//   - string: Neo4j node ID
	//   - error: ErrSpanContextMissing if correlation not found, other errors for failures
	GetNodeForSpan(ctx context.Context, spanID string) (string, error)
}

// Neo4jCorrelationStore implements CorrelationStore using Neo4j graph queries.
// It stores correlation data as properties on Neo4j nodes and uses indexes for efficient lookup.
//
// Storage Strategy:
//   - Correlations are stored as a "langfuse_span_id" property on Neo4j nodes
//   - A separate "Correlation" label is added to correlated nodes for efficient querying
//   - An index on (Correlation:langfuse_span_id) enables fast span-to-node lookups
//
// Thread-safety: Safe for concurrent access via Neo4j's connection pooling.
type Neo4jCorrelationStore struct {
	client graph.GraphClient
}

// NewNeo4jCorrelationStore creates a new Neo4j-backed correlation store.
// The store will ensure indexes exist on first use.
//
// Parameters:
//   - client: Neo4j graph client for executing queries
//
// Returns:
//   - *Neo4jCorrelationStore: The initialized store
//   - error: Any error encountered during initialization
func NewNeo4jCorrelationStore(client graph.GraphClient) (*Neo4jCorrelationStore, error) {
	if client == nil {
		return nil, NewObservabilityError(ErrExporterConnection, "graph client cannot be nil")
	}

	store := &Neo4jCorrelationStore{
		client: client,
	}

	// Create index for efficient span-to-node lookups
	// Use background context as this is initialization
	if err := store.ensureIndexes(context.Background()); err != nil {
		return nil, WrapObservabilityError(ErrExporterConnection,
			"failed to create correlation indexes", err)
	}

	return store, nil
}

// ensureIndexes creates necessary indexes for efficient correlation lookups.
func (s *Neo4jCorrelationStore) ensureIndexes(ctx context.Context) error {
	// Create index on langfuse_span_id for fast span-to-node lookups
	// Using IF NOT EXISTS to make this idempotent
	indexQuery := `
		CREATE INDEX correlation_span_id IF NOT EXISTS
		FOR (n:Correlation)
		ON (n.langfuse_span_id)
	`

	_, err := s.client.Query(ctx, indexQuery, nil)
	if err != nil {
		return WrapObservabilityError(ErrExporterConnection,
			"failed to create correlation index", err)
	}

	return nil
}

// StoreCorrelation stores the node-span correlation in Neo4j as a node property.
func (s *Neo4jCorrelationStore) StoreCorrelation(ctx context.Context, nodeID string, spanID string) error {
	if nodeID == "" {
		return NewObservabilityError(ErrSpanContextMissing, "node ID cannot be empty")
	}
	if spanID == "" {
		return NewObservabilityError(ErrSpanContextMissing, "span ID cannot be empty")
	}

	// Update the node with the span ID and add Correlation label
	// Using MATCH instead of CREATE to ensure node exists
	query := `
		MATCH (n)
		WHERE id(n) = $node_id
		SET n.langfuse_span_id = $span_id,
		    n:Correlation
		RETURN id(n) as node_id
	`

	params := map[string]any{
		"node_id": nodeID,
		"span_id": spanID,
	}

	result, err := s.client.Query(ctx, query, params)
	if err != nil {
		return WrapObservabilityError(ErrExporterConnection,
			"failed to store correlation", err)
	}

	if len(result.Records) == 0 {
		return NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("node %s not found in graph", nodeID))
	}

	return nil
}

// GetSpanForNode retrieves the Langfuse span ID for a given Neo4j node.
func (s *Neo4jCorrelationStore) GetSpanForNode(ctx context.Context, nodeID string) (string, error) {
	if nodeID == "" {
		return "", NewObservabilityError(ErrSpanContextMissing, "node ID cannot be empty")
	}

	query := `
		MATCH (n:Correlation)
		WHERE id(n) = $node_id
		RETURN n.langfuse_span_id as span_id
	`

	params := map[string]any{
		"node_id": nodeID,
	}

	result, err := s.client.Query(ctx, query, params)
	if err != nil {
		return "", WrapObservabilityError(ErrExporterConnection,
			"failed to query correlation", err)
	}

	if len(result.Records) == 0 {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("no correlation found for node %s", nodeID))
	}

	spanID, ok := result.Records[0]["span_id"].(string)
	if !ok || spanID == "" {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("invalid span ID for node %s", nodeID))
	}

	return spanID, nil
}

// GetNodeForSpan retrieves the Neo4j node ID for a given Langfuse span.
func (s *Neo4jCorrelationStore) GetNodeForSpan(ctx context.Context, spanID string) (string, error) {
	if spanID == "" {
		return "", NewObservabilityError(ErrSpanContextMissing, "span ID cannot be empty")
	}

	query := `
		MATCH (n:Correlation {langfuse_span_id: $span_id})
		RETURN id(n) as node_id
		LIMIT 1
	`

	params := map[string]any{
		"span_id": spanID,
	}

	result, err := s.client.Query(ctx, query, params)
	if err != nil {
		return "", WrapObservabilityError(ErrExporterConnection,
			"failed to query correlation", err)
	}

	if len(result.Records) == 0 {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("no correlation found for span %s", spanID))
	}

	// Neo4j returns node IDs as int64
	nodeIDInt, ok := result.Records[0]["node_id"].(int64)
	if !ok {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("invalid node ID for span %s", spanID))
	}

	return fmt.Sprintf("%d", nodeIDInt), nil
}

// InMemoryCorrelationStore provides an in-memory implementation of CorrelationStore for testing.
// It uses concurrent-safe maps for bidirectional lookups.
//
// Thread-safety: Safe for concurrent access via RWMutex.
type InMemoryCorrelationStore struct {
	mu         sync.RWMutex
	nodeToSpan map[string]string // nodeID -> spanID
	spanToNode map[string]string // spanID -> nodeID
}

// NewInMemoryCorrelationStore creates a new in-memory correlation store for testing.
func NewInMemoryCorrelationStore() *InMemoryCorrelationStore {
	return &InMemoryCorrelationStore{
		nodeToSpan: make(map[string]string),
		spanToNode: make(map[string]string),
	}
}

// StoreCorrelation stores the node-span correlation in memory.
func (s *InMemoryCorrelationStore) StoreCorrelation(ctx context.Context, nodeID string, spanID string) error {
	if nodeID == "" {
		return NewObservabilityError(ErrSpanContextMissing, "node ID cannot be empty")
	}
	if spanID == "" {
		return NewObservabilityError(ErrSpanContextMissing, "span ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove old correlations if they exist
	if oldSpanID, exists := s.nodeToSpan[nodeID]; exists {
		delete(s.spanToNode, oldSpanID)
	}
	if oldNodeID, exists := s.spanToNode[spanID]; exists {
		delete(s.nodeToSpan, oldNodeID)
	}

	// Store new correlations
	s.nodeToSpan[nodeID] = spanID
	s.spanToNode[spanID] = nodeID

	return nil
}

// GetSpanForNode retrieves the Langfuse span ID for a given Neo4j node.
func (s *InMemoryCorrelationStore) GetSpanForNode(ctx context.Context, nodeID string) (string, error) {
	if nodeID == "" {
		return "", NewObservabilityError(ErrSpanContextMissing, "node ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	spanID, exists := s.nodeToSpan[nodeID]
	if !exists {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("no correlation found for node %s", nodeID))
	}

	return spanID, nil
}

// GetNodeForSpan retrieves the Neo4j node ID for a given Langfuse span.
func (s *InMemoryCorrelationStore) GetNodeForSpan(ctx context.Context, spanID string) (string, error) {
	if spanID == "" {
		return "", NewObservabilityError(ErrSpanContextMissing, "span ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nodeID, exists := s.spanToNode[spanID]
	if !exists {
		return "", NewObservabilityError(ErrSpanContextMissing,
			fmt.Sprintf("no correlation found for span %s", spanID))
	}

	return nodeID, nil
}

// Clear removes all correlations from the store. Useful for testing.
func (s *InMemoryCorrelationStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodeToSpan = make(map[string]string)
	s.spanToNode = make(map[string]string)
}

// Count returns the number of correlations stored. Useful for testing.
func (s *InMemoryCorrelationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.nodeToSpan)
}
