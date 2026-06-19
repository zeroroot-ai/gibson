package harness

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/types"
)

type MockGraphRAGStore struct {
	// Control flags
	ShouldFailQuery                 bool
	ShouldFailFindSimilarAttacks    bool
	ShouldFailFindSimilarFindings   bool
	ShouldFailGetAttackChains       bool
	ShouldFailGetRelatedFindings    bool
	ShouldFailStore                 bool
	ShouldFailStoreWithoutEmbedding bool
	ShouldFailStoreBatch            bool
	ShouldFailStoreRelationshipOnly bool
	IsHealthy                       bool
	HealthMessage                   string

	// Capture method calls
	QueryCalled                 bool
	FindSimilarAttacksCalled    bool
	FindSimilarFindingsCalled   bool
	GetAttackChainsCalled       bool
	GetRelatedFindingsCalled    bool
	StoreCalled                 bool
	StoreWithoutEmbeddingCalled bool
	StoreBatchCalled            bool
	StoreRelationshipOnlyCalled bool
	HealthCalled                bool
	CloseCalled                 bool

	// Captured arguments
	LastQuery              *graphrag.GraphRAGQuery
	LastStoreRecord        *graphrag.GraphRecord
	LastStoreBatchRecords  []graphrag.GraphRecord
	LastStoreRelationship  *graphrag.Relationship
	LastFindAttacksContent string
	LastFindAttacksTopK    int
	LastFindFindingsID     string
	LastFindFindingsTopK   int
	LastAttackChainsTechID string
	LastAttackChainsDepth  int
	LastRelatedFindingID   string

	// Return values
	QueryResults    []graphrag.GraphRAGResult
	AttackPatterns  []graphrag.AttackPattern
	Findings        []graphrag.FindingNode
	AttackChains    []graphrag.AttackChain
	RelatedFindings []graphrag.FindingNode
	StoredNodeID    types.ID
}

// Query executes a hybrid GraphRAG query
func (m *MockGraphRAGStore) Query(ctx context.Context, query graphrag.GraphRAGQuery) ([]graphrag.GraphRAGResult, error) {
	m.QueryCalled = true
	m.LastQuery = &query

	if m.ShouldFailQuery {
		return nil, errors.New("mock query error")
	}

	return m.QueryResults, nil
}

// FindSimilarAttacks finds attack patterns similar to the given content
func (m *MockGraphRAGStore) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]graphrag.AttackPattern, error) {
	m.FindSimilarAttacksCalled = true
	m.LastFindAttacksContent = content
	m.LastFindAttacksTopK = topK

	if m.ShouldFailFindSimilarAttacks {
		return nil, errors.New("mock find similar attacks error")
	}

	return m.AttackPatterns, nil
}

// FindSimilarFindings finds findings similar to the specified finding
func (m *MockGraphRAGStore) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]graphrag.FindingNode, error) {
	m.FindSimilarFindingsCalled = true
	m.LastFindFindingsID = findingID
	m.LastFindFindingsTopK = topK

	if m.ShouldFailFindSimilarFindings {
		return nil, errors.New("mock find similar findings error")
	}

	return m.Findings, nil
}

// GetAttackChains discovers attack chains from a starting technique
func (m *MockGraphRAGStore) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]graphrag.AttackChain, error) {
	m.GetAttackChainsCalled = true
	m.LastAttackChainsTechID = techniqueID
	m.LastAttackChainsDepth = maxDepth

	if m.ShouldFailGetAttackChains {
		return nil, errors.New("mock get attack chains error")
	}

	return m.AttackChains, nil
}

// GetRelatedFindings retrieves findings related to the specified finding
func (m *MockGraphRAGStore) GetRelatedFindings(ctx context.Context, findingID string) ([]graphrag.FindingNode, error) {
	m.GetRelatedFindingsCalled = true
	m.LastRelatedFindingID = findingID

	if m.ShouldFailGetRelatedFindings {
		return nil, errors.New("mock get related findings error")
	}

	return m.RelatedFindings, nil
}

// Store stores a single graph record
func (m *MockGraphRAGStore) Store(ctx context.Context, record graphrag.GraphRecord) error {
	m.StoreCalled = true
	m.LastStoreRecord = &record

	if m.ShouldFailStore {
		return errors.New("mock store error")
	}

	// Set node ID if not set
	if m.StoredNodeID == "" {
		m.StoredNodeID = record.Node.ID
	}

	return nil
}

// StoreWithoutEmbedding stores a node directly without embedding generation
func (m *MockGraphRAGStore) StoreWithoutEmbedding(ctx context.Context, record graphrag.GraphRecord) error {
	m.StoreWithoutEmbeddingCalled = true
	m.LastStoreRecord = &record

	if m.ShouldFailStoreWithoutEmbedding {
		return errors.New("mock store without embedding error")
	}

	// Set node ID if not set
	if m.StoredNodeID == "" {
		m.StoredNodeID = record.Node.ID
	}

	return nil
}

// StoreBatch stores multiple graph records
func (m *MockGraphRAGStore) StoreBatch(ctx context.Context, records []graphrag.GraphRecord) error {
	m.StoreBatchCalled = true
	m.LastStoreBatchRecords = records

	if m.ShouldFailStoreBatch {
		return errors.New("mock store batch error")
	}

	return nil
}

// StoreAttackPattern stores a MITRE ATT&CK pattern (not used by bridge)
func (m *MockGraphRAGStore) StoreAttackPattern(ctx context.Context, pattern graphrag.AttackPattern) error {
	return nil
}

// StoreFinding stores a security finding (not used by bridge)
func (m *MockGraphRAGStore) StoreFinding(ctx context.Context, finding graphrag.FindingNode) error {
	return nil
}

// StoreFindingWithRun stores a finding with run association
func (m *MockGraphRAGStore) StoreFindingWithRun(ctx context.Context, finding graphrag.FindingNode, runID types.ID) error {
	return nil
}

// GetNode retrieves a single node by ID (for batch validation)
func (m *MockGraphRAGStore) GetNode(ctx context.Context, nodeID types.ID) (*graphrag.GraphNode, error) {
	// For testing, return a dummy node or error based on mock configuration
	// This can be extended with more sophisticated mock behavior as needed
	return nil, errors.New("node not found")
}

// Health returns the health status
func (m *MockGraphRAGStore) Health(ctx context.Context) types.HealthStatus {
	m.HealthCalled = true

	if m.IsHealthy {
		return types.Healthy(m.HealthMessage)
	}
	return types.Unhealthy(m.HealthMessage)
}

// Close releases all resources
func (m *MockGraphRAGStore) Close() error {
	m.CloseCalled = true
	return nil
}

// StoreRelationshipOnly stores a relationship without creating any nodes
func (m *MockGraphRAGStore) StoreRelationshipOnly(ctx context.Context, rel graphrag.Relationship) error {
	m.StoreRelationshipOnlyCalled = true
	m.LastStoreRelationship = &rel

	if m.ShouldFailStoreRelationshipOnly {
		return errors.New("mock store relationship only error")
	}

	return nil
}

// TraverseGraph walks the graph from startNodeID following filtered relationships.
func (m *MockGraphRAGStore) TraverseGraph(ctx context.Context, startNodeID string, maxDepth int, filters graphrag.TraversalFilters) ([]graphrag.GraphNode, error) {
	if m.ShouldFailQuery {
		return nil, errors.New("mock traverse error")
	}
	// Return empty result by default; callers can configure via QueryResults conversion.
	return nil, nil
}

// Compile-time check that MockGraphRAGStore implements graphrag.GraphRAGStore
var _ graphrag.GraphRAGStore = (*MockGraphRAGStore)(nil)
