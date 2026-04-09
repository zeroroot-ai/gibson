package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/graphrag"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// MockGraphRAGStore implements graphrag.GraphRAGStore for testing
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

// Helper function to create a valid SDK query
func createValidSDKQuery() sdkgraphrag.Query {
	return sdkgraphrag.Query{
		Text:         "test query",
		TopK:         5,
		MaxHops:      2,
		MinScore:     0.5,
		VectorWeight: 0.6,
		GraphWeight:  0.4,
		NodeTypes:    []string{"Finding"},
	}
}

// TestDefaultGraphRAGQueryBridge_Query tests the Query method
func TestDefaultGraphRAGQueryBridge_Query(t *testing.T) {
	tests := []struct {
		name        string
		query       sdkgraphrag.Query
		mockResults []graphrag.GraphRAGResult
		shouldFail  bool
		checkError  func(t *testing.T, err error)
		checkResult func(t *testing.T, results []sdkgraphrag.Result, mock *MockGraphRAGStore)
	}{
		{
			name:  "successful query with results",
			query: createValidSDKQuery(),
			mockResults: []graphrag.GraphRAGResult{
				{
					Node: graphrag.GraphNode{
						ID:         types.NewID(),
						Labels:     []graphrag.NodeType{graphrag.NodeType("Finding")},
						Properties: map[string]any{"title": "Test Finding"},
						CreatedAt:  time.Now(),
						UpdatedAt:  time.Now(),
					},
					Score:       0.95,
					VectorScore: 0.98,
					GraphScore:  0.92,
					Path:        []types.ID{types.NewID()},
					Distance:    1,
				},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, results []sdkgraphrag.Result, mock *MockGraphRAGStore) {
				assert.Len(t, results, 1)
				assert.Equal(t, 0.95, results[0].Score)
				assert.Equal(t, 0.98, results[0].VectorScore)
				assert.Equal(t, 0.92, results[0].GraphScore)
				assert.Equal(t, 1, results[0].Distance)

				// Check that internal query was properly converted
				require.NotNil(t, mock.LastQuery)
				assert.Equal(t, "test query", mock.LastQuery.Text)
				assert.Equal(t, 5, mock.LastQuery.TopK)
				assert.Equal(t, 2, mock.LastQuery.MaxHops)
				assert.Equal(t, 0.5, mock.LastQuery.MinScore)
			},
		},
		{
			name:        "empty results",
			query:       createValidSDKQuery(),
			mockResults: []graphrag.GraphRAGResult{},
			shouldFail:  false,
			checkResult: func(t *testing.T, results []sdkgraphrag.Result, mock *MockGraphRAGStore) {
				assert.Len(t, results, 0)
				assert.True(t, mock.QueryCalled)
			},
		},
		{
			name:       "invalid query - missing text and embedding",
			query:      sdkgraphrag.Query{TopK: 5, MaxHops: 2},
			shouldFail: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid query")
			},
		},
		{
			name: "query with mission ID filter",
			query: func() sdkgraphrag.Query {
				q := createValidSDKQuery()
				q.MissionID = types.NewID().String()
				return q
			}(),
			mockResults: []graphrag.GraphRAGResult{},
			shouldFail:  false,
			checkResult: func(t *testing.T, results []sdkgraphrag.Result, mock *MockGraphRAGStore) {
				require.NotNil(t, mock.LastQuery)
				assert.NotNil(t, mock.LastQuery.MissionID)
			},
		},
		{
			name:       "store error propagation",
			query:      createValidSDKQuery(),
			shouldFail: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "query execution failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				QueryResults:    tt.mockResults,
				ShouldFailQuery: tt.shouldFail && tt.checkError != nil,
				IsHealthy:       true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			results, err := bridge.Query(ctx, tt.query)

			if tt.checkError != nil {
				tt.checkError(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, results, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_FindSimilarAttacks tests the FindSimilarAttacks method
func TestDefaultGraphRAGQueryBridge_FindSimilarAttacks(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		topK         int
		mockPatterns []graphrag.AttackPattern
		shouldFail   bool
		checkResult  func(t *testing.T, patterns []sdkgraphrag.AttackPattern, mock *MockGraphRAGStore)
	}{
		{
			name:    "successful attack pattern search",
			content: "lateral movement using SSH",
			topK:    3,
			mockPatterns: []graphrag.AttackPattern{
				{
					ID:          types.NewID(),
					TechniqueID: "T1021.004",
					Name:        "Remote Services: SSH",
					Description: "Adversaries may use SSH to move laterally",
					Tactics:     []string{"Lateral Movement"},
					Platforms:   []string{"Linux", "macOS"},
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, patterns []sdkgraphrag.AttackPattern, mock *MockGraphRAGStore) {
				assert.Len(t, patterns, 1)
				assert.Equal(t, "T1021.004", patterns[0].TechniqueID)
				assert.Equal(t, "Remote Services: SSH", patterns[0].Name)
				assert.Contains(t, patterns[0].Tactics, "Lateral Movement")

				// Check captured arguments
				assert.Equal(t, "lateral movement using SSH", mock.LastFindAttacksContent)
				assert.Equal(t, 3, mock.LastFindAttacksTopK)
			},
		},
		{
			name:         "no patterns found",
			content:      "unknown technique",
			topK:         5,
			mockPatterns: []graphrag.AttackPattern{},
			shouldFail:   false,
			checkResult: func(t *testing.T, patterns []sdkgraphrag.AttackPattern, mock *MockGraphRAGStore) {
				assert.Len(t, patterns, 0)
				assert.True(t, mock.FindSimilarAttacksCalled)
			},
		},
		{
			name:       "store error",
			content:    "test content",
			topK:       5,
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				AttackPatterns:               tt.mockPatterns,
				ShouldFailFindSimilarAttacks: tt.shouldFail,
				IsHealthy:                    true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			patterns, err := bridge.FindSimilarAttacks(ctx, tt.content, tt.topK)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, patterns, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_FindSimilarFindings tests the FindSimilarFindings method
func TestDefaultGraphRAGQueryBridge_FindSimilarFindings(t *testing.T) {
	tests := []struct {
		name         string
		findingID    string
		topK         int
		mockFindings []graphrag.FindingNode
		shouldFail   bool
		checkResult  func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore)
	}{
		{
			name:      "successful finding search",
			findingID: types.NewID().String(),
			topK:      5,
			mockFindings: []graphrag.FindingNode{
				{
					ID:          types.NewID(),
					Title:       "SQL Injection",
					Description: "SQL injection vulnerability detected",
					Severity:    "high",
					Category:    "injection",
					Confidence:  0.95,
					MissionID:   types.NewID(),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore) {
				assert.Len(t, findings, 1)
				assert.Equal(t, "SQL Injection", findings[0].Title)
				assert.Equal(t, "high", findings[0].Severity)
				assert.Equal(t, 0.95, findings[0].Confidence)

				// Check captured arguments
				assert.Equal(t, 5, mock.LastFindFindingsTopK)
			},
		},
		{
			name:         "no similar findings",
			findingID:    types.NewID().String(),
			topK:         3,
			mockFindings: []graphrag.FindingNode{},
			shouldFail:   false,
			checkResult: func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore) {
				assert.Len(t, findings, 0)
				assert.True(t, mock.FindSimilarFindingsCalled)
			},
		},
		{
			name:       "store error",
			findingID:  types.NewID().String(),
			topK:       5,
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				Findings:                      tt.mockFindings,
				ShouldFailFindSimilarFindings: tt.shouldFail,
				IsHealthy:                     true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			findings, err := bridge.FindSimilarFindings(ctx, tt.findingID, tt.topK)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, findings, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_GetAttackChains tests the GetAttackChains method
func TestDefaultGraphRAGQueryBridge_GetAttackChains(t *testing.T) {
	tests := []struct {
		name        string
		techniqueID string
		maxDepth    int
		mockChains  []graphrag.AttackChain
		shouldFail  bool
		checkResult func(t *testing.T, chains []sdkgraphrag.AttackChain, mock *MockGraphRAGStore)
	}{
		{
			name:        "successful attack chain discovery",
			techniqueID: "T1566",
			maxDepth:    3,
			mockChains: []graphrag.AttackChain{
				{
					ID:       types.NewID(),
					Name:     "Phishing to Data Exfiltration",
					Severity: "critical",
					Steps: []graphrag.AttackStep{
						{
							Order:       1,
							TechniqueID: "T1566",
							NodeID:      types.NewID(),
							Description: "Initial phishing email",
							Confidence:  0.9,
						},
						{
							Order:       2,
							TechniqueID: "T1059",
							NodeID:      types.NewID(),
							Description: "Command execution",
							Confidence:  0.85,
						},
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, chains []sdkgraphrag.AttackChain, mock *MockGraphRAGStore) {
				assert.Len(t, chains, 1)
				assert.Equal(t, "Phishing to Data Exfiltration", chains[0].Name)
				assert.Equal(t, "critical", chains[0].Severity)
				assert.Len(t, chains[0].Steps, 2)
				assert.Equal(t, 1, chains[0].Steps[0].Order)
				assert.Equal(t, "T1566", chains[0].Steps[0].TechniqueID)

				// Check captured arguments
				assert.Equal(t, "T1566", mock.LastAttackChainsTechID)
				assert.Equal(t, 3, mock.LastAttackChainsDepth)
			},
		},
		{
			name:        "no chains found",
			techniqueID: "T9999",
			maxDepth:    2,
			mockChains:  []graphrag.AttackChain{},
			shouldFail:  false,
			checkResult: func(t *testing.T, chains []sdkgraphrag.AttackChain, mock *MockGraphRAGStore) {
				assert.Len(t, chains, 0)
				assert.True(t, mock.GetAttackChainsCalled)
			},
		},
		{
			name:        "store error",
			techniqueID: "T1566",
			maxDepth:    3,
			shouldFail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				AttackChains:              tt.mockChains,
				ShouldFailGetAttackChains: tt.shouldFail,
				IsHealthy:                 true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			chains, err := bridge.GetAttackChains(ctx, tt.techniqueID, tt.maxDepth)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, chains, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_GetRelatedFindings tests the GetRelatedFindings method
func TestDefaultGraphRAGQueryBridge_GetRelatedFindings(t *testing.T) {
	tests := []struct {
		name         string
		findingID    string
		mockFindings []graphrag.FindingNode
		shouldFail   bool
		checkResult  func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore)
	}{
		{
			name:      "successful related findings retrieval",
			findingID: types.NewID().String(),
			mockFindings: []graphrag.FindingNode{
				{
					ID:          types.NewID(),
					Title:       "Related Finding 1",
					Description: "First related finding",
					Severity:    "medium",
					Category:    "web",
					Confidence:  0.88,
					MissionID:   types.NewID(),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				},
				{
					ID:          types.NewID(),
					Title:       "Related Finding 2",
					Description: "Second related finding",
					Severity:    "low",
					Category:    "network",
					Confidence:  0.75,
					MissionID:   types.NewID(),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore) {
				assert.Len(t, findings, 2)
				assert.Equal(t, "Related Finding 1", findings[0].Title)
				assert.Equal(t, "Related Finding 2", findings[1].Title)
				assert.True(t, mock.GetRelatedFindingsCalled)
			},
		},
		{
			name:         "no related findings",
			findingID:    types.NewID().String(),
			mockFindings: []graphrag.FindingNode{},
			shouldFail:   false,
			checkResult: func(t *testing.T, findings []sdkgraphrag.FindingNode, mock *MockGraphRAGStore) {
				assert.Len(t, findings, 0)
			},
		},
		{
			name:       "store error",
			findingID:  types.NewID().String(),
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				RelatedFindings:              tt.mockFindings,
				ShouldFailGetRelatedFindings: tt.shouldFail,
				IsHealthy:                    true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			findings, err := bridge.GetRelatedFindings(ctx, tt.findingID)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, findings, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_StoreNode tests the StoreNode method
func TestDefaultGraphRAGQueryBridge_StoreNode(t *testing.T) {
	tests := []struct {
		name        string
		node        sdkgraphrag.GraphNode
		missionID   string
		agentName   string
		shouldFail  bool
		checkResult func(t *testing.T, nodeID string, mock *MockGraphRAGStore)
	}{
		{
			name: "successful node storage",
			node: sdkgraphrag.GraphNode{
				Type:       "Finding",
				Content:    "Test finding content",
				Properties: map[string]any{"severity": "high"},
			},
			missionID:  types.NewID().String(),
			agentName:  "test-agent",
			shouldFail: false,
			checkResult: func(t *testing.T, nodeID string, mock *MockGraphRAGStore) {
				assert.NotEmpty(t, nodeID)
				assert.True(t, mock.StoreCalled)
				require.NotNil(t, mock.LastStoreRecord)

				// Check that mission ID and agent name were set
				node := mock.LastStoreRecord.Node
				assert.NotNil(t, node.MissionID)
				assert.Equal(t, "test-agent", node.Properties["agent_name"])
				assert.Equal(t, "high", node.Properties["severity"])
			},
		},
		{
			name: "node with existing ID",
			node: sdkgraphrag.GraphNode{
				ID:         types.NewID().String(),
				Type:       "Entity",
				Properties: map[string]any{"name": "test"},
			},
			missionID:  types.NewID().String(),
			agentName:  "agent-2",
			shouldFail: false,
			checkResult: func(t *testing.T, nodeID string, mock *MockGraphRAGStore) {
				assert.NotEmpty(t, nodeID)
				require.NotNil(t, mock.LastStoreRecord)
				assert.Equal(t, "test", mock.LastStoreRecord.Node.Properties["name"])
			},
		},
		{
			name: "invalid node - missing type",
			node: sdkgraphrag.GraphNode{
				Properties: map[string]any{"test": "value"},
			},
			missionID:  types.NewID().String(),
			agentName:  "agent",
			shouldFail: true,
		},
		{
			name: "store error",
			node: sdkgraphrag.GraphNode{
				Type: "Finding",
			},
			missionID:  types.NewID().String(),
			agentName:  "agent",
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				ShouldFailStore: tt.shouldFail && tt.name == "store error",
				IsHealthy:       true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			nodeID, err := bridge.StoreNode(ctx, tt.node, tt.missionID, tt.agentName)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, nodeID, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_CreateRelationship tests the CreateRelationship method
func TestDefaultGraphRAGQueryBridge_CreateRelationship(t *testing.T) {
	fromID := types.NewID()
	toID := types.NewID()

	tests := []struct {
		name        string
		rel         sdkgraphrag.Relationship
		shouldFail  bool
		checkResult func(t *testing.T, mock *MockGraphRAGStore)
	}{
		{
			name: "successful relationship creation",
			rel: sdkgraphrag.Relationship{
				FromID:     fromID.String(),
				ToID:       toID.String(),
				Type:       "SIMILAR_TO",
				Properties: map[string]any{"weight": 0.85},
			},
			shouldFail: false,
			checkResult: func(t *testing.T, mock *MockGraphRAGStore) {
				assert.True(t, mock.StoreRelationshipOnlyCalled)
				require.NotNil(t, mock.LastStoreRelationship)

				// Check that relationship was stored correctly
				assert.Equal(t, fromID, mock.LastStoreRelationship.FromID)
				assert.Equal(t, toID, mock.LastStoreRelationship.ToID)
				assert.Equal(t, graphrag.RelationType("SIMILAR_TO"), mock.LastStoreRelationship.Type)
			},
		},
		{
			name: "invalid relationship - missing type",
			rel: sdkgraphrag.Relationship{
				FromID: fromID.String(),
				ToID:   toID.String(),
			},
			shouldFail: true,
		},
		{
			name: "invalid from_id",
			rel: sdkgraphrag.Relationship{
				FromID: "invalid-id",
				ToID:   toID.String(),
				Type:   "RELATED_TO",
			},
			shouldFail: true,
		},
		{
			name: "store error",
			rel: sdkgraphrag.Relationship{
				FromID: fromID.String(),
				ToID:   toID.String(),
				Type:   "EXPLOITS",
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				ShouldFailStoreRelationshipOnly: tt.shouldFail && tt.name == "store error",
				IsHealthy:                       true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			err := bridge.CreateRelationship(ctx, tt.rel)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_StoreBatch tests the StoreBatch method
func TestDefaultGraphRAGQueryBridge_StoreBatch(t *testing.T) {
	tests := []struct {
		name        string
		batch       sdkgraphrag.Batch
		missionID   string
		agentName   string
		shouldFail  bool
		checkResult func(t *testing.T, nodeIDs []string, mock *MockGraphRAGStore)
	}{
		{
			name: "successful batch storage",
			batch: sdkgraphrag.Batch{
				Nodes: []sdkgraphrag.GraphNode{
					{
						Type:       "Finding",
						Properties: map[string]any{"title": "Finding 1"},
					},
					{
						Type:       "Finding",
						Properties: map[string]any{"title": "Finding 2"},
					},
				},
				Relationships: []sdkgraphrag.Relationship{},
			},
			missionID:  types.NewID().String(),
			agentName:  "batch-agent",
			shouldFail: false,
			checkResult: func(t *testing.T, nodeIDs []string, mock *MockGraphRAGStore) {
				assert.Len(t, nodeIDs, 2)
				assert.True(t, mock.StoreBatchCalled)
				require.NotNil(t, mock.LastStoreBatchRecords)
				assert.Len(t, mock.LastStoreBatchRecords, 2)

				// Check that mission ID and agent name were set
				for _, record := range mock.LastStoreBatchRecords {
					assert.NotNil(t, record.Node.MissionID)
					assert.Equal(t, "batch-agent", record.Node.Properties["agent_name"])
				}
			},
		},
		{
			name: "batch with relationships",
			batch: func() sdkgraphrag.Batch {
				node1ID := types.NewID()
				node2ID := types.NewID()
				return sdkgraphrag.Batch{
					Nodes: []sdkgraphrag.GraphNode{
						{ID: node1ID.String(), Type: "Finding"},
						{ID: node2ID.String(), Type: "Finding"},
					},
					Relationships: []sdkgraphrag.Relationship{
						{
							FromID: node1ID.String(),
							ToID:   node2ID.String(),
							Type:   "RELATED_TO",
						},
					},
				}
			}(),
			missionID:  types.NewID().String(),
			agentName:  "agent",
			shouldFail: false,
			checkResult: func(t *testing.T, nodeIDs []string, mock *MockGraphRAGStore) {
				assert.Len(t, nodeIDs, 2)
				require.NotNil(t, mock.LastStoreBatchRecords)

				// Check that first record has the relationship
				assert.Len(t, mock.LastStoreBatchRecords[0].Relationships, 1)
			},
		},
		{
			name: "invalid node in batch",
			batch: sdkgraphrag.Batch{
				Nodes: []sdkgraphrag.GraphNode{
					{Type: "Finding"},
					{}, // Invalid - missing type
				},
			},
			missionID:  types.NewID().String(),
			agentName:  "agent",
			shouldFail: true,
		},
		{
			name: "store batch error",
			batch: sdkgraphrag.Batch{
				Nodes: []sdkgraphrag.GraphNode{
					{Type: "Finding"},
				},
			},
			missionID:  types.NewID().String(),
			agentName:  "agent",
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				ShouldFailStoreBatch: tt.shouldFail && tt.name == "store batch error",
				IsHealthy:            true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			nodeIDs, err := bridge.StoreBatch(ctx, tt.batch, tt.missionID, tt.agentName)

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, nodeIDs, mock)
				}
			}
		})
	}
}

// TestDefaultGraphRAGQueryBridge_Traverse tests the Traverse method
func TestDefaultGraphRAGQueryBridge_Traverse(t *testing.T) {
	startNodeID := types.NewID().String()

	tests := []struct {
		name string
		opts sdkgraphrag.TraversalOptions
	}{
		{
			name: "traverse returns not implemented",
			opts: sdkgraphrag.TraversalOptions{
				MaxDepth:          3,
				Direction:         "outbound",
				RelationshipTypes: []string{"SIMILAR_TO"},
				NodeTypes:         []string{"Finding"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				IsHealthy: true,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			results, err := bridge.Traverse(ctx, startNodeID, tt.opts)

			// Traverse should return "not yet implemented" error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not yet implemented")
			assert.Nil(t, results)
		})
	}
}

// TestDefaultGraphRAGQueryBridge_Health tests the Health method
func TestDefaultGraphRAGQueryBridge_Health(t *testing.T) {
	tests := []struct {
		name          string
		isHealthy     bool
		healthMessage string
		checkResult   func(t *testing.T, status types.HealthStatus)
	}{
		{
			name:          "healthy store",
			isHealthy:     true,
			healthMessage: "all systems operational",
			checkResult: func(t *testing.T, status types.HealthStatus) {
				assert.True(t, status.IsHealthy())
				assert.Contains(t, status.Message, "all systems operational")
			},
		},
		{
			name:          "unhealthy store",
			isHealthy:     false,
			healthMessage: "connection error",
			checkResult: func(t *testing.T, status types.HealthStatus) {
				assert.True(t, status.IsUnhealthy())
				assert.Contains(t, status.Message, "connection error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGraphRAGStore{
				IsHealthy:     tt.isHealthy,
				HealthMessage: tt.healthMessage,
			}

			bridge := NewGraphRAGQueryBridge(mock, nil)
			ctx := context.Background()

			status := bridge.Health(ctx)

			assert.True(t, mock.HealthCalled)
			if tt.checkResult != nil {
				tt.checkResult(t, status)
			}
		})
	}
}

// Note: TestDefaultGraphRAGQueryBridge_NilStore has been removed since GraphRAG is now
// a required core component. The bridge should never be created with a nil store.
// NoopGraphRAGQueryBridge tests have also been removed for the same reason.

// TestStoreBatch_ValidBatch tests that a batch with valid relationships succeeds.
func TestStoreBatch_ValidBatch(t *testing.T) {
	// Create nodes with IDs
	node1ID := types.NewID()
	node2ID := types.NewID()
	node3ID := types.NewID()

	batch := sdkgraphrag.Batch{
		Nodes: []sdkgraphrag.GraphNode{
			{
				ID:         node1ID.String(),
				Type:       "Host",
				Properties: map[string]any{"name": "server1"},
			},
			{
				ID:         node2ID.String(),
				Type:       "Port",
				Properties: map[string]any{"number": 443},
			},
			{
				ID:         node3ID.String(),
				Type:       "Service",
				Properties: map[string]any{"name": "https"},
			},
		},
		Relationships: []sdkgraphrag.Relationship{
			{
				FromID: node1ID.String(),
				ToID:   node2ID.String(),
				Type:   "HAS_PORT",
			},
			{
				FromID: node2ID.String(),
				ToID:   node3ID.String(),
				Type:   "RUNS_SERVICE",
			},
		},
	}

	mock := &MockGraphRAGStore{
		IsHealthy: true,
	}

	bridge := NewGraphRAGQueryBridge(mock, nil)
	ctx := context.Background()
	missionID := types.NewID().String()

	nodeIDs, err := bridge.StoreBatch(ctx, batch, missionID, "test-agent")

	// Should succeed without errors
	require.NoError(t, err)
	assert.Len(t, nodeIDs, 3)
	assert.True(t, mock.StoreBatchCalled)
	require.NotNil(t, mock.LastStoreBatchRecords)
	assert.Len(t, mock.LastStoreBatchRecords, 3)

	// Verify relationships were added to the correct records
	// First record (node1) should have the HAS_PORT relationship
	assert.Len(t, mock.LastStoreBatchRecords[0].Relationships, 1)
	assert.Equal(t, node1ID, mock.LastStoreBatchRecords[0].Relationships[0].FromID)
	assert.Equal(t, node2ID, mock.LastStoreBatchRecords[0].Relationships[0].ToID)

	// Second record (node2) should have the RUNS_SERVICE relationship
	assert.Len(t, mock.LastStoreBatchRecords[1].Relationships, 1)
	assert.Equal(t, node2ID, mock.LastStoreBatchRecords[1].Relationships[0].FromID)
	assert.Equal(t, node3ID, mock.LastStoreBatchRecords[1].Relationships[0].ToID)

	// Third record (node3) should have no relationships
	assert.Len(t, mock.LastStoreBatchRecords[2].Relationships, 0)
}

// TestStoreBatch_InvalidFromID tests that a batch with invalid FromID is rejected.
func TestStoreBatch_InvalidFromID(t *testing.T) {
	node1ID := types.NewID()
	node2ID := types.NewID()
	invalidFromID := types.NewID() // Not in batch

	batch := sdkgraphrag.Batch{
		Nodes: []sdkgraphrag.GraphNode{
			{
				ID:         node1ID.String(),
				Type:       "Host",
				Properties: map[string]any{"name": "server1"},
			},
			{
				ID:         node2ID.String(),
				Type:       "Port",
				Properties: map[string]any{"number": 443},
			},
		},
		Relationships: []sdkgraphrag.Relationship{
			{
				FromID: invalidFromID.String(), // Invalid - not in batch
				ToID:   node2ID.String(),
				Type:   "HAS_PORT",
			},
		},
	}

	mock := &MockGraphRAGStore{
		IsHealthy: true,
	}

	bridge := NewGraphRAGQueryBridge(mock, nil)
	ctx := context.Background()
	missionID := types.NewID().String()

	nodeIDs, err := bridge.StoreBatch(ctx, batch, missionID, "test-agent")

	// Should fail with validation error
	require.Error(t, err)
	assert.Nil(t, nodeIDs)
	assert.Contains(t, err.Error(), "batch validation failed")
	assert.Contains(t, err.Error(), "invalid relationships")
	assert.Contains(t, err.Error(), invalidFromID.String())
	assert.Contains(t, err.Error(), "from_id")
	assert.Contains(t, err.Error(), "not found")
	assert.False(t, mock.StoreBatchCalled, "StoreBatch should not be called when validation fails")
}

// TestStoreBatch_InvalidToID tests that a batch with invalid ToID is rejected.
func TestStoreBatch_InvalidToID(t *testing.T) {
	node1ID := types.NewID()
	node2ID := types.NewID()
	invalidToID := types.NewID() // Not in batch

	batch := sdkgraphrag.Batch{
		Nodes: []sdkgraphrag.GraphNode{
			{
				ID:         node1ID.String(),
				Type:       "Host",
				Properties: map[string]any{"name": "server1"},
			},
			{
				ID:         node2ID.String(),
				Type:       "Port",
				Properties: map[string]any{"number": 443},
			},
		},
		Relationships: []sdkgraphrag.Relationship{
			{
				FromID: node1ID.String(),
				ToID:   invalidToID.String(), // Invalid - not in batch
				Type:   "HAS_PORT",
			},
		},
	}

	mock := &MockGraphRAGStore{
		IsHealthy: true,
	}

	bridge := NewGraphRAGQueryBridge(mock, nil)
	ctx := context.Background()
	missionID := types.NewID().String()

	nodeIDs, err := bridge.StoreBatch(ctx, batch, missionID, "test-agent")

	// Should fail with validation error
	require.Error(t, err)
	assert.Nil(t, nodeIDs)
	assert.Contains(t, err.Error(), "batch validation failed")
	assert.Contains(t, err.Error(), "invalid relationships")
	assert.Contains(t, err.Error(), invalidToID.String())
	assert.Contains(t, err.Error(), "to_id")
	assert.Contains(t, err.Error(), "not found")
	assert.False(t, mock.StoreBatchCalled, "StoreBatch should not be called when validation fails")
}

// TestStoreBatch_MultipleInvalid tests that all invalid relationships are reported.
func TestStoreBatch_MultipleInvalid(t *testing.T) {
	node1ID := types.NewID()
	node2ID := types.NewID()
	invalidFromID1 := types.NewID() // Not in batch
	invalidFromID2 := types.NewID() // Not in batch
	invalidToID1 := types.NewID()   // Not in batch
	invalidToID2 := types.NewID()   // Not in batch

	batch := sdkgraphrag.Batch{
		Nodes: []sdkgraphrag.GraphNode{
			{
				ID:         node1ID.String(),
				Type:       "Host",
				Properties: map[string]any{"name": "server1"},
			},
			{
				ID:         node2ID.String(),
				Type:       "Port",
				Properties: map[string]any{"number": 443},
			},
		},
		Relationships: []sdkgraphrag.Relationship{
			{
				FromID: invalidFromID1.String(), // Invalid from_id
				ToID:   node2ID.String(),
				Type:   "HAS_PORT",
			},
			{
				FromID: node1ID.String(),
				ToID:   invalidToID1.String(), // Invalid to_id
				Type:   "CONNECTS_TO",
			},
			{
				FromID: invalidFromID2.String(), // Invalid from_id
				ToID:   invalidToID2.String(),   // Invalid to_id (both invalid)
				Type:   "SIMILAR_TO",
			},
		},
	}

	mock := &MockGraphRAGStore{
		IsHealthy: true,
	}

	bridge := NewGraphRAGQueryBridge(mock, nil)
	ctx := context.Background()
	missionID := types.NewID().String()

	nodeIDs, err := bridge.StoreBatch(ctx, batch, missionID, "test-agent")

	// Should fail with validation error
	require.Error(t, err)
	assert.Nil(t, nodeIDs)
	assert.Contains(t, err.Error(), "batch validation failed")
	assert.Contains(t, err.Error(), "invalid relationships")
	assert.False(t, mock.StoreBatchCalled, "StoreBatch should not be called when validation fails")

	// All invalid relationships should be listed in the error
	errorMsg := err.Error()

	// Check for first relationship (invalid from_id)
	assert.Contains(t, errorMsg, "rel[0]")
	assert.Contains(t, errorMsg, "HAS_PORT")
	assert.Contains(t, errorMsg, invalidFromID1.String())
	assert.Contains(t, errorMsg, "from_id")

	// Check for second relationship (invalid to_id)
	assert.Contains(t, errorMsg, "rel[1]")
	assert.Contains(t, errorMsg, "CONNECTS_TO")
	assert.Contains(t, errorMsg, invalidToID1.String())
	assert.Contains(t, errorMsg, "to_id")

	// Check for third relationship (both from_id and to_id invalid)
	assert.Contains(t, errorMsg, "rel[2]")
	assert.Contains(t, errorMsg, "SIMILAR_TO")
	assert.Contains(t, errorMsg, invalidFromID2.String())
	assert.Contains(t, errorMsg, invalidToID2.String())

	// Verify that error messages include relationship types
	assert.Contains(t, errorMsg, "HAS_PORT")
	assert.Contains(t, errorMsg, "CONNECTS_TO")
	assert.Contains(t, errorMsg, "SIMILAR_TO")
}

// TestStoreSemantic tests the StoreSemantic method
func TestStoreSemantic(t *testing.T) {
	tests := []struct {
		name       string
		node       sdkgraphrag.GraphNode
		shouldFail bool
		checkError func(t *testing.T, err error)
	}{
		{
			name: "successful semantic store with content",
			node: sdkgraphrag.GraphNode{
				Type:    "Finding",
				Content: "This is a test finding with semantic content",
				Properties: map[string]any{
					"severity": "high",
				},
			},
			shouldFail: false,
		},
		{
			name: "fails without content",
			node: sdkgraphrag.GraphNode{
				Type: "Finding",
				Properties: map[string]any{
					"severity": "high",
				},
			},
			shouldFail: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Content is required")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockGraphRAGStore{
				IsHealthy:     true,
				HealthMessage: "healthy",
			}
			bridge := NewGraphRAGQueryBridge(mockStore, nil)

			nodeID, err := bridge.StoreSemantic(context.Background(), tt.node, "test-mission", "test-agent")

			if tt.shouldFail {
				assert.Error(t, err)
				if tt.checkError != nil {
					tt.checkError(t, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, nodeID)
				assert.True(t, mockStore.StoreCalled, "Store should be called for semantic storage")
			}
		})
	}
}

// TestStoreStructured tests the StoreStructured method
func TestStoreStructured(t *testing.T) {
	tests := []struct {
		name       string
		node       sdkgraphrag.GraphNode
		shouldFail bool
	}{
		{
			name: "successful structured store without content",
			node: sdkgraphrag.GraphNode{
				Type: "Host",
				Properties: map[string]any{
					"ip_address": "192.168.1.1",
					"hostname":   "test-host",
				},
			},
			shouldFail: false,
		},
		{
			name: "successful structured store with content (ignored)",
			node: sdkgraphrag.GraphNode{
				Type:    "Port",
				Content: "This content is ignored for structured storage",
				Properties: map[string]any{
					"port_number": 443,
					"protocol":    "tcp",
				},
			},
			shouldFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockGraphRAGStore{
				IsHealthy:     true,
				HealthMessage: "healthy",
			}
			bridge := NewGraphRAGQueryBridge(mockStore, nil)

			nodeID, err := bridge.StoreStructured(context.Background(), tt.node, "test-mission", "test-agent")

			if tt.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, nodeID)
				assert.True(t, mockStore.StoreWithoutEmbeddingCalled, "StoreWithoutEmbedding should be called")
			}
		})
	}
}

// TestQuerySemantic tests the QuerySemantic method
func TestQuerySemantic(t *testing.T) {
	tests := []struct {
		name       string
		query      sdkgraphrag.Query
		shouldFail bool
		checkError func(t *testing.T, err error)
		checkQuery func(t *testing.T, query *graphrag.GraphRAGQuery)
	}{
		{
			name: "successful semantic query with text",
			query: sdkgraphrag.Query{
				Text:         "test semantic query",
				TopK:         5,
				MaxHops:      2,
				VectorWeight: 0.8,
				GraphWeight:  0.2,
			},
			shouldFail: false,
			checkQuery: func(t *testing.T, query *graphrag.GraphRAGQuery) {
				assert.True(t, query.ForceSemanticOnly, "ForceSemanticOnly should be set")
				assert.Equal(t, "test semantic query", query.Text)
			},
		},
		{
			name: "fails without text or embedding",
			query: sdkgraphrag.Query{
				TopK:    5,
				MaxHops: 2,
			},
			shouldFail: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Text or Embedding is required")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockGraphRAGStore{
				IsHealthy:     true,
				HealthMessage: "healthy",
			}
			bridge := NewGraphRAGQueryBridge(mockStore, nil)

			results, err := bridge.QuerySemantic(context.Background(), tt.query)

			if tt.shouldFail {
				assert.Error(t, err)
				if tt.checkError != nil {
					tt.checkError(t, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, results)
				assert.True(t, mockStore.QueryCalled, "Query should be called")
				if tt.checkQuery != nil && mockStore.LastQuery != nil {
					tt.checkQuery(t, mockStore.LastQuery)
				}
			}
		})
	}
}

// TestQueryStructured tests the QueryStructured method
func TestQueryStructured(t *testing.T) {
	tests := []struct {
		name       string
		query      sdkgraphrag.Query
		shouldFail bool
		checkError func(t *testing.T, err error)
		checkQuery func(t *testing.T, query *graphrag.GraphRAGQuery)
	}{
		{
			name: "successful structured query with node types",
			query: sdkgraphrag.Query{
				NodeTypes:    []string{"Host", "Port"},
				TopK:         10,
				VectorWeight: 0.5,
				GraphWeight:  0.5,
			},
			shouldFail: false,
			checkQuery: func(t *testing.T, query *graphrag.GraphRAGQuery) {
				assert.True(t, query.ForceStructuredOnly, "ForceStructuredOnly should be set")
				assert.Len(t, query.NodeTypes, 2)
			},
		},
		{
			name: "fails without node types",
			query: sdkgraphrag.Query{
				TopK: 10,
			},
			shouldFail: true,
			checkError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "NodeTypes is required")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockGraphRAGStore{
				IsHealthy:     true,
				HealthMessage: "healthy",
			}
			bridge := NewGraphRAGQueryBridge(mockStore, nil)

			results, err := bridge.QueryStructured(context.Background(), tt.query)

			if tt.shouldFail {
				assert.Error(t, err)
				if tt.checkError != nil {
					tt.checkError(t, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, results)
				assert.True(t, mockStore.QueryCalled, "Query should be called")
				if tt.checkQuery != nil && mockStore.LastQuery != nil {
					tt.checkQuery(t, mockStore.LastQuery)
				}
			}
		})
	}
}
