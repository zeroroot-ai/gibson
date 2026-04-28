package component

// service_harness_parity_test.go tests the handler methods added by the
// platform-harness-parity spec: GraphRAG, findings, missions, delegation,
// context, LLM, and extended memory RPCs on ComponentServiceServer.
//
// Each test constructs a minimal server via NewComponentServiceServer with stub
// registry/queue, then wires exactly the mock needed for the handler under
// test via the corresponding With*() method. Auth context is set with
// auth.ContextWithTenantString. Tests verify happy-path delegation, nil-dependency
// returns Unimplemented, and missing tenant returns Unauthenticated.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/memory"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// noopWorkQueue is a minimal WorkQueue that satisfies the interface.
type noopWorkQueue struct{}

func (q *noopWorkQueue) Enqueue(_ context.Context, _, _, _ string, _ WorkItem) (string, error) {
	return "", nil
}
func (q *noopWorkQueue) Claim(_ context.Context, _, _, _, _ string, _ time.Duration) (*WorkItem, error) {
	return nil, nil
}
func (q *noopWorkQueue) DeliverResult(_ context.Context, _ string, _ WorkResult) error { return nil }
func (q *noopWorkQueue) WaitForResult(_ context.Context, _ string, _ time.Duration) (*WorkResult, error) {
	return nil, nil
}
func (q *noopWorkQueue) Acknowledge(_ context.Context, _, _, _, _ string) error { return nil }
func (q *noopWorkQueue) ReclaimAbandoned(_ context.Context, _, _, _ string, _ time.Duration) error {
	return nil
}

// noopRegistry satisfies ComponentRegistry without touching Redis.
type noopRegistry struct{}

func (r *noopRegistry) Register(_ context.Context, _, _, _ string, _ ComponentInfo) (string, error) {
	return "inst-noop", nil
}
func (r *noopRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *noopRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *noopRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}
func (r *noopRegistry) DiscoverAll(_ context.Context, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}
func (r *noopRegistry) ListTenantComponents(_ context.Context, _ string) ([]ComponentInfo, error) {
	return nil, nil
}
func (r *noopRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}
func (r *noopRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

// testLogger returns a slog.Logger that discards output below error level.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// newParityServer builds a ComponentServiceServer with noop registry/queue.
func newParityServer() *ComponentServiceServer {
	return NewComponentServiceServer(
		&noopRegistry{},
		&noopWorkQueue{},
		testLogger(),
		nil, nil, nil, nil, nil,
	)
}

// tenantCtx returns a background context stamped with "test-tenant".
func tenantCtx() context.Context {
	return auth.ContextWithTenantString(context.Background(), "test-tenant")
}

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockGraphRAGQuerier implements GraphRAGQuerier.
type mockGraphRAGQuerier struct {
	queryResults []*graphragpb.QueryResult
	queryErr     error
	storeID      string
	storeErr     error
}

func (m *mockGraphRAGQuerier) QueryNodes(_ context.Context, _ string, _ *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	return m.queryResults, m.queryErr
}
func (m *mockGraphRAGQuerier) StoreNode(_ context.Context, _ string, _ *graphragpb.GraphNode) (string, error) {
	return m.storeID, m.storeErr
}
func (m *mockGraphRAGQuerier) FindSimilarAttacks(_ context.Context, _, _ string, _ int) ([]byte, error) {
	return nil, nil
}
func (m *mockGraphRAGQuerier) GetAttackChains(_ context.Context, _, _ string, _ int) ([]byte, error) {
	return nil, nil
}
func (m *mockGraphRAGQuerier) FindSimilarFindings(_ context.Context, _, _ string, _ int) ([]byte, error) {
	return nil, nil
}
func (m *mockGraphRAGQuerier) GetRelatedFindings(_ context.Context, _, _ string) ([]byte, error) {
	return nil, nil
}

// mockFindingQuerier implements FindingQuerier.
type mockFindingQuerier struct {
	findingsJSON []byte
	err          error
}

func (m *mockFindingQuerier) GetFindings(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return m.findingsJSON, m.err
}
func (m *mockFindingQuerier) GetRunFindings(_ context.Context, _, _, _ string, _ []byte) ([]byte, error) {
	return m.findingsJSON, m.err
}

// mockMissionManager implements MissionManager.
type mockMissionManager struct {
	missionJSON []byte
	err         error
}

func (m *mockMissionManager) CreateMission(_ context.Context, _ string, _ []byte, _ string, _ []byte) ([]byte, error) {
	return m.missionJSON, m.err
}
func (m *mockMissionManager) RunMission(_ context.Context, _, _ string, _ []byte) error {
	return m.err
}
func (m *mockMissionManager) GetMissionStatus(_ context.Context, _, _ string) ([]byte, error) {
	return m.missionJSON, m.err
}
func (m *mockMissionManager) WaitForMission(_ context.Context, _, _ string, _ int64) ([]byte, error) {
	return m.missionJSON, m.err
}
func (m *mockMissionManager) ListMissions(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return m.missionJSON, m.err
}
func (m *mockMissionManager) CancelMission(_ context.Context, _, _ string) error {
	return m.err
}
func (m *mockMissionManager) GetMissionResults(_ context.Context, _, _ string) ([]byte, error) {
	return m.missionJSON, m.err
}
func (m *mockMissionManager) GetMissionRunHistory(_ context.Context, _, _ string) ([]byte, error) {
	return m.missionJSON, m.err
}

// mockAgentDelegator implements AgentDelegator.
type mockAgentDelegator struct {
	resultJSON []byte
	err        error
}

func (m *mockAgentDelegator) DelegateToAgent(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return m.resultJSON, m.err
}

// mockComponentLister implements ComponentLister.
type mockComponentLister struct {
	tools  []ToolDescriptor
	agents []AgentDescriptor
	err    error
}

func (m *mockComponentLister) ListTools(_ context.Context, _ string) ([]ToolDescriptor, error) {
	return m.tools, m.err
}
func (m *mockComponentLister) ListAgents(_ context.Context, _ string) ([]AgentDescriptor, error) {
	return m.agents, m.err
}

// mockCredentialStore implements CredentialStore.
type mockCredentialStore struct {
	credJSON []byte
	err      error
}

func (m *mockCredentialStore) GetCredential(_ context.Context, _, _ string) ([]byte, error) {
	return m.credJSON, m.err
}

// mockWorkingMemory implements memory.WorkingMemory.
type mockWorkingMemory struct {
	deleted []string
}

func (m *mockWorkingMemory) Get(_ string) (interface{}, bool)  { return nil, false }
func (m *mockWorkingMemory) Set(_ string, _ interface{}) error { return nil }
func (m *mockWorkingMemory) Delete(key string) bool            { m.deleted = append(m.deleted, key); return true }
func (m *mockWorkingMemory) Clear()                            {}
func (m *mockWorkingMemory) List() []string                    { return nil }
func (m *mockWorkingMemory) TokenCount() int                   { return 0 }
func (m *mockWorkingMemory) MaxTokens() int                    { return 0 }

// mockMemoryStore wraps mockWorkingMemory to satisfy memory.MemoryStore.
type mockMemoryStore struct {
	working *mockWorkingMemory
}

func (s *mockMemoryStore) Working() memory.WorkingMemory   { return s.working }
func (s *mockMemoryStore) Mission() memory.MissionMemory   { return nil }
func (s *mockMemoryStore) LongTerm() memory.LongTermMemory { return nil }

// ---------------------------------------------------------------------------
// 1. QueryNodes — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_QueryNodes_HappyPath(t *testing.T) {
	want := []*graphragpb.QueryResult{{Score: 0.9}}
	mock := &mockGraphRAGQuerier{queryResults: want}
	svc := newParityServer().WithGraphRAG(mock)

	resp, err := svc.QueryNodes(tenantCtx(), &componentpb.QueryNodesRequest{
		Query: &graphragpb.GraphQuery{},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Results, 1)
	assert.InDelta(t, 0.9, resp.Results[0].Score, 0.001)
}

// ---------------------------------------------------------------------------
// 2. QueryNodes — nil graphrag returns Unimplemented
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_QueryNodes_NilGraphRAG(t *testing.T) {
	svc := newParityServer() // graphrag not wired

	_, err := svc.QueryNodes(tenantCtx(), &componentpb.QueryNodesRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ---------------------------------------------------------------------------
// 3. StoreNode — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_StoreNode_HappyPath(t *testing.T) {
	mock := &mockGraphRAGQuerier{storeID: "node-abc-123"}
	svc := newParityServer().WithGraphRAG(mock)

	resp, err := svc.StoreNode(tenantCtx(), &componentpb.StoreNodeRequest{
		Node: &graphragpb.GraphNode{},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "node-abc-123", resp.NodeId)
}

// ---------------------------------------------------------------------------
// 4. GetFindings — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_GetFindings_HappyPath(t *testing.T) {
	payload := []byte(`[{"id":"f1","title":"SQL Injection"}]`)
	mock := &mockFindingQuerier{findingsJSON: payload}
	svc := newParityServer().WithFindingQuerier(mock)

	resp, err := svc.GetFindings(tenantCtx(), &componentpb.GetFindingsRequest{})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, payload, resp.FindingsJson)
}

// ---------------------------------------------------------------------------
// 5. GetFindings — nil findingQuerier returns Unimplemented
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_GetFindings_NilQuerier(t *testing.T) {
	svc := newParityServer()

	_, err := svc.GetFindings(tenantCtx(), &componentpb.GetFindingsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ---------------------------------------------------------------------------
// 6. CreateMission — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_CreateMission_HappyPath(t *testing.T) {
	payload := []byte(`{"id":"mission-42"}`)
	mock := &mockMissionManager{missionJSON: payload}
	svc := newParityServer().WithMissionManager(mock)

	resp, err := svc.CreateMission(tenantCtx(), &componentpb.CreateMissionRequest{
		MissionDefinitionJson: []byte(`{}`),
		TargetId:              "target-1",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, payload, resp.MissionJson)
}

// ---------------------------------------------------------------------------
// 7. CreateMission — nil missionMgr returns Unimplemented
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_CreateMission_NilManager(t *testing.T) {
	svc := newParityServer()

	_, err := svc.CreateMission(tenantCtx(), &componentpb.CreateMissionRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ---------------------------------------------------------------------------
// 8. DelegateToAgent — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_DelegateToAgent_HappyPath(t *testing.T) {
	resultPayload := []byte(`{"status":"complete","output":"found 3 hosts"}`)
	mock := &mockAgentDelegator{resultJSON: resultPayload}
	svc := newParityServer().WithAgentDelegator(mock)

	resp, err := svc.DelegateToAgent(tenantCtx(), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{"target":"10.0.0.1"}`),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, resultPayload, resp.ResultJson)
}

// ---------------------------------------------------------------------------
// 9. ListTools — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_ListTools_HappyPath(t *testing.T) {
	tools := []ToolDescriptor{
		{Name: "nmap", Version: "7.94", Description: "Port scanner", Tags: []string{"discovery"}},
		{Name: "nuclei", Version: "3.1.0", Description: "Vulnerability scanner"},
	}
	mock := &mockComponentLister{tools: tools}
	svc := newParityServer().WithComponentLister(mock)

	resp, err := svc.ListTools(tenantCtx(), &componentpb.ListToolsRequest{})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Tools, 2)
	assert.Equal(t, "nmap", resp.Tools[0].Name)
	assert.Equal(t, "nuclei", resp.Tools[1].Name)
}

// ---------------------------------------------------------------------------
// 10. GetCredential — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_GetCredential_HappyPath(t *testing.T) {
	credPayload := []byte(`{"username":"admin","password":"s3cr3t"}`)
	mock := &mockCredentialStore{credJSON: credPayload}
	svc := newParityServer().WithCredentialStore(mock)

	resp, err := svc.GetCredential(tenantCtx(), &componentpb.GetCredentialRequest{
		Name: "db-creds",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, credPayload, resp.CredentialJson)
}

// ---------------------------------------------------------------------------
// 11. GetCredential — nil credentialStore returns Unimplemented
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_GetCredential_NilStore(t *testing.T) {
	svc := newParityServer()

	_, err := svc.GetCredential(tenantCtx(), &componentpb.GetCredentialRequest{Name: "any"})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ---------------------------------------------------------------------------
// 12. MemoryDelete (working tier) — happy path
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_MemoryDelete_WorkingTier_HappyPath(t *testing.T) {
	wm := &mockWorkingMemory{}
	store := &mockMemoryStore{working: wm}
	svc := NewComponentServiceServer(
		&noopRegistry{},
		&noopWorkQueue{},
		testLogger(),
		nil, store, nil, nil, nil,
	)

	resp, err := svc.MemoryDelete(tenantCtx(), &componentpb.MemoryDeleteRequest{
		Tier: memTierWorking,
		Key:  "scratch-key",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, wm.deleted, "scratch-key")
}

// ---------------------------------------------------------------------------
// 13. MemoryDelete — nil memory returns Unimplemented for working tier
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_MemoryDelete_NilMemory(t *testing.T) {
	svc := newParityServer() // memory not wired

	_, err := svc.MemoryDelete(tenantCtx(), &componentpb.MemoryDeleteRequest{
		Tier: memTierWorking,
		Key:  "k",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ---------------------------------------------------------------------------
// 14. Unauthenticated — QueryNodes without tenant returns Unauthenticated
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_Unauthenticated_QueryNodes(t *testing.T) {
	mock := &mockGraphRAGQuerier{}
	svc := newParityServer().WithGraphRAG(mock)

	// context without tenant
	_, err := svc.QueryNodes(context.Background(), &componentpb.QueryNodesRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// 15. Unauthenticated — GetFindings without tenant returns Unauthenticated
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_Unauthenticated_GetFindings(t *testing.T) {
	mock := &mockFindingQuerier{findingsJSON: []byte(`[]`)}
	svc := newParityServer().WithFindingQuerier(mock)

	_, err := svc.GetFindings(context.Background(), &componentpb.GetFindingsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// 16. DelegateToAgent — upstream error surfaces as Internal
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_DelegateToAgent_UpstreamError(t *testing.T) {
	mock := &mockAgentDelegator{err: errors.New("agent unreachable")}
	svc := newParityServer().WithAgentDelegator(mock)

	_, err := svc.DelegateToAgent(tenantCtx(), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// 17. ListTools — nil componentLister returns Unimplemented
// ---------------------------------------------------------------------------

func TestServiceHarnessParity_ListTools_NilLister(t *testing.T) {
	svc := newParityServer()

	_, err := svc.ListTools(tenantCtx(), &componentpb.ListToolsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
