package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockGraphClient is a minimal mock for testing approval manager
type mockApprovalGraphClient struct {
	graph.GraphClient
	queryFunc func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error)
}

func (m *mockApprovalGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, cypher, params)
	}
	return graph.QueryResult{Records: []map[string]any{}}, nil
}

// mockEventBus captures published events for testing
type mockApprovalEventBus struct {
	events []events.Event
}

func (m *mockApprovalEventBus) Publish(event events.Event) {
	m.events = append(m.events, event)
}

func TestNewNeo4jApprovalManager(t *testing.T) {
	client := &mockApprovalGraphClient{}
	bus := &mockApprovalEventBus{}

	manager := NewNeo4jApprovalManager(client, bus)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.graphClient)
	assert.NotNil(t, manager.eventBus)
	assert.NotNil(t, manager.waiters)
	assert.Equal(t, 0, len(manager.waiters))
}

func TestCreateRequest_Success(t *testing.T) {
	missionID := types.NewID().String()
	nodeID := types.NewID().String()

	client := &mockApprovalGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			// Verify parameters
			assert.Equal(t, missionID, params["mission_id"])
			assert.Equal(t, nodeID, params["node_id"])
			assert.Equal(t, "Please approve this action", params["context"])
			assert.Equal(t, "reject", params["timeout_action"])

			return graph.QueryResult{
				Records: []map[string]any{
					{"id": params["id"]},
				},
			}, nil
		},
	}

	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	req := ApprovalRequest{
		MissionID:     missionID,
		NodeID:        nodeID,
		Context:       "Please approve this action",
		Timeout:       5 * time.Minute,
		TimeoutAction: "reject",
	}

	approvalID, err := manager.CreateRequest(context.Background(), req)

	require.NoError(t, err)
	assert.NotEmpty(t, approvalID)

	// Verify event was published
	require.Equal(t, 1, len(bus.events))
	assert.Equal(t, events.EventApprovalRequested, bus.events[0].Type)
}

func TestCreateRequest_ValidationErrors(t *testing.T) {
	client := &mockApprovalGraphClient{}
	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	tests := []struct {
		name    string
		request ApprovalRequest
		wantErr string
	}{
		{
			name: "missing mission ID",
			request: ApprovalRequest{
				NodeID:        types.NewID().String(),
				Context:       "test",
				TimeoutAction: "reject",
			},
			wantErr: "mission ID cannot be empty",
		},
		{
			name: "missing node ID",
			request: ApprovalRequest{
				MissionID:     types.NewID().String(),
				Context:       "test",
				TimeoutAction: "reject",
			},
			wantErr: "node ID cannot be empty",
		},
		{
			name: "missing context",
			request: ApprovalRequest{
				MissionID:     types.NewID().String(),
				NodeID:        types.NewID().String(),
				TimeoutAction: "reject",
			},
			wantErr: "context cannot be empty",
		},
		{
			name: "invalid timeout action",
			request: ApprovalRequest{
				MissionID:     types.NewID().String(),
				NodeID:        types.NewID().String(),
				Context:       "test",
				TimeoutAction: "invalid",
			},
			wantErr: "timeout action must be 'reject' or 'skip'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.CreateRequest(context.Background(), tt.request)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRespondToApproval_Success(t *testing.T) {
	approvalID := types.NewID().String()
	missionID := types.NewID().String()
	nodeID := types.NewID().String()

	client := &mockApprovalGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			// Check if this is the storeResponse query (has SET clause)
			if strings.Contains(cypher, "SET") {
				return graph.QueryResult{
					Records: []map[string]any{
						{"id": approvalID},
					},
				}, nil
			}
			// Otherwise it's the getApproval query (RETURN properties)
			return graph.QueryResult{
				Records: []map[string]any{
					{
						"a": map[string]any{
							"id":                  approvalID,
							"mission_id":          missionID,
							"node_id":             nodeID,
							"context":             "test",
							"timeout_action":      "reject",
							"requested_at":        time.Now(),
							"timeout_duration_ms": int64(300000),
						},
					},
				},
			}, nil
		},
	}

	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	response := ApprovalResponse{
		Approved:    true,
		RespondedBy: "human",
		Comment:     "Looks good",
	}

	err := manager.RespondToApproval(context.Background(), approvalID, response)

	require.NoError(t, err)

	// Verify event was published
	require.Equal(t, 1, len(bus.events))
	assert.Equal(t, events.EventApprovalGranted, bus.events[0].Type)
}

func TestRespondToApproval_Rejection(t *testing.T) {
	approvalID := types.NewID().String()
	missionID := types.NewID().String()
	nodeID := types.NewID().String()

	client := &mockApprovalGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			// Check if this is the storeResponse query (has SET clause)
			if strings.Contains(cypher, "SET") {
				return graph.QueryResult{
					Records: []map[string]any{
						{"id": approvalID},
					},
				}, nil
			}
			// Otherwise it's the getApproval query (RETURN properties)
			return graph.QueryResult{
				Records: []map[string]any{
					{
						"a": map[string]any{
							"id":                  approvalID,
							"mission_id":          missionID,
							"node_id":             nodeID,
							"context":             "test",
							"timeout_action":      "reject",
							"requested_at":        time.Now(),
							"timeout_duration_ms": int64(300000),
						},
					},
				},
			}, nil
		},
	}

	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	response := ApprovalResponse{
		Approved:    false,
		RespondedBy: "human",
		Comment:     "Too risky",
	}

	err := manager.RespondToApproval(context.Background(), approvalID, response)

	require.NoError(t, err)

	// Verify event was published
	require.Equal(t, 1, len(bus.events))
	assert.Equal(t, events.EventApprovalRejected, bus.events[0].Type)
}

func TestWaitForApproval_ImmediateResponse(t *testing.T) {
	approvalID := types.NewID().String()
	client := &mockApprovalGraphClient{}
	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	// Simulate immediate approval in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		response := ApprovalResponse{
			Approved:    true,
			RespondedBy: "human",
			Comment:     "Approved quickly",
		}
		// Trigger the waiter directly
		manager.mu.RLock()
		ch, exists := manager.waiters[approvalID]
		manager.mu.RUnlock()
		if exists {
			ch <- response
		}
	}()

	// Start waiting
	response, err := manager.WaitForApproval(context.Background(), approvalID, 5*time.Second)

	require.NoError(t, err)
	assert.True(t, response.Approved)
	assert.Equal(t, "human", response.RespondedBy)
	assert.Equal(t, "Approved quickly", response.Comment)
}

func TestWaitForApproval_Timeout(t *testing.T) {
	approvalID := types.NewID().String()
	missionID := types.NewID().String()

	client := &mockApprovalGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			// Get approval for timeout handling
			if cypher != "" {
				return graph.QueryResult{
					Records: []map[string]any{
						{
							"a": map[string]any{
								"id":                  approvalID,
								"mission_id":          missionID,
								"node_id":             types.NewID().String(),
								"context":             "test",
								"timeout_action":      "skip",
								"requested_at":        time.Now(),
								"timeout_duration_ms": int64(100),
							},
						},
					},
				}, nil
			}
			return graph.QueryResult{Records: []map[string]any{{"id": approvalID}}}, nil
		},
	}

	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	// Wait with a very short timeout
	response, err := manager.WaitForApproval(context.Background(), approvalID, 100*time.Millisecond)

	require.NoError(t, err)
	assert.True(t, response.Approved) // "skip" action means approved
	assert.Equal(t, "timeout", response.RespondedBy)

	// Verify timeout event was published
	require.Equal(t, 1, len(bus.events))
	assert.Equal(t, events.EventApprovalTimeout, bus.events[0].Type)
}

func TestWaitForApproval_ContextCancellation(t *testing.T) {
	approvalID := types.NewID().String()
	client := &mockApprovalGraphClient{}
	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := manager.WaitForApproval(ctx, approvalID, 5*time.Second)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestGetPendingApprovals_Success(t *testing.T) {
	missionID := types.NewID().String()
	approval1ID := types.NewID().String()
	approval2ID := types.NewID().String()

	client := &mockApprovalGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			assert.Equal(t, missionID, params["mission_id"])

			return graph.QueryResult{
				Records: []map[string]any{
					{
						"a": map[string]any{
							"id":                  approval1ID,
							"mission_id":          missionID,
							"node_id":             types.NewID().String(),
							"context":             "First approval",
							"timeout_action":      "reject",
							"requested_at":        time.Now(),
							"timeout_duration_ms": int64(300000),
						},
					},
					{
						"a": map[string]any{
							"id":                  approval2ID,
							"mission_id":          missionID,
							"node_id":             types.NewID().String(),
							"context":             "Second approval",
							"timeout_action":      "skip",
							"requested_at":        time.Now(),
							"timeout_duration_ms": int64(600000),
						},
					},
				},
			}, nil
		},
	}

	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	approvals, err := manager.GetPendingApprovals(context.Background(), missionID)

	require.NoError(t, err)
	assert.Equal(t, 2, len(approvals))
	assert.Equal(t, approval1ID, approvals[0].ID)
	assert.Equal(t, approval2ID, approvals[1].ID)
	assert.Equal(t, "First approval", approvals[0].Context)
	assert.Equal(t, "Second approval", approvals[1].Context)
}

func TestGetPendingApprovals_EmptyMissionID(t *testing.T) {
	client := &mockApprovalGraphClient{}
	bus := &mockApprovalEventBus{}
	manager := NewNeo4jApprovalManager(client, bus)

	_, err := manager.GetPendingApprovals(context.Background(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission ID cannot be empty")
}

func TestRecordToApprovalRequest_Success(t *testing.T) {
	approvalID := types.NewID().String()
	missionID := types.NewID().String()
	nodeID := types.NewID().String()
	now := time.Now()

	data := map[string]any{
		"id":                  approvalID,
		"mission_id":          missionID,
		"node_id":             nodeID,
		"context":             "Test context",
		"timeout_action":      "reject",
		"requested_at":        now,
		"timeout_duration_ms": int64(300000),
	}

	approval, err := recordToApprovalRequest(data)

	require.NoError(t, err)
	assert.Equal(t, approvalID, approval.ID)
	assert.Equal(t, missionID, approval.MissionID)
	assert.Equal(t, nodeID, approval.NodeID)
	assert.Equal(t, "Test context", approval.Context)
	assert.Equal(t, "reject", approval.TimeoutAction)
	assert.Equal(t, 5*time.Minute, approval.Timeout)
}

func TestRecordToApprovalRequest_InvalidData(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		wantErr string
	}{
		{
			name:    "not a map",
			data:    "invalid",
			wantErr: "invalid approval request data type",
		},
		{
			name: "missing ID",
			data: map[string]any{
				"mission_id":     types.NewID().String(),
				"node_id":        types.NewID().String(),
				"context":        "test",
				"timeout_action": "reject",
			},
			wantErr: "missing or invalid approval ID",
		},
		{
			name: "missing context",
			data: map[string]any{
				"id":             types.NewID().String(),
				"mission_id":     types.NewID().String(),
				"node_id":        types.NewID().String(),
				"timeout_action": "reject",
			},
			wantErr: "missing or invalid context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := recordToApprovalRequest(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestToInt64_Conversions(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int64
		ok    bool
	}{
		{"int64", int64(42), 42, true},
		{"float64", float64(42.0), 42, true},
		{"int", int(42), 42, true},
		{"int32", int32(42), 42, true},
		{"string", "42", 0, false},
		{"nil", nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toInt64(tt.value)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestApprovalRequestJSON(t *testing.T) {
	req := ApprovalRequest{
		ID:            types.NewID().String(),
		MissionID:     types.NewID().String(),
		NodeID:        types.NewID().String(),
		Context:       "Test approval",
		RequestedAt:   time.Now(),
		Timeout:       5 * time.Minute,
		TimeoutAction: "reject",
	}

	// Test that it can be marshaled
	data, err := req.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), req.ID)
	assert.Contains(t, string(data), req.Context)
}

func TestApprovalResponseJSON(t *testing.T) {
	resp := ApprovalResponse{
		Approved:    true,
		RespondedAt: time.Now(),
		RespondedBy: "human",
		Comment:     "Looks good",
	}

	// Test that it can be marshaled
	data, err := resp.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "human")
	assert.Contains(t, string(data), "Looks good")
}
