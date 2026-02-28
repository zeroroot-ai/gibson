package orchestrator

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MockApprovalManager is a mock implementation of ApprovalManager for testing
type MockApprovalManager struct {
	mock.Mock
}

func (m *MockApprovalManager) CreateRequest(ctx context.Context, req ApprovalRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

func (m *MockApprovalManager) WaitForApproval(ctx context.Context, approvalID string, timeout time.Duration) (ApprovalResponse, error) {
	args := m.Called(ctx, approvalID, timeout)
	return args.Get(0).(ApprovalResponse), args.Error(1)
}

func (m *MockApprovalManager) RespondToApproval(ctx context.Context, approvalID string, response ApprovalResponse) error {
	args := m.Called(ctx, approvalID, response)
	return args.Error(0)
}

func (m *MockApprovalManager) GetPendingApprovals(ctx context.Context, missionID string) ([]ApprovalRequest, error) {
	args := m.Called(ctx, missionID)
	return args.Get(0).([]ApprovalRequest), args.Error(1)
}

// MockEscalationManager is a mock implementation of EscalationManager for testing
type MockEscalationManager struct {
	mock.Mock
}

func (m *MockEscalationManager) CreateEscalation(ctx context.Context, esc Escalation) (string, error) {
	args := m.Called(ctx, esc)
	return args.String(0), args.Error(1)
}

func (m *MockEscalationManager) WaitForAcknowledgment(ctx context.Context, escalationID string, timeout time.Duration) error {
	args := m.Called(ctx, escalationID, timeout)
	return args.Error(0)
}

func (m *MockEscalationManager) AcknowledgeEscalation(ctx context.Context, escalationID string, acknowledgedBy string) error {
	args := m.Called(ctx, escalationID, acknowledgedBy)
	return args.Error(0)
}

func (m *MockEscalationManager) GetEscalations(ctx context.Context, missionID string) ([]Escalation, error) {
	args := m.Called(ctx, missionID)
	return args.Get(0).([]Escalation), args.Error(1)
}

func TestRequestApproval_ManagerNotConfigured(t *testing.T) {
	// Create actor without approval manager
	actor := &Actor{
		approvalManager: nil,
	}

	decision := &Decision{
		Action:          ActionRequestApproval,
		TargetNodeID:    "node-1",
		ApprovalContext: "Test approval",
	}

	missionID := types.NewID()
	_, err := actor.requestApproval(context.Background(), decision, missionID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "approval manager not configured")
}

func TestEscalate_ManagerNotConfigured(t *testing.T) {
	// Create actor without escalation manager
	actor := &Actor{
		escalationManager: nil,
	}

	decision := &Decision{
		Action:            ActionEscalate,
		TargetNodeID:      "node-1",
		EscalationLevel:   "human",
		EscalationUrgency: "critical",
		EscalationContext: "Test escalation",
	}

	missionID := types.NewID()
	_, err := actor.escalate(context.Background(), decision, missionID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "escalation manager not configured")
}

func TestEscalate_NonCritical(t *testing.T) {
	mockEscalation := new(MockEscalationManager)

	escalationID := types.NewID().String()
	mockEscalation.On("CreateEscalation", mock.Anything, mock.MatchedBy(func(esc Escalation) bool {
		return esc.Level == "human" && esc.Urgency == "normal"
	})).Return(escalationID, nil)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	actor := &Actor{
		escalationManager: mockEscalation,
		logger:            logger,
	}

	decision := &Decision{
		Action:            ActionEscalate,
		TargetNodeID:      "node-1",
		EscalationLevel:   "human",
		EscalationUrgency: "normal",
		EscalationContext: "Non-critical test",
	}

	missionID := types.NewID()
	result, err := actor.escalate(context.Background(), decision, missionID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsTerminal)
	assert.Equal(t, ActionEscalate, result.Action)
	assert.Equal(t, escalationID, result.Metadata["escalation_id"])

	// WaitForAcknowledgment should not be called for non-critical
	mockEscalation.AssertNotCalled(t, "WaitForAcknowledgment")
	mockEscalation.AssertExpectations(t)
}

// MockCheckpointManager is a mock implementation of CheckpointManager for testing
type MockCheckpointManager struct {
	mock.Mock
}

func (m *MockCheckpointManager) CreateCheckpoint(ctx context.Context, missionID string, label string) (string, error) {
	args := m.Called(ctx, missionID, label)
	return args.String(0), args.Error(1)
}

func (m *MockCheckpointManager) RestoreCheckpoint(ctx context.Context, checkpointID string) error {
	args := m.Called(ctx, checkpointID)
	return args.Error(0)
}

func (m *MockCheckpointManager) GetCheckpoints(ctx context.Context, missionID string) ([]Checkpoint, error) {
	args := m.Called(ctx, missionID)
	return args.Get(0).([]Checkpoint), args.Error(1)
}

func (m *MockCheckpointManager) CreateImplicitCheckpoint(ctx context.Context, missionID string, nodeID string) error {
	args := m.Called(ctx, missionID, nodeID)
	return args.Error(0)
}

// MockReflectionEngine is a mock implementation of ReflectionEngine for testing
type MockReflectionEngine struct {
	mock.Mock
}

func (m *MockReflectionEngine) Reflect(ctx context.Context, scope ReflectionScope, prompt string, state *ObservationState) (*ReflectionResult, error) {
	args := m.Called(ctx, scope, prompt, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ReflectionResult), args.Error(1)
}

func (m *MockReflectionEngine) GetRecentInsights(ctx context.Context, missionID string, limit int) ([]ReflectionInsight, error) {
	args := m.Called(ctx, missionID, limit)
	return args.Get(0).([]ReflectionInsight), args.Error(1)
}

// MockMemoryRecaller is a mock implementation of MemoryRecaller for testing
type MockMemoryRecaller struct {
	mock.Mock
}

func (m *MockMemoryRecaller) Recall(ctx context.Context, query RecallQuery) (*RecallResult, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*RecallResult), args.Error(1)
}

// Test requestApproval action handler

// Note: More comprehensive integration tests for requestApproval would require
// mocking the graph client and workflow nodes. The existing approval_test.go
// covers the ApprovalManager functionality, and decision validation tests
// ensure the action is properly defined.

// Test abort action handler
// Note: abort() requires graph client to update mission status in Neo4j.
// Full integration testing requires mock graph client setup.

// Test escalate action handler with critical urgency

func TestEscalate_HumanCritical(t *testing.T) {
	mockEscalation := new(MockEscalationManager)

	escalationID := types.NewID().String()
	mockEscalation.On("CreateEscalation", mock.Anything, mock.MatchedBy(func(esc Escalation) bool {
		return esc.Level == "human" && esc.Urgency == "critical"
	})).Return(escalationID, nil)

	mockEscalation.On("WaitForAcknowledgment", mock.Anything, escalationID, mock.Anything).Return(nil)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	actor := &Actor{
		escalationManager: mockEscalation,
		logger:            logger,
	}

	decision := &Decision{
		Action:            ActionEscalate,
		TargetNodeID:      "node-1",
		EscalationLevel:   "human",
		EscalationUrgency: "critical",
		EscalationContext: "Critical issue found",
	}

	missionID := types.NewID()
	result, err := actor.escalate(context.Background(), decision, missionID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsTerminal)
	assert.Equal(t, escalationID, result.Metadata["escalation_id"])

	// WaitForAcknowledgment should be called for critical+human
	mockEscalation.AssertExpectations(t)
}

// Test rollback action handler

func TestRollback_ManagerNotConfigured(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	actor := &Actor{
		checkpointManager: nil,
		logger:            logger,
	}

	decision := &Decision{
		Action:       ActionRollback,
		CheckpointID: types.NewID().String(),
	}

	missionID := types.NewID()
	_, err := actor.rollback(context.Background(), decision, missionID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checkpoint manager not configured")
}

// Note: Full rollback testing with RestoreCheckpoint requires graph client mocking.

// Test reflect action handler

func TestReflect_ManagerNotConfigured(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	actor := &Actor{
		reflectionEngine: nil,
		logger:           logger,
	}

	decision := &Decision{
		Action:          ActionReflect,
		ReflectionScope: "mission",
	}

	missionID := types.NewID()
	_, err := actor.reflect(context.Background(), decision, missionID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reflection engine not configured")
}

// Note: Full reflect testing requires ObservationState construction and
// reflection result storage in Neo4j which needs graph client mocking.

// Test recall action handler

func TestRecall_ManagerNotConfigured(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	actor := &Actor{
		memoryRecaller: nil,
		logger:         logger,
	}

	decision := &Decision{
		Action:           ActionRecall,
		RecallQuery:      "test query",
		RecallMemoryTier: "mission",
	}

	missionID := types.NewID()
	_, err := actor.recall(context.Background(), decision, missionID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory recaller not configured")
}

// Note: Full recall testing requires proper RecallQuery construction and
// result handling which is better tested in recall_test.go
