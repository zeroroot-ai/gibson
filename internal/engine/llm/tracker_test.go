package llm

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestUsageScope_String(t *testing.T) {
	tests := []struct {
		name     string
		scope    UsageScope
		expected string
	}{
		{
			name: "mission only",
			scope: UsageScope{
				MissionID: types.ID("mission-123"),
			},
			expected: "mission:mission-123",
		},
		{
			name: "mission and agent",
			scope: UsageScope{
				MissionID: types.ID("mission-123"),
				AgentName: "test-agent",
			},
			expected: "mission:mission-123/agent:test-agent",
		},
		{
			name: "mission, agent, and slot",
			scope: UsageScope{
				MissionID: types.ID("mission-123"),
				AgentName: "test-agent",
				SlotName:  "test-slot",
			},
			expected: "mission:mission-123/agent:test-agent/slot:test-slot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestUsageScope_Key(t *testing.T) {
	scope1 := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "agent1",
		SlotName:  "slot1",
	}

	scope2 := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "agent1",
		SlotName:  "slot1",
	}

	scope3 := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "agent1",
		SlotName:  "slot2",
	}

	// Same scopes should have same key
	if scope1.Key() != scope2.Key() {
		t.Errorf("expected same key for identical scopes, got %q and %q", scope1.Key(), scope2.Key())
	}

	// Different scopes should have different keys
	if scope1.Key() == scope3.Key() {
		t.Errorf("expected different keys for different scopes, both got %q", scope1.Key())
	}
}

func TestNewTokenTracker(t *testing.T) {
	// With custom pricing
	pricing := NewPricingConfig()
	tracker := NewTokenTracker(pricing)

	if tracker == nil {
		t.Fatal("NewTokenTracker returned nil")
	}
	if tracker.pricing == nil {
		t.Error("tracker.pricing is nil")
	}
	if tracker.usage == nil {
		t.Error("tracker.usage map is nil")
	}
	if tracker.budgets == nil {
		t.Error("tracker.budgets map is nil")
	}

	// With nil pricing (should use default)
	tracker = NewTokenTracker(nil)
	if tracker == nil {
		t.Fatal("NewTokenTracker with nil pricing returned nil")
	}
	if tracker.pricing == nil {
		t.Error("tracker.pricing is nil when nil was passed")
	}
}

func TestRecordUsage(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
		SlotName:  "test-slot",
	}

	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}

	// Record usage
	err := tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Verify usage was recorded
	record, err := tracker.GetUsage(scope)
	if err != nil {
		t.Fatalf("GetUsage failed: %v", err)
	}

	if record.InputTokens != 1000 {
		t.Errorf("expected InputTokens 1000, got %d", record.InputTokens)
	}
	if record.OutputTokens != 500 {
		t.Errorf("expected OutputTokens 500, got %d", record.OutputTokens)
	}
	if record.CallCount != 1 {
		t.Errorf("expected CallCount 1, got %d", record.CallCount)
	}
	if record.TotalCost <= 0 {
		t.Errorf("expected positive cost, got %f", record.TotalCost)
	}
}

func TestRecordUsage_Aggregation(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
		SlotName:  "test-slot",
	}

	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}

	// Record usage at slot level
	err := tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Verify slot-level record
	slotRecord, err := tracker.GetUsage(scope)
	if err != nil {
		t.Fatalf("GetUsage for slot failed: %v", err)
	}
	if slotRecord.InputTokens != 1000 {
		t.Errorf("expected slot InputTokens 1000, got %d", slotRecord.InputTokens)
	}

	// Verify agent-level aggregation
	agentScope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
	}
	agentRecord, err := tracker.GetUsage(agentScope)
	if err != nil {
		t.Fatalf("GetUsage for agent failed: %v", err)
	}
	if agentRecord.InputTokens != 1000 {
		t.Errorf("expected agent InputTokens 1000, got %d", agentRecord.InputTokens)
	}

	// Verify mission-level aggregation
	missionScope := UsageScope{
		MissionID: types.ID("mission-123"),
	}
	missionRecord, err := tracker.GetUsage(missionScope)
	if err != nil {
		t.Fatalf("GetUsage for mission failed: %v", err)
	}
	if missionRecord.InputTokens != 1000 {
		t.Errorf("expected mission InputTokens 1000, got %d", missionRecord.InputTokens)
	}
}

func TestRecordUsage_MultipleRecords(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
		SlotName:  "test-slot",
	}

	// Record first usage
	usage1 := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}
	err := tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage1)
	if err != nil {
		t.Fatalf("RecordUsage 1 failed: %v", err)
	}

	// Record second usage
	usage2 := TokenUsage{
		InputTokens:  2000,
		OutputTokens: 1000,
	}
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage2)
	if err != nil {
		t.Fatalf("RecordUsage 2 failed: %v", err)
	}

	// Verify accumulated usage
	record, err := tracker.GetUsage(scope)
	if err != nil {
		t.Fatalf("GetUsage failed: %v", err)
	}

	if record.InputTokens != 3000 {
		t.Errorf("expected InputTokens 3000, got %d", record.InputTokens)
	}
	if record.OutputTokens != 1500 {
		t.Errorf("expected OutputTokens 1500, got %d", record.OutputTokens)
	}
	if record.CallCount != 2 {
		t.Errorf("expected CallCount 2, got %d", record.CallCount)
	}
}

func TestGetUsage_NotFound(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("nonexistent-mission"),
	}

	_, err := tracker.GetUsage(scope)
	if err == nil {
		t.Fatal("expected error for nonexistent scope, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrUsageNotFound {
		t.Errorf("expected error code %q, got %q", ErrUsageNotFound, gibsonErr.Code)
	}
}

func TestGetCost(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
	}

	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}

	// Record usage
	err := tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Get cost
	cost, err := tracker.GetCost(scope)
	if err != nil {
		t.Fatalf("GetCost failed: %v", err)
	}

	if cost <= 0 {
		t.Errorf("expected positive cost, got %f", cost)
	}

	// Verify cost matches the record
	record, _ := tracker.GetUsage(scope)
	if cost != record.TotalCost {
		t.Errorf("cost mismatch: GetCost=%f, record.TotalCost=%f", cost, record.TotalCost)
	}
}

func TestSetBudget(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
	}

	budget := Budget{
		MaxCost:         10.0,
		MaxInputTokens:  100000,
		MaxOutputTokens: 50000,
		MaxTotalTokens:  150000,
	}

	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Verify budget was set
	retrievedBudget, err := tracker.GetBudget(scope)
	if err != nil {
		t.Fatalf("GetBudget failed: %v", err)
	}

	if retrievedBudget.MaxCost != budget.MaxCost {
		t.Errorf("expected MaxCost %f, got %f", budget.MaxCost, retrievedBudget.MaxCost)
	}
	if retrievedBudget.MaxInputTokens != budget.MaxInputTokens {
		t.Errorf("expected MaxInputTokens %d, got %d", budget.MaxInputTokens, retrievedBudget.MaxInputTokens)
	}
	if retrievedBudget.MaxOutputTokens != budget.MaxOutputTokens {
		t.Errorf("expected MaxOutputTokens %d, got %d", budget.MaxOutputTokens, retrievedBudget.MaxOutputTokens)
	}
	if retrievedBudget.MaxTotalTokens != budget.MaxTotalTokens {
		t.Errorf("expected MaxTotalTokens %d, got %d", budget.MaxTotalTokens, retrievedBudget.MaxTotalTokens)
	}
}

func TestGetBudget_NotSet(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	budget, err := tracker.GetBudget(scope)
	if err != nil {
		t.Fatalf("GetBudget failed: %v", err)
	}

	// Should return unlimited budget (all zeros)
	if budget.MaxCost != 0 {
		t.Errorf("expected MaxCost 0 for unset budget, got %f", budget.MaxCost)
	}
	if budget.MaxInputTokens != 0 {
		t.Errorf("expected MaxInputTokens 0 for unset budget, got %d", budget.MaxInputTokens)
	}
}

func TestCheckBudget_NoBudget(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	usage := TokenUsage{
		InputTokens:  1000000,
		OutputTokens: 1000000,
	}

	// Should not error with no budget set (unlimited)
	err := tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Errorf("unexpected error with no budget: %v", err)
	}
}

func TestCheckBudget_CostLimit(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	// Set budget with cost limit
	budget := Budget{
		MaxCost: 1.0, // $1 limit
	}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Record some usage
	usage1 := TokenUsage{
		InputTokens:  10000,
		OutputTokens: 5000,
	}
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage1)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Try to use more tokens that would exceed budget
	usage2 := TokenUsage{
		InputTokens:  100000,
		OutputTokens: 50000,
	}
	err = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage2)
	if err == nil {
		t.Fatal("expected budget exceeded error, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrBudgetExceeded {
		t.Errorf("expected error code %q, got %q", ErrBudgetExceeded, gibsonErr.Code)
	}
}

func TestCheckBudget_InputTokenLimit(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	// Set budget with input token limit
	budget := Budget{
		MaxInputTokens: 5000,
	}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Record some usage
	usage1 := TokenUsage{
		InputTokens:  3000,
		OutputTokens: 1000,
	}
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage1)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Try to use more input tokens that would exceed budget
	usage2 := TokenUsage{
		InputTokens:  3000, // 3000 + 3000 = 6000 > 5000
		OutputTokens: 1000,
	}
	err = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage2)
	if err == nil {
		t.Fatal("expected budget exceeded error, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrBudgetExceeded {
		t.Errorf("expected error code %q, got %q", ErrBudgetExceeded, gibsonErr.Code)
	}
}

func TestCheckBudget_OutputTokenLimit(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	// Set budget with output token limit
	budget := Budget{
		MaxOutputTokens: 2000,
	}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Record some usage
	usage1 := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 1500,
	}
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage1)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Try to use more output tokens that would exceed budget
	usage2 := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 1000, // 1500 + 1000 = 2500 > 2000
	}
	err = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage2)
	if err == nil {
		t.Fatal("expected budget exceeded error, got nil")
	}
}

func TestCheckBudget_TotalTokenLimit(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	// Set budget with total token limit
	budget := Budget{
		MaxTotalTokens: 5000,
	}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Record some usage
	usage1 := TokenUsage{
		InputTokens:  2000,
		OutputTokens: 1000,
	} // Total: 3000
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage1)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Try to use more tokens that would exceed total limit
	usage2 := TokenUsage{
		InputTokens:  1500,
		OutputTokens: 1000,
	} // Total: 2500, combined: 5500 > 5000
	err = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage2)
	if err == nil {
		t.Fatal("expected budget exceeded error, got nil")
	}
}

func TestCheckBudget_WithinBudget(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
	}

	// Set budget
	budget := Budget{
		MaxCost:         10.0,
		MaxInputTokens:  100000,
		MaxOutputTokens: 50000,
		MaxTotalTokens:  150000,
	}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// Check small usage that's within budget
	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}
	err = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Errorf("unexpected error for usage within budget: %v", err)
	}
}

func TestReset(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	scope := UsageScope{
		MissionID: types.ID("mission-123"),
		AgentName: "test-agent",
	}

	// Set budget and record usage
	budget := Budget{MaxCost: 10.0}
	err := tracker.SetBudget(scope, budget)
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}
	err = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
	if err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Reset usage
	err = tracker.Reset(scope)
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Verify usage is cleared
	_, err = tracker.GetUsage(scope)
	if err == nil {
		t.Error("expected error after reset, got nil")
	}

	// Verify budget is preserved
	retrievedBudget, err := tracker.GetBudget(scope)
	if err != nil {
		t.Fatalf("GetBudget failed: %v", err)
	}
	if retrievedBudget.MaxCost != budget.MaxCost {
		t.Errorf("budget was cleared by Reset, expected MaxCost %f, got %f", budget.MaxCost, retrievedBudget.MaxCost)
	}
}

func TestTokenTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // readers, writers, budget checkers

	// Concurrent usage recording
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				scope := UsageScope{
					MissionID: types.ID(fmt.Sprintf("mission-%d", id%10)),
					AgentName: fmt.Sprintf("agent-%d", id),
				}
				usage := TokenUsage{
					InputTokens:  100,
					OutputTokens: 50,
				}
				_ = tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				scope := UsageScope{
					MissionID: types.ID(fmt.Sprintf("mission-%d", id%10)),
				}
				_, _ = tracker.GetUsage(scope)
				_, _ = tracker.GetCost(scope)
			}
		}(i)
	}

	// Concurrent budget operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				scope := UsageScope{
					MissionID: types.ID(fmt.Sprintf("mission-%d", id%10)),
				}
				budget := Budget{MaxCost: 10.0}
				_ = tracker.SetBudget(scope, budget)
				_, _ = tracker.GetBudget(scope)
				usage := TokenUsage{InputTokens: 100, OutputTokens: 50}
				_ = tracker.CheckBudget(scope, "anthropic", "claude-3-opus-20240229", usage)
			}
		}(i)
	}

	wg.Wait()
}

func TestTokenTracker_HierarchicalAggregation(t *testing.T) {
	tracker := NewTokenTracker(DefaultPricing())

	missionID := types.ID("mission-123")

	// Record usage for multiple agents and slots
	scopes := []UsageScope{
		{MissionID: missionID, AgentName: "agent1", SlotName: "slot1"},
		{MissionID: missionID, AgentName: "agent1", SlotName: "slot2"},
		{MissionID: missionID, AgentName: "agent2", SlotName: "slot1"},
	}

	usage := TokenUsage{
		InputTokens:  1000,
		OutputTokens: 500,
	}

	for _, scope := range scopes {
		err := tracker.RecordUsage(scope, "anthropic", "claude-3-opus-20240229", usage)
		if err != nil {
			t.Fatalf("RecordUsage failed for %s: %v", scope, err)
		}
	}

	// Verify slot-level usage
	for _, scope := range scopes {
		record, err := tracker.GetUsage(scope)
		if err != nil {
			t.Fatalf("GetUsage failed for slot %s: %v", scope, err)
		}
		if record.InputTokens != 1000 {
			t.Errorf("expected slot InputTokens 1000, got %d for %s", record.InputTokens, scope)
		}
	}

	// Verify agent1 aggregation (2 slots)
	agent1Scope := UsageScope{MissionID: missionID, AgentName: "agent1"}
	agent1Record, err := tracker.GetUsage(agent1Scope)
	if err != nil {
		t.Fatalf("GetUsage failed for agent1: %v", err)
	}
	if agent1Record.InputTokens != 2000 {
		t.Errorf("expected agent1 InputTokens 2000, got %d", agent1Record.InputTokens)
	}

	// Verify agent2 aggregation (1 slot)
	agent2Scope := UsageScope{MissionID: missionID, AgentName: "agent2"}
	agent2Record, err := tracker.GetUsage(agent2Scope)
	if err != nil {
		t.Fatalf("GetUsage failed for agent2: %v", err)
	}
	if agent2Record.InputTokens != 1000 {
		t.Errorf("expected agent2 InputTokens 1000, got %d", agent2Record.InputTokens)
	}

	// Verify mission aggregation (3 slots total)
	missionScope := UsageScope{MissionID: missionID}
	missionRecord, err := tracker.GetUsage(missionScope)
	if err != nil {
		t.Fatalf("GetUsage failed for mission: %v", err)
	}
	if missionRecord.InputTokens != 3000 {
		t.Errorf("expected mission InputTokens 3000, got %d", missionRecord.InputTokens)
	}
	if missionRecord.OutputTokens != 1500 {
		t.Errorf("expected mission OutputTokens 1500, got %d", missionRecord.OutputTokens)
	}
}
