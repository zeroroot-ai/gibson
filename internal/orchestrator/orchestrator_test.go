package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// =============================================================================
// Mock Implementations
// =============================================================================

type mockObserver struct {
	observeFunc func(ctx context.Context, missionID string) (*ObservationState, error)
	callCount   int
}

func (m *mockObserver) Observe(ctx context.Context, missionID string) (*ObservationState, error) {
	m.callCount++
	if m.observeFunc != nil {
		return m.observeFunc(ctx, missionID)
	}
	return createDefaultObservationState(missionID), nil
}

type mockThinker struct {
	thinkFunc func(ctx context.Context, state *ObservationState) (*ThinkResult, error)
	callCount int
}

func (m *mockThinker) Think(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
	m.callCount++
	if m.thinkFunc != nil {
		return m.thinkFunc(ctx, state)
	}
	return createDefaultThinkResult(ActionComplete), nil
}

type mockActor struct {
	actFunc   func(ctx context.Context, decision *Decision, missionID string) (*ActionResult, error)
	callCount int
}

func (m *mockActor) Act(ctx context.Context, decision *Decision, missionID string) (*ActionResult, error) {
	m.callCount++
	if m.actFunc != nil {
		return m.actFunc(ctx, decision, missionID)
	}
	return createDefaultActionResult(decision.Action, decision.Action == ActionComplete), nil
}

type mockEventBus struct {
	events []events.Event
}

func (m *mockEventBus) Publish(event events.Event) {
	m.events = append(m.events, event)
}

type mockDecisionLogWriter struct {
	decisions []loggedDecision
	actions   []loggedAction
}

type loggedDecision struct {
	decision  *Decision
	result    *ThinkResult
	iteration int
	missionID string
}

type loggedAction struct {
	action    *ActionResult
	iteration int
	missionID string
}

func (m *mockDecisionLogWriter) LogDecision(ctx context.Context, decision *Decision, result *ThinkResult, iteration int, missionID string) error {
	m.decisions = append(m.decisions, loggedDecision{decision, result, iteration, missionID})
	return nil
}

func (m *mockDecisionLogWriter) LogAction(ctx context.Context, action *ActionResult, iteration int, missionID string) error {
	m.actions = append(m.actions, loggedAction{action, iteration, missionID})
	return nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func createDefaultObservationState(missionID string) *ObservationState {
	return &ObservationState{
		MissionInfo: MissionInfo{
			ID:     missionID,
			Name:   "Test Mission",
			Status: "running",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     1,
			CompletedNodes: 0,
			FailedNodes:    0,
			PendingNodes:   1,
		},
		ReadyNodes: []NodeSummary{
			{ID: types.NewID().String(), Name: "Test Node", AgentName: "test-agent"},
		},
		RunningNodes: []NodeSummary{},
		ResourceConstraints: ResourceConstraints{
			MaxConcurrent:  10,
			CurrentRunning: 0,
		},
		ObservedAt: time.Now(),
	}
}

func createDefaultThinkResult(action DecisionAction) *ThinkResult {
	decision := &Decision{
		Reasoning:  "Test reasoning",
		Action:     action,
		Confidence: 0.9,
	}

	if action == ActionComplete {
		decision.StopReason = "Mission complete"
	} else if action == ActionExecuteAgent || action == ActionSkipAgent || action == ActionRetry {
		decision.TargetNodeID = types.NewID().String()
	} else if action == ActionSpawnAgent {
		decision.SpawnConfig = &SpawnNodeConfig{
			AgentName:   "spawned-agent",
			Description: "Dynamically spawned agent",
			TaskConfig:  map[string]interface{}{},
			DependsOn:   []string{},
		}
	}

	return &ThinkResult{
		Decision:         decision,
		TotalTokens:      500,
		PromptTokens:     400,
		CompletionTokens: 100,
		Latency:          50 * time.Millisecond,
		Model:            "test-model",
	}
}

func createDefaultActionResult(action DecisionAction, isTerminal bool) *ActionResult {
	return &ActionResult{
		Action:       action,
		IsTerminal:   isTerminal,
		TargetNodeID: types.NewID().String(),
		Metadata:     map[string]interface{}{},
	}
}

// =============================================================================
// Configuration Tests
// =============================================================================

func TestOrchestratorOptions(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil,
		WithMaxIterations(50),
		WithBudget(100000),
		WithMaxConcurrent(5),
		WithTimeout(30*time.Minute),
	)

	assert.Equal(t, 50, o.maxIterations)
	assert.Equal(t, 100000, o.budget)
	assert.Equal(t, 5, o.maxConcurrent)
	assert.Equal(t, 30*time.Minute, o.timeout)
}

func TestOrchestratorDefaults(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil)

	assert.Equal(t, 100, o.maxIterations)
	assert.Equal(t, 0, o.budget)
	assert.Equal(t, 10, o.maxConcurrent)
	assert.Equal(t, time.Duration(0), o.timeout)
	assert.NotNil(t, o.logger)
	assert.NotNil(t, o.tracer)
}

func TestOrchestratorStatus(t *testing.T) {
	tests := []struct {
		status   OrchestratorStatus
		expected string
	}{
		{StatusCompleted, "completed"},
		{StatusFailed, "failed"},
		{StatusMaxIterations, "max_iterations"},
		{StatusTimeout, "timeout"},
		{StatusCancelled, "cancelled"},
		{StatusBudgetExceeded, "budget_exceeded"},
		{StatusConcurrencyLimit, "concurrency_limit"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestOrchestratorResultString(t *testing.T) {
	result := &OrchestratorResult{
		MissionID:       "mission-123",
		Status:          StatusCompleted,
		TotalIterations: 10,
		TotalDecisions:  8,
		TotalTokensUsed: 50000,
		Duration:        5 * time.Minute,
		CompletedNodes:  15,
		FailedNodes:     2,
	}

	str := result.String()
	assert.NotEmpty(t, str)
	assert.Greater(t, len(str), 50)
}

// =============================================================================
// Simple Mission Tests
// =============================================================================

func TestOrchestrator_Run_SimpleMission(t *testing.T) {
	t.Run("observe -> think -> act -> complete", func(t *testing.T) {
		missionID := types.NewID().String()
		ctx := context.Background()

		observer := &mockObserver{
			observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
				return createDefaultObservationState(mid), nil
			},
		}

		thinker := &mockThinker{
			thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
				return createDefaultThinkResult(ActionComplete), nil
			},
		}

		actor := &mockActor{
			actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
				return createDefaultActionResult(ActionComplete, true), nil
			},
		}

		o := NewOrchestrator(observer, thinker, actor)

		result, err := o.Run(ctx, missionID)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, StatusCompleted, result.Status)
		assert.Equal(t, 1, result.TotalIterations)
		assert.Equal(t, 1, result.TotalDecisions)
		assert.Equal(t, 1, observer.callCount)
		assert.Equal(t, 1, thinker.callCount)
		assert.Equal(t, 1, actor.callCount)
	})
}

// =============================================================================
// Multi-Iteration Tests
// =============================================================================

func TestOrchestrator_Run_MultipleIterations(t *testing.T) {
	t.Run("multiple decisions before complete", func(t *testing.T) {
		missionID := types.NewID().String()
		ctx := context.Background()

		node1ID := types.NewID().String()
		node2ID := types.NewID().String()

		observeCount := 0
		observer := &mockObserver{
			observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
				observeCount++
				iteration := observeCount
				switch iteration {
				case 1:
					// Iteration 1: 2 ready nodes
					return &ObservationState{
						MissionInfo: MissionInfo{ID: mid},
						GraphSummary: GraphSummary{
							TotalNodes: 2, CompletedNodes: 0, FailedNodes: 0, PendingNodes: 2,
						},
						ReadyNodes: []NodeSummary{
							{ID: node1ID, Name: "Node 1", AgentName: "agent-1"},
							{ID: node2ID, Name: "Node 2", AgentName: "agent-2"},
						},
						RunningNodes: []NodeSummary{},
						ResourceConstraints: ResourceConstraints{
							MaxConcurrent:  10,
							CurrentRunning: 0,
						},
						ObservedAt: time.Now(),
					}, nil
				case 2:
					// Iteration 2: 1 ready, 1 completed
					return &ObservationState{
						MissionInfo: MissionInfo{ID: mid},
						GraphSummary: GraphSummary{
							TotalNodes: 2, CompletedNodes: 1, FailedNodes: 0, PendingNodes: 1,
						},
						ReadyNodes: []NodeSummary{
							{ID: node2ID, Name: "Node 2", AgentName: "agent-2"},
						},
						RunningNodes: []NodeSummary{},
						ResourceConstraints: ResourceConstraints{
							MaxConcurrent:  10,
							CurrentRunning: 0,
						},
						ObservedAt: time.Now(),
					}, nil
				default:
					// Iteration 3: all completed, no more work
					return &ObservationState{
						MissionInfo: MissionInfo{ID: mid},
						GraphSummary: GraphSummary{
							TotalNodes: 2, CompletedNodes: 2, FailedNodes: 0, PendingNodes: 0,
						},
						ReadyNodes:   []NodeSummary{},
						RunningNodes: []NodeSummary{},
						ResourceConstraints: ResourceConstraints{
							MaxConcurrent:  10,
							CurrentRunning: 0,
						},
						ObservedAt: time.Now(),
					}, nil
				}
			},
		}

		thinker := &mockThinker{
			thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
				decision := &Decision{
					Reasoning:    "Execute node",
					Action:       ActionExecuteAgent,
					TargetNodeID: state.ReadyNodes[0].ID,
					Confidence:   0.9,
				}
				return &ThinkResult{
					Decision:    decision,
					TotalTokens: 500,
					Latency:     50 * time.Millisecond,
				}, nil
			},
		}

		actor := &mockActor{
			actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
				return createDefaultActionResult(ActionExecuteAgent, false), nil
			},
		}

		o := NewOrchestrator(observer, thinker, actor)

		result, err := o.Run(ctx, missionID)

		require.NoError(t, err)
		assert.Equal(t, StatusCompleted, result.Status)
		assert.Equal(t, 3, result.TotalIterations)
		assert.Equal(t, 2, result.TotalDecisions)
		assert.Equal(t, 1000, result.TotalTokensUsed) // 2 decisions * 500 tokens
	})
}

// =============================================================================
// Limit Tests
// =============================================================================

func TestOrchestrator_Run_MaxIterationsReached(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	// State always has ready nodes (never completes naturally)
	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			state := createDefaultObservationState(mid)
			state.ReadyNodes = []NodeSummary{
				{ID: types.NewID().String(), Name: "Node", AgentName: "agent"},
			}
			return state, nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionExecuteAgent), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionExecuteAgent, false), nil
		},
	}

	o := NewOrchestrator(observer, thinker, actor, WithMaxIterations(5))

	result, err := o.Run(ctx, missionID)

	require.NoError(t, err)
	assert.Equal(t, StatusMaxIterations, result.Status)
	assert.Equal(t, 5, result.TotalIterations)
	assert.Equal(t, 5, observer.callCount)
}

func TestOrchestrator_Run_BudgetExceeded(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			state := createDefaultObservationState(mid)
			state.ReadyNodes = []NodeSummary{
				{ID: types.NewID().String(), Name: "Node", AgentName: "agent"},
			}
			return state, nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			result := createDefaultThinkResult(ActionExecuteAgent)
			result.TotalTokens = 300
			return result, nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionExecuteAgent, false), nil
		},
	}

	o := NewOrchestrator(observer, thinker, actor, WithBudget(500))

	result, err := o.Run(ctx, missionID)

	require.NoError(t, err)
	assert.Equal(t, StatusBudgetExceeded, result.Status)
	assert.GreaterOrEqual(t, result.TotalTokensUsed, 500)
}

func TestOrchestrator_Run_ContextCancellation(t *testing.T) {
	missionID := types.NewID().String()

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return createDefaultObservationState(mid), nil
		},
	}

	thinker := &mockThinker{}
	actor := &mockActor{}

	o := NewOrchestrator(observer, thinker, actor)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := o.Run(ctx, missionID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, StatusCancelled, result.Status)
	assert.NotNil(t, result.Error)
	assert.Equal(t, context.Canceled, result.Error)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestOrchestrator_Run_ObserverFailure(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observerErr := errors.New("failed to query graph database")

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return nil, observerErr
		},
	}

	thinker := &mockThinker{}
	actor := &mockActor{}

	o := NewOrchestrator(observer, thinker, actor)

	result, err := o.Run(ctx, missionID)

	assert.Error(t, err)
	assert.ErrorIs(t, err, observerErr)
	require.NotNil(t, result)
	assert.Equal(t, StatusFailed, result.Status)
	assert.Equal(t, 0, result.TotalIterations)
}

func TestOrchestrator_Run_ThinkerFailure(t *testing.T) {
	t.Run("thinker fails immediately", func(t *testing.T) {
		missionID := types.NewID().String()
		ctx := context.Background()

		thinkerErr := errors.New("LLM API error: rate limit exceeded")

		observer := &mockObserver{
			observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
				return createDefaultObservationState(mid), nil
			},
		}

		thinker := &mockThinker{
			thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
				return nil, thinkerErr
			},
		}

		actor := &mockActor{}

		o := NewOrchestrator(observer, thinker, actor)

		result, err := o.Run(ctx, missionID)

		assert.Error(t, err)
		assert.ErrorIs(t, err, thinkerErr)
		require.NotNil(t, result)
		assert.Equal(t, StatusFailed, result.Status)
		assert.Equal(t, 1, result.TotalIterations)
	})

	t.Run("thinker fails after retries", func(t *testing.T) {
		missionID := types.NewID().String()
		ctx := context.Background()

		thinkerErr := errors.New("LLM parse error")

		observer := &mockObserver{
			observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
				return createDefaultObservationState(mid), nil
			},
		}

		thinkCount := 0
		thinker := &mockThinker{
			thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
				thinkCount++
				if thinkCount == 1 {
					return createDefaultThinkResult(ActionExecuteAgent), nil
				}
				return nil, thinkerErr
			},
		}

		actor := &mockActor{
			actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
				return createDefaultActionResult(ActionExecuteAgent, false), nil
			},
		}

		o := NewOrchestrator(observer, thinker, actor)

		result, err := o.Run(ctx, missionID)

		assert.Error(t, err)
		assert.ErrorIs(t, err, thinkerErr)
		require.NotNil(t, result)
		assert.Equal(t, StatusFailed, result.Status)
		assert.Equal(t, 2, result.TotalIterations)
		assert.Equal(t, 1, result.TotalDecisions)
	})
}

func TestOrchestrator_Run_ActorFailure(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	actorErr := errors.New("agent execution failed: connection timeout")

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return createDefaultObservationState(mid), nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionExecuteAgent), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return nil, actorErr
		},
	}

	o := NewOrchestrator(observer, thinker, actor)

	result, err := o.Run(ctx, missionID)

	assert.Error(t, err)
	assert.ErrorIs(t, err, actorErr)
	require.NotNil(t, result)
	assert.Equal(t, StatusFailed, result.Status)
	assert.Equal(t, 1, result.TotalIterations)
}

func TestOrchestrator_Run_InvalidMissionID(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil)

	ctx := context.Background()
	result, err := o.Run(ctx, "invalid-id-format")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid mission ID")
}

// =============================================================================
// Decision Type Tests
// =============================================================================

func TestOrchestrator_Run_AllDecisionTypes(t *testing.T) {
	tests := []struct {
		name       string
		action     DecisionAction
		isTerminal bool
	}{
		{
			name:       "execute_agent",
			action:     ActionExecuteAgent,
			isTerminal: false,
		},
		{
			name:       "skip_agent",
			action:     ActionSkipAgent,
			isTerminal: false,
		},
		{
			name:       "spawn_agent",
			action:     ActionSpawnAgent,
			isTerminal: false,
		},
		{
			name:       "complete",
			action:     ActionComplete,
			isTerminal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missionID := types.NewID().String()
			ctx := context.Background()

			iterationCount := 0

			observer := &mockObserver{
				observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
					iterationCount++
					if tt.isTerminal {
						return createDefaultObservationState(mid), nil
					}
					// For non-terminal actions, complete on second iteration
					if iterationCount == 1 {
						return createDefaultObservationState(mid), nil
					}
					// No more work available
					state := createDefaultObservationState(mid)
					state.ReadyNodes = []NodeSummary{}
					state.RunningNodes = []NodeSummary{}
					return state, nil
				},
			}

			thinkCount := 0
			thinker := &mockThinker{
				thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
					thinkCount++
					if thinkCount == 1 {
						return createDefaultThinkResult(tt.action), nil
					}
					return createDefaultThinkResult(ActionComplete), nil
				},
			}

			actor := &mockActor{
				actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
					return createDefaultActionResult(decision.Action, decision.Action.IsTerminal()), nil
				},
			}

			o := NewOrchestrator(observer, thinker, actor)

			result, err := o.Run(ctx, missionID)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, StatusCompleted, result.Status)

			if tt.isTerminal {
				assert.Equal(t, 1, result.TotalIterations)
			} else {
				assert.Equal(t, 2, result.TotalIterations)
			}
		})
	}
}

// =============================================================================
// Event and Logging Tests
// =============================================================================

func TestOrchestrator_Run_EventBusIntegration(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return createDefaultObservationState(mid), nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionComplete), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionComplete, true), nil
		},
	}

	eventBus := &mockEventBus{}

	o := NewOrchestrator(observer, thinker, actor, WithEventBus(eventBus))

	result, err := o.Run(ctx, missionID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, StatusCompleted, result.Status)

	// Verify events were published
	assert.Greater(t, len(eventBus.events), 0)

	// Check for mission started event
	hasStartedEvent := false
	for _, event := range eventBus.events {
		if event.Type == events.EventMissionStarted {
			hasStartedEvent = true
			break
		}
	}
	assert.True(t, hasStartedEvent, "expected mission started event")
}

func TestOrchestrator_Run_DecisionLogWriter(t *testing.T) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return createDefaultObservationState(mid), nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionComplete), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionComplete, true), nil
		},
	}

	logWriter := &mockDecisionLogWriter{}

	o := NewOrchestrator(observer, thinker, actor, WithDecisionLogWriter(logWriter))

	result, err := o.Run(ctx, missionID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, StatusCompleted, result.Status)

	// Verify decisions and actions were logged
	assert.Equal(t, 1, len(logWriter.decisions))
	assert.Equal(t, 1, len(logWriter.actions))

	// Verify logged decision
	assert.Equal(t, ActionComplete, logWriter.decisions[0].decision.Action)
	assert.Equal(t, 0, logWriter.decisions[0].iteration)
	assert.Equal(t, missionID, logWriter.decisions[0].missionID)

	// Verify logged action
	assert.Equal(t, ActionComplete, logWriter.actions[0].action.Action)
	assert.Equal(t, 0, logWriter.actions[0].iteration)
	assert.Equal(t, missionID, logWriter.actions[0].missionID)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkOrchestrator_Run_SimpleMission(b *testing.B) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			return createDefaultObservationState(mid), nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionComplete), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionComplete, true), nil
		},
	}

	o := NewOrchestrator(observer, thinker, actor)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := o.Run(ctx, missionID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOrchestrator_Run_MultipleIterations(b *testing.B) {
	missionID := types.NewID().String()
	ctx := context.Background()

	observeCount := 0
	observer := &mockObserver{
		observeFunc: func(ctx context.Context, mid string) (*ObservationState, error) {
			observeCount++
			if observeCount <= 10 {
				state := createDefaultObservationState(mid)
				state.ReadyNodes = []NodeSummary{
					{ID: types.NewID().String(), Name: "Node", AgentName: "agent"},
				}
				return state, nil
			}
			// Complete after 10 iterations
			state := createDefaultObservationState(mid)
			state.ReadyNodes = []NodeSummary{}
			state.RunningNodes = []NodeSummary{}
			return state, nil
		},
	}

	thinker := &mockThinker{
		thinkFunc: func(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
			return createDefaultThinkResult(ActionExecuteAgent), nil
		},
	}

	actor := &mockActor{
		actFunc: func(ctx context.Context, decision *Decision, mid string) (*ActionResult, error) {
			return createDefaultActionResult(ActionExecuteAgent, false), nil
		},
	}

	o := NewOrchestrator(observer, thinker, actor)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := o.Run(ctx, missionID)
		if err != nil {
			b.Fatal(err)
		}
	}
}
