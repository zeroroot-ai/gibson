package eval

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/eval"
)

func TestNewEvalResultCollector(t *testing.T) {
	missionID := types.NewID()
	collector := NewEvalResultCollector(missionID)

	require.NotNil(t, collector)
	assert.Equal(t, missionID, collector.missionID)
	assert.NotNil(t, collector.trajectories)
	assert.NotNil(t, collector.feedbackHist)
	assert.NotNil(t, collector.harnesses)
	assert.NotNil(t, collector.finalScores)
	assert.NotNil(t, collector.alerts)
	assert.Equal(t, 0, collector.totalTokens)
	assert.False(t, collector.startTime.IsZero())
}

func TestAddTrajectoryStep(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	step := eval.TrajectoryStep{
		Type:      "tool",
		Name:      "nmap",
		StartTime: time.Now(),
		Duration:  100 * time.Millisecond,
	}

	// Add step for agent1
	collector.AddTrajectoryStep("agent1", step)

	// Verify trajectory was created
	trajectory := collector.GetTrajectory("agent1")
	require.NotNil(t, trajectory)
	assert.Len(t, trajectory.Steps, 1)
	assert.Equal(t, "tool", trajectory.Steps[0].Type)
	assert.Equal(t, "nmap", trajectory.Steps[0].Name)

	// Add another step for the same agent
	step2 := eval.TrajectoryStep{
		Type:      "llm",
		Name:      "primary",
		StartTime: time.Now(),
		Duration:  200 * time.Millisecond,
	}
	collector.AddTrajectoryStep("agent1", step2)

	// Verify step was appended
	trajectory = collector.GetTrajectory("agent1")
	assert.Len(t, trajectory.Steps, 2)
	assert.Equal(t, "llm", trajectory.Steps[1].Type)

	// Add step for different agent
	collector.AddTrajectoryStep("agent2", step)
	trajectory2 := collector.GetTrajectory("agent2")
	require.NotNil(t, trajectory2)
	assert.Len(t, trajectory2.Steps, 1)
}

func TestCollector_AddFeedback(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	alert1 := eval.Alert{
		Level:     eval.AlertWarning,
		Scorer:    "test-scorer",
		Score:     0.4,
		Threshold: 0.5,
		Message:   "Performance below threshold",
	}

	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 5,
		Scores: map[string]eval.PartialScore{
			"test-scorer": {
				Score:      0.4,
				Confidence: 0.8,
				Status:     eval.ScoreStatusPartial,
			},
		},
		Alerts: []eval.Alert{alert1},
	}

	// Add feedback for agent1
	collector.AddFeedback("agent1", feedback)

	// Verify feedback was stored
	history := collector.GetFeedbackHistory("agent1")
	require.Len(t, history, 1)
	assert.Equal(t, 5, history[0].StepIndex)

	// Verify alert was extracted
	alerts := collector.GetAlerts()
	require.Len(t, alerts, 1)
	assert.Equal(t, eval.AlertWarning, alerts[0].Level)

	// Add more feedback
	feedback2 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 10,
		Scores: map[string]eval.PartialScore{
			"test-scorer": {
				Score:      0.7,
				Confidence: 0.9,
				Status:     eval.ScoreStatusPartial,
			},
		},
		Alerts: []eval.Alert{},
	}
	collector.AddFeedback("agent1", feedback2)

	// Verify feedback was appended
	history = collector.GetFeedbackHistory("agent1")
	assert.Len(t, history, 2)
	assert.Equal(t, 10, history[1].StepIndex)
}

func TestAddAlert(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	alert := eval.Alert{
		Level:     eval.AlertCritical,
		Scorer:    "security-scorer",
		Score:     0.1,
		Threshold: 0.2,
		Message:   "Critical performance issue",
	}

	collector.AddAlert(alert)

	alerts := collector.GetAlerts()
	require.Len(t, alerts, 1)
	assert.Equal(t, eval.AlertCritical, alerts[0].Level)
	assert.Equal(t, "security-scorer", alerts[0].Scorer)
}

func TestSetFinalScore(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	result := eval.ScoreResult{
		Score: 0.85,
		Details: map[string]any{
			"precision": 0.9,
			"recall":    0.8,
		},
	}

	err := collector.SetFinalScore("accuracy-scorer", result)
	require.NoError(t, err)

	// Test invalid score
	invalidResult := eval.ScoreResult{
		Score: 1.5, // Out of range
	}
	err = collector.SetFinalScore("invalid-scorer", invalidResult)
	assert.Error(t, err)
}

func TestGetSummary(t *testing.T) {
	missionID := types.NewID()
	collector := NewEvalResultCollector(missionID)

	// Add some data
	step := eval.TrajectoryStep{
		Type:      "tool",
		Name:      "test-tool",
		StartTime: time.Now(),
		Duration:  50 * time.Millisecond,
	}
	collector.AddTrajectoryStep("agent1", step)
	collector.AddTrajectoryStep("agent1", step)
	collector.AddTrajectoryStep("agent2", step)

	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Scores: map[string]eval.PartialScore{
			"scorer1": {
				Score:      0.8,
				Confidence: 0.9,
			},
		},
		Alerts: []eval.Alert{
			{
				Level:     eval.AlertWarning,
				Scorer:    "scorer1",
				Score:     0.4,
				Threshold: 0.5,
				Message:   "Warning",
			},
		},
	}
	collector.AddFeedback("agent1", feedback)

	// Get summary
	summary := collector.GetSummary()
	require.NotNil(t, summary)
	assert.Equal(t, missionID, summary.MissionID)
	assert.Equal(t, 3, summary.TotalSteps)
	assert.Equal(t, 1, summary.TotalAlerts)
	assert.Equal(t, 1, summary.WarningCount)
	assert.Equal(t, 0, summary.CriticalCount)
	assert.Greater(t, summary.Duration, time.Duration(0))
}

func TestGetSummaryWithScores(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add feedback with scores from multiple agents
	feedback1 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Scores: map[string]eval.PartialScore{
			"scorer1": {Score: 0.8, Confidence: 0.9},
			"scorer2": {Score: 0.6, Confidence: 0.8},
		},
	}
	collector.AddFeedback("agent1", feedback1)

	feedback2 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Scores: map[string]eval.PartialScore{
			"scorer1": {Score: 0.9, Confidence: 0.95},
			"scorer2": {Score: 0.7, Confidence: 0.85},
		},
	}
	collector.AddFeedback("agent2", feedback2)

	summary := collector.GetSummary()

	// Verify scores were averaged across agents
	assert.Contains(t, summary.ScorerScores, "scorer1")
	assert.Contains(t, summary.ScorerScores, "scorer2")
	assert.InDelta(t, 0.85, summary.ScorerScores["scorer1"], 0.01) // (0.8 + 0.9) / 2
	assert.InDelta(t, 0.65, summary.ScorerScores["scorer2"], 0.01) // (0.6 + 0.7) / 2
}

func TestFinalizeWithoutHarnesses(t *testing.T) {
	missionID := types.NewID()
	collector := NewEvalResultCollector(missionID)

	// Add data manually without harnesses
	step := eval.TrajectoryStep{
		Type:      "tool",
		Name:      "nmap",
		StartTime: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	collector.AddTrajectoryStep("agent1", step)

	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Scores: map[string]eval.PartialScore{
			"scorer1": {Score: 0.75, Confidence: 0.9},
		},
		Alerts: []eval.Alert{
			{
				Level:     eval.AlertWarning,
				Scorer:    "scorer1",
				Score:     0.4,
				Threshold: 0.5,
				Message:   "Test warning",
			},
		},
	}
	collector.AddFeedback("agent1", feedback)

	// Finalize
	ctx := context.Background()
	summary, err := collector.Finalize(ctx)
	require.NoError(t, err)
	require.NotNil(t, summary)

	assert.Equal(t, missionID, summary.MissionID)
	assert.Equal(t, 1, summary.TotalSteps)
	assert.Equal(t, 1, summary.TotalAlerts)
	assert.Equal(t, 1, summary.WarningCount)
	assert.Equal(t, 0, summary.CriticalCount)
	assert.Contains(t, summary.ScorerScores, "scorer1")
	assert.InDelta(t, 0.75, summary.ScorerScores["scorer1"], 0.01)
}

func TestGetTrajectoryNonExistent(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	trajectory := collector.GetTrajectory("non-existent")
	assert.Nil(t, trajectory)
}

func TestGetFeedbackHistoryNonExistent(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	history := collector.GetFeedbackHistory("non-existent")
	assert.NotNil(t, history)
	assert.Len(t, history, 0)
}

func TestCopyPreventsExternalModification(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	alert := eval.Alert{
		Level:   eval.AlertWarning,
		Scorer:  "test",
		Message: "original",
	}
	collector.AddAlert(alert)

	// Get copy
	alerts := collector.GetAlerts()
	require.Len(t, alerts, 1)

	// Modify copy
	alerts[0].Message = "modified"

	// Verify original is unchanged
	originalAlerts := collector.GetAlerts()
	assert.Equal(t, "original", originalAlerts[0].Message)
}

func TestMultipleAgentsScoreAveraging(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Agent 1 feedback
	feedback1 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Scores: map[string]eval.PartialScore{
			"accuracy": {Score: 0.9, Confidence: 0.95},
			"speed":    {Score: 0.7, Confidence: 0.8},
		},
	}
	collector.AddFeedback("agent1", feedback1)

	// Agent 2 feedback
	feedback2 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Scores: map[string]eval.PartialScore{
			"accuracy": {Score: 0.8, Confidence: 0.9},
			"speed":    {Score: 0.6, Confidence: 0.85},
		},
	}
	collector.AddFeedback("agent2", feedback2)

	// Agent 3 feedback
	feedback3 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Scores: map[string]eval.PartialScore{
			"accuracy": {Score: 0.85, Confidence: 0.92},
			"speed":    {Score: 0.5, Confidence: 0.75},
		},
	}
	collector.AddFeedback("agent3", feedback3)

	summary := collector.GetSummary()

	// Verify averaging: (0.9 + 0.8 + 0.85) / 3 = 0.85
	assert.InDelta(t, 0.85, summary.ScorerScores["accuracy"], 0.01)
	// Verify averaging: (0.7 + 0.6 + 0.5) / 3 = 0.6
	assert.InDelta(t, 0.6, summary.ScorerScores["speed"], 0.01)
}

func TestAlertCounting(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add warnings
	for i := 0; i < 3; i++ {
		collector.AddAlert(eval.Alert{
			Level:   eval.AlertWarning,
			Message: "warning",
		})
	}

	// Add critical alerts
	for i := 0; i < 2; i++ {
		collector.AddAlert(eval.Alert{
			Level:   eval.AlertCritical,
			Message: "critical",
		})
	}

	summary := collector.GetSummary()
	assert.Equal(t, 5, summary.TotalAlerts)
	assert.Equal(t, 3, summary.WarningCount)
	assert.Equal(t, 2, summary.CriticalCount)
}

func TestConcurrentAccess(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())
	var wg sync.WaitGroup

	// Number of concurrent goroutines
	numGoroutines := 10
	numOperations := 100

	// Test concurrent AddTrajectoryStep
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(agentID int) {
			defer wg.Done()
			agentName := "agent" + string(rune('0'+agentID))
			for j := 0; j < numOperations; j++ {
				step := eval.TrajectoryStep{
					Type:      "tool",
					Name:      "test",
					StartTime: time.Now(),
					Duration:  10 * time.Millisecond,
				}
				collector.AddTrajectoryStep(agentName, step)
			}
		}(i)
	}
	wg.Wait()

	// Verify all steps were added
	totalSteps := 0
	for i := 0; i < numGoroutines; i++ {
		agentName := "agent" + string(rune('0'+i))
		trajectory := collector.GetTrajectory(agentName)
		if trajectory != nil {
			totalSteps += len(trajectory.Steps)
		}
	}
	assert.Equal(t, numGoroutines*numOperations, totalSteps)

	// Test concurrent AddFeedback
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(agentID int) {
			defer wg.Done()
			agentName := "agent" + string(rune('0'+agentID))
			for j := 0; j < numOperations; j++ {
				feedback := eval.Feedback{
					Timestamp: time.Now(),
					StepIndex: j,
					Scores: map[string]eval.PartialScore{
						"test-scorer": {
							Score:      0.5,
							Confidence: 0.8,
						},
					},
				}
				collector.AddFeedback(agentName, feedback)
			}
		}(i)
	}
	wg.Wait()

	// Verify all feedback was added
	totalFeedback := 0
	for i := 0; i < numGoroutines; i++ {
		agentName := "agent" + string(rune('0'+i))
		history := collector.GetFeedbackHistory(agentName)
		totalFeedback += len(history)
	}
	assert.Equal(t, numGoroutines*numOperations, totalFeedback)

	// Test concurrent reads with writes
	wg.Add(numGoroutines * 2)
	for i := 0; i < numGoroutines; i++ {
		// Writers
		go func(agentID int) {
			defer wg.Done()
			agentName := "agent" + string(rune('0'+agentID))
			for j := 0; j < 10; j++ {
				alert := eval.Alert{
					Level:     eval.AlertWarning,
					Scorer:    "test",
					Score:     0.4,
					Threshold: 0.5,
					Message:   "test",
				}
				collector.AddAlert(alert)
				collector.AddTrajectoryStep(agentName, eval.TrajectoryStep{
					Type: "test",
					Name: "test",
				})
			}
		}(i)

		// Readers
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = collector.GetSummary()
				_ = collector.GetAlerts()
			}
		}()
	}
	wg.Wait()
}
