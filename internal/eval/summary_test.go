package eval

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/eval"
)

func TestNewEvalSummary(t *testing.T) {
	missionID := types.NewID()
	summary := NewEvalSummary(missionID)

	assert.Equal(t, missionID, summary.MissionID)
	assert.Equal(t, 0.0, summary.OverallScore)
	assert.NotNil(t, summary.ScorerScores)
	assert.Empty(t, summary.ScorerScores)
	assert.Equal(t, 0, summary.TotalSteps)
	assert.Equal(t, 0, summary.TotalAlerts)
	assert.Equal(t, 0, summary.WarningCount)
	assert.Equal(t, 0, summary.CriticalCount)
	assert.Equal(t, time.Duration(0), summary.Duration)
	assert.Equal(t, 0, summary.TokensUsed)
	assert.NotNil(t, summary.FeedbackHistory)
	assert.Empty(t, summary.FeedbackHistory)
}

func TestComputeOverallScore_EqualWeighting(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.8,
		"task_completion":  0.6,
		"finding_accuracy": 0.9,
	}

	score := summary.ComputeOverallScore(nil)

	// (0.8 + 0.6 + 0.9) / 3 = 0.7666...
	assert.InDelta(t, 0.7666, score, 0.001)
	assert.Equal(t, summary.OverallScore, score)
}

func TestComputeOverallScore_WeightedAverage(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.8,
		"task_completion":  0.6,
		"finding_accuracy": 0.9,
	}

	weights := map[string]float64{
		"tool_correctness": 0.5, // 50% weight
		"task_completion":  0.3, // 30% weight
		"finding_accuracy": 0.2, // 20% weight
	}

	score := summary.ComputeOverallScore(weights)

	// (0.8 * 0.5 + 0.6 * 0.3 + 0.9 * 0.2) = 0.4 + 0.18 + 0.18 = 0.76
	assert.InDelta(t, 0.76, score, 0.001)
	assert.Equal(t, summary.OverallScore, score)
}

func TestComputeOverallScore_WeightedAverage_Normalized(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.8,
		"task_completion":  0.6,
	}

	// Non-normalized weights (sum to 5.0 instead of 1.0)
	weights := map[string]float64{
		"tool_correctness": 3.0,
		"task_completion":  2.0,
	}

	score := summary.ComputeOverallScore(weights)

	// Normalized: 3.0/5.0 = 0.6, 2.0/5.0 = 0.4
	// (0.8 * 0.6 + 0.6 * 0.4) = 0.48 + 0.24 = 0.72
	assert.InDelta(t, 0.72, score, 0.001)
}

func TestComputeOverallScore_PartialWeights(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.8,
		"task_completion":  0.6,
		"finding_accuracy": 0.9,
	}

	// Only provide weights for subset of scorers
	weights := map[string]float64{
		"tool_correctness": 0.7,
		"task_completion":  0.3,
		// finding_accuracy has no weight, should be excluded
	}

	score := summary.ComputeOverallScore(weights)

	// (0.8 * 0.7 + 0.6 * 0.3) = 0.56 + 0.18 = 0.74
	assert.InDelta(t, 0.74, score, 0.001)
}

func TestComputeOverallScore_EmptyScores(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{}

	score := summary.ComputeOverallScore(nil)

	assert.Equal(t, 0.0, score)
	assert.Equal(t, 0.0, summary.OverallScore)
}

func TestComputeOverallScore_ZeroWeights(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.8,
		"task_completion":  0.6,
	}

	// All weights are zero
	weights := map[string]float64{
		"tool_correctness": 0.0,
		"task_completion":  0.0,
	}

	score := summary.ComputeOverallScore(weights)

	// Should fall back to equal weighting: (0.8 + 0.6) / 2 = 0.7
	assert.InDelta(t, 0.7, score, 0.001)
}

func TestEvalSummary_AddFeedback(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	feedback1 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Alerts: []eval.Alert{
			{Level: eval.AlertWarning, Message: "Low score"},
			{Level: eval.AlertWarning, Message: "Slow progress"},
		},
	}

	feedback2 := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Alerts: []eval.Alert{
			{Level: eval.AlertCritical, Message: "Critical issue"},
		},
	}

	summary.AddFeedback(feedback1)
	assert.Len(t, summary.FeedbackHistory, 1)
	assert.Equal(t, 2, summary.TotalAlerts)
	assert.Equal(t, 2, summary.WarningCount)
	assert.Equal(t, 0, summary.CriticalCount)

	summary.AddFeedback(feedback2)
	assert.Len(t, summary.FeedbackHistory, 2)
	assert.Equal(t, 3, summary.TotalAlerts)
	assert.Equal(t, 2, summary.WarningCount)
	assert.Equal(t, 1, summary.CriticalCount)
}

func TestEvalSummary_AddFeedback_NoAlerts(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 0,
		Alerts:    []eval.Alert{},
	}

	summary.AddFeedback(feedback)
	assert.Len(t, summary.FeedbackHistory, 1)
	assert.Equal(t, 0, summary.TotalAlerts)
	assert.Equal(t, 0, summary.WarningCount)
	assert.Equal(t, 0, summary.CriticalCount)
}

func TestUpdateFromFinalScores(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	scores := map[string]float64{
		"tool_correctness": 0.85,
		"task_completion":  0.75,
		"finding_accuracy": 0.92,
	}

	summary.UpdateFromFinalScores(scores)

	assert.Equal(t, 0.85, summary.ScorerScores["tool_correctness"])
	assert.Equal(t, 0.75, summary.ScorerScores["task_completion"])
	assert.Equal(t, 0.92, summary.ScorerScores["finding_accuracy"])
}

func TestUpdateFromFinalScores_Overwrite(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.5,
	}

	scores := map[string]float64{
		"tool_correctness": 0.85,
		"task_completion":  0.75,
	}

	summary.UpdateFromFinalScores(scores)

	assert.Equal(t, 0.85, summary.ScorerScores["tool_correctness"])
	assert.Equal(t, 0.75, summary.ScorerScores["task_completion"])
}

func TestGetAverageConfidence(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	feedback1 := eval.Feedback{
		Overall: eval.PartialScore{Confidence: 0.8},
	}
	feedback2 := eval.Feedback{
		Overall: eval.PartialScore{Confidence: 0.6},
	}
	feedback3 := eval.Feedback{
		Overall: eval.PartialScore{Confidence: 0.9},
	}

	summary.AddFeedback(feedback1)
	summary.AddFeedback(feedback2)
	summary.AddFeedback(feedback3)

	avgConfidence := summary.GetAverageConfidence()

	// (0.8 + 0.6 + 0.9) / 3 = 0.7666...
	assert.InDelta(t, 0.7666, avgConfidence, 0.001)
}

func TestGetAverageConfidence_NoHistory(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	avgConfidence := summary.GetAverageConfidence()
	assert.Equal(t, 0.0, avgConfidence)
}

func TestHasCriticalAlerts(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	assert.False(t, summary.HasCriticalAlerts())

	feedback := eval.Feedback{
		Alerts: []eval.Alert{
			{Level: eval.AlertCritical, Message: "Critical issue"},
		},
	}

	summary.AddFeedback(feedback)
	assert.True(t, summary.HasCriticalAlerts())
}

func TestHasWarnings(t *testing.T) {
	summary := NewEvalSummary(types.NewID())
	assert.False(t, summary.HasWarnings())

	feedback := eval.Feedback{
		Alerts: []eval.Alert{
			{Level: eval.AlertWarning, Message: "Low score"},
		},
	}

	summary.AddFeedback(feedback)
	assert.True(t, summary.HasWarnings())
}

func TestGetLatestFeedback(t *testing.T) {
	summary := NewEvalSummary(types.NewID())

	// No history initially
	latest := summary.GetLatestFeedback()
	assert.Nil(t, latest)

	// Add feedback
	feedback1 := eval.Feedback{
		StepIndex: 0,
		Overall:   eval.PartialScore{Score: 0.5},
	}
	feedback2 := eval.Feedback{
		StepIndex: 1,
		Overall:   eval.PartialScore{Score: 0.7},
	}
	feedback3 := eval.Feedback{
		StepIndex: 2,
		Overall:   eval.PartialScore{Score: 0.9},
	}

	summary.AddFeedback(feedback1)
	summary.AddFeedback(feedback2)
	summary.AddFeedback(feedback3)

	latest = summary.GetLatestFeedback()
	require.NotNil(t, latest)
	assert.Equal(t, 2, latest.StepIndex)
	assert.Equal(t, 0.9, latest.Overall.Score)
}

func TestEvalSummary_Integration(t *testing.T) {
	// Create a complete evaluation summary with realistic data
	missionID := types.NewID()
	summary := NewEvalSummary(missionID)

	// Set mission metrics
	summary.TotalSteps = 15
	summary.Duration = 5 * time.Minute
	summary.TokensUsed = 12000

	// Add feedback history
	for i := 0; i < 5; i++ {
		feedback := eval.Feedback{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			StepIndex: i * 3,
			Overall: eval.PartialScore{
				Score:      0.6 + float64(i)*0.05,
				Confidence: 0.7 + float64(i)*0.03,
			},
		}

		if i == 2 {
			feedback.Alerts = []eval.Alert{
				{Level: eval.AlertWarning, Message: "Slow progress"},
			}
		}
		if i == 4 {
			feedback.Alerts = []eval.Alert{
				{Level: eval.AlertCritical, Message: "Critical issue detected"},
			}
		}

		summary.AddFeedback(feedback)
	}

	// Update final scores
	scores := map[string]float64{
		"tool_correctness": 0.85,
		"task_completion":  0.75,
		"finding_accuracy": 0.90,
	}
	summary.UpdateFromFinalScores(scores)

	// Compute overall score with weights
	weights := map[string]float64{
		"tool_correctness": 0.4,
		"task_completion":  0.3,
		"finding_accuracy": 0.3,
	}
	overallScore := summary.ComputeOverallScore(weights)

	// Verify results
	assert.Equal(t, missionID, summary.MissionID)
	assert.Equal(t, 15, summary.TotalSteps)
	assert.Equal(t, 5*time.Minute, summary.Duration)
	assert.Equal(t, 12000, summary.TokensUsed)
	assert.Len(t, summary.FeedbackHistory, 5)
	assert.Equal(t, 2, summary.TotalAlerts)
	assert.Equal(t, 1, summary.WarningCount)
	assert.Equal(t, 1, summary.CriticalCount)
	assert.True(t, summary.HasCriticalAlerts())
	assert.True(t, summary.HasWarnings())
	assert.InDelta(t, 0.835, overallScore, 0.001) // 0.85*0.4 + 0.75*0.3 + 0.90*0.3
	assert.Equal(t, overallScore, summary.OverallScore)

	avgConfidence := summary.GetAverageConfidence()
	assert.Greater(t, avgConfidence, 0.7)

	latest := summary.GetLatestFeedback()
	require.NotNil(t, latest)
	assert.Equal(t, 12, latest.StepIndex)
}
