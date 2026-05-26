package eval

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/eval"
)

// EvalSummary represents the complete evaluation results for a mission.
// It aggregates scores, metrics, and feedback history from all evaluation components.
type EvalSummary struct {
	// MissionID is the unique identifier of the evaluated mission.
	MissionID types.ID `json:"mission_id"`

	// OverallScore is the aggregated evaluation score across all scorers (0.0 to 1.0).
	// This is computed from ScorerScores using the configured weights.
	OverallScore float64 `json:"overall_score"`

	// ScorerScores contains individual scores from each scorer, keyed by scorer name.
	// Each score is in the range [0.0, 1.0].
	ScorerScores map[string]float64 `json:"scorer_scores"`

	// TotalSteps is the number of trajectory steps executed during the mission.
	// This includes tool calls, LLM completions, delegations, and other operations.
	TotalSteps int `json:"total_steps"`

	// TotalAlerts is the total number of evaluation alerts generated during execution.
	// This includes both warnings and critical alerts.
	TotalAlerts int `json:"total_alerts"`

	// WarningCount is the number of warning-level alerts generated.
	// Warnings indicate below-expected performance but not critical issues.
	WarningCount int `json:"warning_count"`

	// CriticalCount is the number of critical-level alerts generated.
	// Critical alerts indicate serious performance issues.
	CriticalCount int `json:"critical_count"`

	// Duration is the total time taken for the mission execution.
	Duration time.Duration `json:"duration"`

	// TokensUsed is the total number of LLM tokens consumed during execution.
	// This includes tokens from all LLM calls across all slots.
	TokensUsed int `json:"tokens_used"`

	// FeedbackHistory contains all evaluation feedback generated during execution,
	// ordered chronologically. Each Feedback represents a snapshot of scores and
	// alerts at a specific point in the trajectory.
	FeedbackHistory []eval.Feedback `json:"feedback_history"`
}

// NewEvalSummary creates a new EvalSummary with the given mission ID.
// All numeric fields are initialized to zero, and maps/slices are initialized as empty.
func NewEvalSummary(missionID types.ID) *EvalSummary {
	return &EvalSummary{
		MissionID:       missionID,
		OverallScore:    0.0,
		ScorerScores:    make(map[string]float64),
		TotalSteps:      0,
		TotalAlerts:     0,
		WarningCount:    0,
		CriticalCount:   0,
		Duration:        0,
		TokensUsed:      0,
		FeedbackHistory: []eval.Feedback{},
	}
}

// ComputeOverallScore calculates the overall score from individual scorer scores.
// If weights is nil or empty, all scorers are weighted equally (simple average).
// If weights are provided, only scorers with matching names in the weights map are included.
// Weight values are normalized to sum to 1.0.
//
// This method updates the OverallScore field and returns the computed value.
func (s *EvalSummary) ComputeOverallScore(weights map[string]float64) float64 {
	if len(s.ScorerScores) == 0 {
		s.OverallScore = 0.0
		return 0.0
	}

	// If no weights provided, return simple average
	if len(weights) == 0 {
		var sum float64
		for _, score := range s.ScorerScores {
			sum += score
		}
		s.OverallScore = sum / float64(len(s.ScorerScores))
		return s.OverallScore
	}

	// Normalize weights for scorers that exist in results
	var weightSum float64
	for name, weight := range weights {
		if _, exists := s.ScorerScores[name]; exists {
			weightSum += weight
		}
	}

	if weightSum == 0.0 {
		// No matching scorers or all weights are zero, fall back to equal weighting
		var sum float64
		for _, score := range s.ScorerScores {
			sum += score
		}
		s.OverallScore = sum / float64(len(s.ScorerScores))
		return s.OverallScore
	}

	// Calculate weighted sum
	var weightedSum float64
	for name, score := range s.ScorerScores {
		if weight, hasWeight := weights[name]; hasWeight {
			normalizedWeight := weight / weightSum
			weightedSum += score * normalizedWeight
		}
	}

	s.OverallScore = weightedSum
	return s.OverallScore
}

// AddFeedback appends a feedback entry to the history and updates alert counts.
// This method should be called each time new evaluation feedback is generated
// during mission execution.
func (s *EvalSummary) AddFeedback(feedback eval.Feedback) {
	s.FeedbackHistory = append(s.FeedbackHistory, feedback)

	// Update alert counts
	for _, alert := range feedback.Alerts {
		s.TotalAlerts++
		switch alert.Level {
		case eval.AlertWarning:
			s.WarningCount++
		case eval.AlertCritical:
			s.CriticalCount++
		}
	}
}

// UpdateFromFinalScores updates the scorer scores from a map of final evaluation results.
// This is typically called at the end of mission execution with the complete scores.
func (s *EvalSummary) UpdateFromFinalScores(scores map[string]float64) {
	for name, score := range scores {
		s.ScorerScores[name] = score
	}
}

// GetAverageConfidence computes the average confidence across all feedback in the history.
// Returns 0.0 if there is no feedback history.
func (s *EvalSummary) GetAverageConfidence() float64 {
	if len(s.FeedbackHistory) == 0 {
		return 0.0
	}

	var sum float64
	for _, feedback := range s.FeedbackHistory {
		sum += feedback.Overall.Confidence
	}
	return sum / float64(len(s.FeedbackHistory))
}

// HasCriticalAlerts returns true if any critical alerts were generated during execution.
func (s *EvalSummary) HasCriticalAlerts() bool {
	return s.CriticalCount > 0
}

// HasWarnings returns true if any warning alerts were generated during execution.
func (s *EvalSummary) HasWarnings() bool {
	return s.WarningCount > 0
}

// GetLatestFeedback returns the most recent feedback from the history.
// Returns nil if there is no feedback history.
func (s *EvalSummary) GetLatestFeedback() *eval.Feedback {
	if len(s.FeedbackHistory) == 0 {
		return nil
	}
	return &s.FeedbackHistory[len(s.FeedbackHistory)-1]
}
