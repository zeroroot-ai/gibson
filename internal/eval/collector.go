package eval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/eval"
)

// EvalResultCollector aggregates evaluation results from multiple agents during mission execution.
// It is thread-safe and collects trajectories, feedback, scores, and alerts from FeedbackHarnesses.
type EvalResultCollector struct {
	mu sync.Mutex

	// missionID is the unique identifier for this mission
	missionID types.ID

	// startTime is when the collector was created (mission start)
	startTime time.Time

	// trajectories tracks the execution path for each agent
	// Key: agent name, Value: trajectory
	trajectories map[string]*eval.Trajectory

	// feedbackHist stores all feedback entries for each agent
	// Key: agent name, Value: ordered list of feedback
	feedbackHist map[string][]eval.Feedback

	// harnesses tracks registered harnesses for final result collection
	// Key: agent name, Value: feedback harness
	harnesses map[string]*eval.FeedbackHarness

	// finalScores stores the final score from each scorer
	// Key: scorer name, Value: final score result
	finalScores map[string]eval.ScoreResult

	// alerts stores all evaluation alerts generated during execution
	alerts []eval.Alert

	// totalTokens tracks total token usage across all agents
	totalTokens int
}

// NewEvalResultCollector creates a new collector for the given mission.
// The collector starts tracking from the current time.
func NewEvalResultCollector(missionID types.ID) *EvalResultCollector {
	return &EvalResultCollector{
		missionID:    missionID,
		startTime:    time.Now(),
		trajectories: make(map[string]*eval.Trajectory),
		feedbackHist: make(map[string][]eval.Feedback),
		harnesses:    make(map[string]*eval.FeedbackHarness),
		finalScores:  make(map[string]eval.ScoreResult),
		alerts:       []eval.Alert{},
		totalTokens:  0,
	}
}

// RegisterHarness registers a FeedbackHarness for an agent.
// This allows the collector to extract trajectory and feedback history during finalization.
// The agentName must be unique; registering the same agent twice will overwrite the previous harness.
func (c *EvalResultCollector) RegisterHarness(agentName string, h *eval.FeedbackHarness) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.harnesses[agentName] = h
}

// RegisterFeedbackHarness is an alias for RegisterHarness for backwards compatibility.
func (c *EvalResultCollector) RegisterFeedbackHarness(agentName string, h *eval.FeedbackHarness) {
	c.RegisterHarness(agentName, h)
}

// AddTrajectoryStep adds a single step to an agent's trajectory.
// If the trajectory doesn't exist for this agent, a new one is created.
// This method is thread-safe and can be called concurrently from multiple agents.
func (c *EvalResultCollector) AddTrajectoryStep(agentName string, step eval.TrajectoryStep) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or create trajectory for this agent
	trajectory, exists := c.trajectories[agentName]
	if !exists {
		trajectory = &eval.Trajectory{
			Steps:     []eval.TrajectoryStep{},
			StartTime: time.Now(),
		}
		c.trajectories[agentName] = trajectory
	}

	// Append the step
	trajectory.Steps = append(trajectory.Steps, step)
	trajectory.EndTime = time.Now()
}

// AddFeedback appends feedback to an agent's feedback history.
// This method also extracts and stores any alerts from the feedback.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) AddFeedback(agentName string, feedback eval.Feedback) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Append to history
	c.feedbackHist[agentName] = append(c.feedbackHist[agentName], feedback)

	// Extract and store alerts
	for _, alert := range feedback.Alerts {
		c.alerts = append(c.alerts, alert)
	}
}

// AddAlert adds a standalone evaluation alert to the collector.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) AddAlert(alert eval.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.alerts = append(c.alerts, alert)
}

// Finalize computes the final evaluation summary by collecting all data from registered harnesses
// and calculating aggregate metrics. This should be called once at the end of mission execution.
//
// The method:
// 1. Collects trajectories and feedback from all registered harnesses
// 2. Computes final scores from all scorers
// 3. Aggregates metrics (steps, tokens, alerts)
// 4. Returns a complete EvalSummary
//
// This method is NOT thread-safe with respect to other Finalize calls, but is safe with
// respect to Add* methods. It should only be called once per mission.
func (c *EvalResultCollector) Finalize(ctx context.Context) (*EvalSummary, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	summary := NewEvalSummary(c.missionID)

	// Collect trajectories and feedback from registered harnesses
	for agentName, harness := range c.harnesses {
		// Get trajectory from RecordingHarness
		trajectory := harness.RecordingHarness().Trajectory()
		c.trajectories[agentName] = &trajectory

		// Get feedback history
		feedbackHistory := harness.FeedbackHistory()
		c.feedbackHist[agentName] = feedbackHistory

		// Extract alerts from feedback
		for _, feedback := range feedbackHistory {
			for _, alert := range feedback.Alerts {
				// Check if alert already exists to avoid duplicates
				found := false
				for _, existingAlert := range c.alerts {
					if existingAlert.Scorer == alert.Scorer &&
						existingAlert.Score == alert.Score &&
						existingAlert.Level == alert.Level &&
						existingAlert.Message == alert.Message {
						found = true
						break
					}
				}
				if !found {
					c.alerts = append(c.alerts, alert)
				}
			}
		}

		// Track token usage from the harness
		tokenTracker := harness.TokenUsage()
		if tokenTracker != nil {
			usage := tokenTracker.Total()
			c.totalTokens += usage.TotalTokens
		}
	}

	// Aggregate all feedback history from all agents
	var allFeedback []eval.Feedback
	for _, agentFeedback := range c.feedbackHist {
		allFeedback = append(allFeedback, agentFeedback...)
	}
	summary.FeedbackHistory = allFeedback

	// Count total steps across all trajectories
	totalSteps := 0
	for _, trajectory := range c.trajectories {
		totalSteps += len(trajectory.Steps)
	}
	summary.TotalSteps = totalSteps

	// Set token usage
	summary.TokensUsed = c.totalTokens

	// Compute alert counts
	summary.TotalAlerts = len(c.alerts)
	for _, alert := range c.alerts {
		switch alert.Level {
		case eval.AlertWarning:
			summary.WarningCount++
		case eval.AlertCritical:
			summary.CriticalCount++
		}
	}

	// Calculate duration
	summary.Duration = time.Since(c.startTime)

	// Compute final scores
	// For each registered harness, run final scoring if scorers are available
	scorerResults := make(map[string]float64)

	// If we have final scores stored, use those
	if len(c.finalScores) > 0 {
		for scorerName, scoreResult := range c.finalScores {
			scorerResults[scorerName] = scoreResult.Score
		}
	} else {
		// Otherwise, use the latest feedback scores from each agent
		// This aggregates the most recent scores across all agents
		scorerScores := make(map[string][]float64)

		for _, feedbackList := range c.feedbackHist {
			if len(feedbackList) > 0 {
				// Get the latest feedback for this agent
				latestFeedback := feedbackList[len(feedbackList)-1]

				// Extract individual scorer scores
				for scorerName, partialScore := range latestFeedback.Scores {
					scorerScores[scorerName] = append(scorerScores[scorerName], partialScore.Score)
				}
			}
		}

		// Average scores across agents for each scorer
		for scorerName, scores := range scorerScores {
			if len(scores) > 0 {
				var sum float64
				for _, score := range scores {
					sum += score
				}
				scorerResults[scorerName] = sum / float64(len(scores))
			}
		}
	}

	// Update summary with scorer scores
	summary.UpdateFromFinalScores(scorerResults)

	// Compute overall score (equal weighting by default)
	summary.ComputeOverallScore(nil)

	return summary, nil
}

// GetSummary returns a snapshot of the current evaluation state without blocking.
// This is safe to call concurrently with other operations and is suitable for real-time
// display in the TUI. The returned summary reflects the current state but may not be
// complete if the mission is still running.
//
// Unlike Finalize, this method:
// - Does NOT collect from harnesses (uses already-collected data only)
// - Can be called multiple times safely
// - Returns partial results suitable for progress display
func (c *EvalResultCollector) GetSummary() *EvalSummary {
	c.mu.Lock()
	defer c.mu.Unlock()

	summary := NewEvalSummary(c.missionID)

	// Aggregate all feedback history
	var allFeedback []eval.Feedback
	for _, agentFeedback := range c.feedbackHist {
		allFeedback = append(allFeedback, agentFeedback...)
	}
	summary.FeedbackHistory = allFeedback

	// Count total steps
	totalSteps := 0
	for _, trajectory := range c.trajectories {
		totalSteps += len(trajectory.Steps)
	}
	summary.TotalSteps = totalSteps

	// Set token usage
	summary.TokensUsed = c.totalTokens

	// Set alert counts
	summary.TotalAlerts = len(c.alerts)
	for _, alert := range c.alerts {
		switch alert.Level {
		case eval.AlertWarning:
			summary.WarningCount++
		case eval.AlertCritical:
			summary.CriticalCount++
		}
	}

	// Calculate duration so far
	summary.Duration = time.Since(c.startTime)

	// Use final scores if available, otherwise get latest scores from feedback
	scorerResults := make(map[string]float64)

	if len(c.finalScores) > 0 {
		// Use final scores if they've been set
		for scorerName, scoreResult := range c.finalScores {
			scorerResults[scorerName] = scoreResult.Score
		}
	} else {
		// Fall back to latest feedback scores
		scorerScores := make(map[string][]float64)

		for _, feedbackList := range c.feedbackHist {
			if len(feedbackList) > 0 {
				latestFeedback := feedbackList[len(feedbackList)-1]

				for scorerName, partialScore := range latestFeedback.Scores {
					scorerScores[scorerName] = append(scorerScores[scorerName], partialScore.Score)
				}
			}
		}

		// Average scores across agents for each scorer
		for scorerName, scores := range scorerScores {
			if len(scores) > 0 {
				var sum float64
				for _, score := range scores {
					sum += score
				}
				scorerResults[scorerName] = sum / float64(len(scores))
			}
		}
	}

	// Update summary with scores
	summary.UpdateFromFinalScores(scorerResults)

	// Compute overall score
	summary.ComputeOverallScore(nil)

	return summary
}

// SetFinalScore stores a final score from a scorer.
// This is typically called after mission completion when final evaluation is performed.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) SetFinalScore(scorerName string, result eval.ScoreResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Validate score
	if err := eval.ValidateScore(result.Score); err != nil {
		return fmt.Errorf("invalid score for scorer %s: %w", scorerName, err)
	}

	c.finalScores[scorerName] = result
	return nil
}

// GetTrajectory returns the trajectory for a specific agent.
// Returns nil if no trajectory exists for the agent.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) GetTrajectory(agentName string) *eval.Trajectory {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.trajectories[agentName]
}

// GetFeedbackHistory returns the feedback history for a specific agent.
// Returns an empty slice if no feedback exists for the agent.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) GetFeedbackHistory(agentName string) []eval.Feedback {
	c.mu.Lock()
	defer c.mu.Unlock()

	history := c.feedbackHist[agentName]
	if history == nil {
		return []eval.Feedback{}
	}

	// Return a copy to prevent external modification
	result := make([]eval.Feedback, len(history))
	copy(result, history)
	return result
}

// GetAlerts returns all alerts collected so far.
// Returns a copy to prevent external modification.
// Thread-safe for concurrent access.
func (c *EvalResultCollector) GetAlerts() []eval.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()

	alerts := make([]eval.Alert, len(c.alerts))
	copy(alerts, c.alerts)
	return alerts
}
