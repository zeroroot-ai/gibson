// Package eval provides evaluation and scoring functionality for Gibson missions.
//
// This package integrates the SDK's evaluation framework (github.com/zeroroot-ai/sdk/eval)
// into the Gibson runtime, enabling real-time agent performance assessment and feedback.
//
// # Overview
//
// The eval package provides data structures and utilities for:
//
//   - Aggregating evaluation results across multiple scorers
//   - Tracking feedback history during mission execution
//   - Computing weighted overall scores
//   - Managing alert counts and severity levels
//   - Persisting evaluation summaries for post-mission analysis
//
// # Key Components
//
// EvalSummary is the primary data structure that aggregates all evaluation
// results for a mission. It includes:
//
//   - Individual scorer scores with flexible weighting
//   - Real-time feedback history with alerts
//   - Mission metrics (steps, tokens, duration)
//   - Helper methods for score computation and analysis
//
// # Usage Example
//
//	// Create a new evaluation summary
//	missionID := types.NewID()
//	summary := eval.NewEvalSummary(missionID)
//
//	// Add feedback as the mission progresses
//	feedback := eval.Feedback{
//	    Timestamp: time.Now(),
//	    StepIndex: 5,
//	    Overall: eval.PartialScore{
//	        Score:      0.85,
//	        Confidence: 0.9,
//	    },
//	    Alerts: []eval.Alert{
//	        {Level: eval.AlertWarning, Message: "Minor issue"},
//	    },
//	}
//	summary.AddFeedback(feedback)
//
//	// Update final scores after mission completion
//	scores := map[string]float64{
//	    "tool_correctness": 0.90,
//	    "task_completion":  0.85,
//	    "finding_accuracy": 0.95,
//	}
//	summary.UpdateFromFinalScores(scores)
//
//	// Compute weighted overall score
//	weights := map[string]float64{
//	    "tool_correctness": 0.4,
//	    "task_completion":  0.3,
//	    "finding_accuracy": 0.3,
//	}
//	overallScore := summary.ComputeOverallScore(weights)
//
// # Integration with SDK
//
// This package uses types from github.com/zeroroot-ai/sdk/eval including:
//
//   - eval.Feedback: Real-time evaluation feedback
//   - eval.Alert: Threshold breach notifications
//   - eval.PartialScore: Streaming evaluation results
//
// These SDK types are embedded in the EvalSummary to maintain compatibility
// with the broader evaluation ecosystem.
package eval
