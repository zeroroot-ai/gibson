package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zeroroot-ai/sdk/eval"
)

// JSONLEntry represents a single line in the JSONL export.
// Each entry has a type and timestamp for easy parsing and filtering.
type JSONLEntry struct {
	// Type indicates the kind of data in this entry
	Type string `json:"type"`

	// Timestamp is when this entry was created
	Timestamp time.Time `json:"timestamp"`

	// Data contains the actual payload (structure varies by type)
	Data any `json:"data"`
}

// Entry types for JSONL export
const (
	EntryTypeTrajectoryStep = "trajectory_step"
	EntryTypeFeedback       = "feedback"
	EntryTypeAlert          = "alert"
	EntryTypeScore          = "score"
	EntryTypeSummary        = "summary"
)

// ExportJSONL exports evaluation results to a JSONL file at the specified path.
// Each line contains a JSON object with type, timestamp, and data fields.
// Uses atomic write pattern (write to temp file, then rename).
//
// The export includes:
//   - trajectory_step: Individual steps from feedback history
//   - feedback: Complete feedback entries with scores
//   - alert: Individual alert entries
//   - score: Final scorer scores
//   - summary: Overall evaluation summary
func ExportJSONL(path string, collector *EvalResultCollector) error {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create temporary file for atomic write
	tempFile, err := os.CreateTemp(dir, ".eval-*.jsonl.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()

	// Ensure cleanup of temp file on error
	defer func() {
		if tempFile != nil {
			tempFile.Close()
			os.Remove(tempPath)
		}
	}()

	// Write JSONL content to temp file
	if err := WriteJSONL(tempFile, collector); err != nil {
		return err
	}

	// Close temp file before rename
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Atomic rename to final path
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tempPath, path, err)
	}

	// Prevent deferred cleanup from removing the successfully renamed file
	tempFile = nil

	return nil
}

// WriteJSONL writes evaluation results to the provided writer in JSONL format.
// This is the core export logic, separated for easier testing.
// Each line is a complete JSON object that can be parsed independently.
func WriteJSONL(w io.Writer, collector *EvalResultCollector) error {
	encoder := json.NewEncoder(w)

	// Get snapshot of collector state
	summary := collector.GetSummary()
	allAlerts := collector.GetAlerts()

	// Write feedback history entries
	// Each feedback includes scores, alerts, and recommendations
	for _, feedback := range summary.FeedbackHistory {
		entry := JSONLEntry{
			Type:      EntryTypeFeedback,
			Timestamp: feedback.Timestamp,
			Data:      feedback,
		}

		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("failed to encode feedback entry: %w", err)
		}

		// Export trajectory step reference from this feedback
		stepEntry := JSONLEntry{
			Type:      EntryTypeTrajectoryStep,
			Timestamp: feedback.Timestamp,
			Data: TrajectoryStepData{
				StepIndex:    feedback.StepIndex,
				OverallScore: feedback.Overall.Score,
				Confidence:   feedback.Overall.Confidence,
				Action:       feedback.Overall.Action,
			},
		}

		if err := encoder.Encode(stepEntry); err != nil {
			return fmt.Errorf("failed to encode trajectory step entry: %w", err)
		}
	}

	// Write all alerts (deduplicated by collector)
	for _, alert := range allAlerts {
		alertEntry := JSONLEntry{
			Type:      EntryTypeAlert,
			Timestamp: time.Now(),
			Data: AlertData{
				Alert:     alert,
				StepIndex: -1, // Unknown step index for aggregated alerts
			},
		}

		if err := encoder.Encode(alertEntry); err != nil {
			return fmt.Errorf("failed to encode alert entry: %w", err)
		}
	}

	// Write final scorer scores
	for scorerName, score := range summary.ScorerScores {
		scoreEntry := JSONLEntry{
			Type:      EntryTypeScore,
			Timestamp: time.Now(),
			Data: ScoreData{
				ScorerName: scorerName,
				Score:      score,
			},
		}

		if err := encoder.Encode(scoreEntry); err != nil {
			return fmt.Errorf("failed to encode score entry for scorer %s: %w", scorerName, err)
		}
	}

	// Write final summary
	summaryEntry := JSONLEntry{
		Type:      EntryTypeSummary,
		Timestamp: time.Now(),
		Data:      summary,
	}

	if err := encoder.Encode(summaryEntry); err != nil {
		return fmt.Errorf("failed to encode summary entry: %w", err)
	}

	return nil
}

// AlertData contains alert information with context.
type AlertData struct {
	Alert     eval.Alert `json:"alert"`
	StepIndex int        `json:"step_index"`
}

// TrajectoryStepData contains high-level trajectory step information.
// This provides a quick overview of the trajectory without full details.
type TrajectoryStepData struct {
	StepIndex    int                    `json:"step_index"`
	OverallScore float64                `json:"overall_score"`
	Confidence   float64                `json:"confidence"`
	Action       eval.RecommendedAction `json:"action"`
}

// ScoreData contains final scorer results.
type ScoreData struct {
	ScorerName string  `json:"scorer_name"`
	Score      float64 `json:"score"`
}
