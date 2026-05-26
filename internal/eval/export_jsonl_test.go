package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/eval"
)

func TestJSONLEntry_Marshaling(t *testing.T) {
	entry := JSONLEntry{
		Type:      EntryTypeFeedback,
		Timestamp: time.Date(2025, 1, 5, 12, 0, 0, 0, time.UTC),
		Data: eval.Feedback{
			StepIndex: 5,
			Overall: eval.PartialScore{
				Score:      0.8,
				Confidence: 0.9,
			},
		},
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded JSONLEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, EntryTypeFeedback, decoded.Type)
	assert.Equal(t, entry.Timestamp.Unix(), decoded.Timestamp.Unix())
}

func TestWriteJSONL_EmptyCollector(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	var buf bytes.Buffer
	err := WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Should still write a summary entry even if empty
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.GreaterOrEqual(t, len(lines), 1)

	// Last line should be summary
	var lastEntry JSONLEntry
	err = json.Unmarshal([]byte(lines[len(lines)-1]), &lastEntry)
	require.NoError(t, err)
	assert.Equal(t, EntryTypeSummary, lastEntry.Type)
}

func TestWriteJSONL_WithFeedback(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add some feedback
	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall: eval.PartialScore{
			Score:      0.85,
			Confidence: 0.9,
			Action:     eval.ActionContinue,
		},
		Scores: map[string]eval.PartialScore{
			"test_scorer": {
				Score:      0.85,
				Confidence: 0.9,
			},
		},
		Alerts: []eval.Alert{
			{
				Level:     eval.AlertWarning,
				Scorer:    "test_scorer",
				Score:     0.85,
				Threshold: 0.9,
				Message:   "Below threshold",
				Action:    eval.ActionAdjust,
			},
		},
	}

	collector.AddFeedback("test_agent", feedback)

	var buf bytes.Buffer
	err := WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Parse all lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Greater(t, len(lines), 0)

	// Count entry types
	entryTypes := make(map[string]int)
	for _, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err)
		entryTypes[entry.Type]++
	}

	// Should have feedback, trajectory_step, alert, and summary entries
	assert.Greater(t, entryTypes[EntryTypeFeedback], 0)
	assert.Greater(t, entryTypes[EntryTypeTrajectoryStep], 0)
	assert.Greater(t, entryTypes[EntryTypeAlert], 0)
	assert.Equal(t, 1, entryTypes[EntryTypeSummary])
}

func TestWriteJSONL_WithScores(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add final scores
	scores := map[string]float64{
		"tool_correctness": 0.9,
		"task_completion":  0.85,
		"finding_accuracy": 0.95,
	}

	for scorerName, score := range scores {
		err := collector.SetFinalScore(scorerName, eval.ScoreResult{
			Score: score,
		})
		require.NoError(t, err)
	}

	var buf bytes.Buffer
	err := WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Parse all lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	// Count score entries
	scoreCount := 0
	scoreData := make(map[string]float64)

	for _, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err)

		if entry.Type == EntryTypeScore {
			scoreCount++

			// Parse score data
			dataBytes, err := json.Marshal(entry.Data)
			require.NoError(t, err)

			var score ScoreData
			err = json.Unmarshal(dataBytes, &score)
			require.NoError(t, err)

			scoreData[score.ScorerName] = score.Score
		}
	}

	assert.Equal(t, len(scores), scoreCount)
	assert.Equal(t, 0.9, scoreData["tool_correctness"])
	assert.Equal(t, 0.85, scoreData["task_completion"])
	assert.Equal(t, 0.95, scoreData["finding_accuracy"])
}

func TestWriteJSONL_ParseableOutput(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add comprehensive data
	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 3,
		Overall: eval.PartialScore{
			Score:      0.7,
			Confidence: 0.8,
			Action:     eval.ActionAdjust,
			Feedback:   "Consider improving approach",
		},
		Scores: map[string]eval.PartialScore{
			"scorer1": {Score: 0.8, Confidence: 0.9},
			"scorer2": {Score: 0.6, Confidence: 0.7},
		},
		Alerts: []eval.Alert{
			{
				Level:   eval.AlertWarning,
				Scorer:  "scorer2",
				Score:   0.6,
				Message: "Low score",
			},
		},
	}

	collector.AddFeedback("agent1", feedback)
	err := collector.SetFinalScore("final_scorer", eval.ScoreResult{Score: 0.85})
	require.NoError(t, err)

	var buf bytes.Buffer
	err = WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Verify each line is valid JSON
	scanner := bufio.NewScanner(&buf)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		var entry JSONLEntry
		err := json.Unmarshal(scanner.Bytes(), &entry)
		require.NoError(t, err, "Line %d should be valid JSON", lineCount)
		assert.NotEmpty(t, entry.Type)
		assert.False(t, entry.Timestamp.IsZero())
		assert.NotNil(t, entry.Data)
	}

	assert.Greater(t, lineCount, 0)
	require.NoError(t, scanner.Err())
}

func TestExportJSONL_FileCreation(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add some data
	feedback := eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall: eval.PartialScore{
			Score:      0.9,
			Confidence: 0.95,
		},
	}
	collector.AddFeedback("test_agent", feedback)

	// Create temp file path
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "eval-results.jsonl")

	// Export
	err := ExportJSONL(outputPath, collector)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(outputPath)
	require.NoError(t, err)

	// Verify file content
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Greater(t, len(data), 0)

	// Verify it's valid JSONL
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err)
	}
}

func TestExportJSONL_AtomicWrite(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "eval-results.jsonl")

	// Export successfully
	err := ExportJSONL(outputPath, collector)
	require.NoError(t, err)

	// Verify no temp files left behind
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	for _, entry := range entries {
		assert.False(t, strings.Contains(entry.Name(), ".tmp"))
	}
}

func TestExportJSONL_DirectoryCreation(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	tempDir := t.TempDir()
	// Use nested directory that doesn't exist
	outputPath := filepath.Join(tempDir, "nested", "dir", "eval-results.jsonl")

	// Export should create directories
	err := ExportJSONL(outputPath, collector)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
}

func TestExportJSONL_OverwriteExisting(t *testing.T) {
	collector1 := NewEvalResultCollector(types.NewID())
	collector1.AddFeedback("agent1", eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall:   eval.PartialScore{Score: 0.5},
	})

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "eval-results.jsonl")

	// First export
	err := ExportJSONL(outputPath, collector1)
	require.NoError(t, err)

	originalInfo, err := os.Stat(outputPath)
	require.NoError(t, err)

	// Wait to ensure different timestamp
	time.Sleep(10 * time.Millisecond)

	// Second export with different collector
	collector2 := NewEvalResultCollector(types.NewID())
	collector2.AddFeedback("agent2", eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 2,
		Overall:   eval.PartialScore{Score: 0.9},
	})

	err = ExportJSONL(outputPath, collector2)
	require.NoError(t, err)

	newInfo, err := os.Stat(outputPath)
	require.NoError(t, err)

	// File should be updated
	assert.NotEqual(t, originalInfo.ModTime(), newInfo.ModTime())
}

func TestWriteJSONL_MultipleFeedbackEntries(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add multiple feedback entries
	for i := 0; i < 5; i++ {
		feedback := eval.Feedback{
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			StepIndex: i,
			Overall: eval.PartialScore{
				Score:      float64(i) * 0.1,
				Confidence: 0.9,
			},
		}
		collector.AddFeedback("test_agent", feedback)
	}

	var buf bytes.Buffer
	err := WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Count feedback entries
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	feedbackCount := 0

	for _, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err)

		if entry.Type == EntryTypeFeedback {
			feedbackCount++
		}
	}

	assert.Equal(t, 5, feedbackCount)
}

func TestWriteJSONL_SummaryContent(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Add data
	collector.AddFeedback("agent1", eval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall:   eval.PartialScore{Score: 0.8},
		Alerts: []eval.Alert{
			{Level: eval.AlertWarning, Message: "Test"},
		},
	})

	err := collector.SetFinalScore("test_scorer", eval.ScoreResult{Score: 0.85})
	require.NoError(t, err)

	var buf bytes.Buffer
	err = WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Find summary entry
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var summaryEntry JSONLEntry
	found := false

	for _, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err)

		if entry.Type == EntryTypeSummary {
			summaryEntry = entry
			found = true
			break
		}
	}

	require.True(t, found)

	// Parse summary data
	dataBytes, err := json.Marshal(summaryEntry.Data)
	require.NoError(t, err)

	var summary EvalSummary
	err = json.Unmarshal(dataBytes, &summary)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.TotalAlerts)
	assert.Equal(t, 1, summary.WarningCount)
	assert.Greater(t, summary.Duration, time.Duration(0))
}

func TestExportJSONL_InvalidPath(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Try to write to invalid path (file as directory)
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "file")
	err := os.WriteFile(tempFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Try to create file inside what's actually a file
	invalidPath := filepath.Join(tempFile, "subdir", "eval.jsonl")

	err = ExportJSONL(invalidPath, collector)
	assert.Error(t, err)
}

func TestJSONLEntryTypes(t *testing.T) {
	tests := []struct {
		name      string
		entryType string
	}{
		{"trajectory step", EntryTypeTrajectoryStep},
		{"feedback", EntryTypeFeedback},
		{"alert", EntryTypeAlert},
		{"score", EntryTypeScore},
		{"summary", EntryTypeSummary},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.entryType)
		})
	}
}

func TestAlertData_Marshaling(t *testing.T) {
	alertData := AlertData{
		Alert: eval.Alert{
			Level:     eval.AlertCritical,
			Scorer:    "test_scorer",
			Score:     0.1,
			Threshold: 0.2,
			Message:   "Critical failure",
			Action:    eval.ActionAbort,
		},
		StepIndex: 10,
	}

	data, err := json.Marshal(alertData)
	require.NoError(t, err)

	var decoded AlertData
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, eval.AlertCritical, decoded.Alert.Level)
	assert.Equal(t, 10, decoded.StepIndex)
	assert.Equal(t, 0.1, decoded.Alert.Score)
}

func TestTrajectoryStepData_Marshaling(t *testing.T) {
	stepData := TrajectoryStepData{
		StepIndex:    5,
		OverallScore: 0.75,
		Confidence:   0.85,
		Action:       eval.ActionContinue,
	}

	data, err := json.Marshal(stepData)
	require.NoError(t, err)

	var decoded TrajectoryStepData
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 5, decoded.StepIndex)
	assert.Equal(t, 0.75, decoded.OverallScore)
	assert.Equal(t, 0.85, decoded.Confidence)
	assert.Equal(t, eval.ActionContinue, decoded.Action)
}

func TestScoreData_Marshaling(t *testing.T) {
	scoreData := ScoreData{
		ScorerName: "tool_correctness",
		Score:      0.92,
	}

	data, err := json.Marshal(scoreData)
	require.NoError(t, err)

	var decoded ScoreData
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "tool_correctness", decoded.ScorerName)
	assert.Equal(t, 0.92, decoded.Score)
}

func TestWriteJSONL_RealWorldScenario(t *testing.T) {
	collector := NewEvalResultCollector(types.NewID())

	// Simulate a real evaluation with multiple feedback entries over time
	for i := 0; i < 3; i++ {
		feedback := eval.Feedback{
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			StepIndex: i,
			Overall: eval.PartialScore{
				Score:      0.7 + float64(i)*0.1,
				Confidence: 0.85,
				Action:     eval.ActionContinue,
				Feedback:   "Progressing well",
			},
			Scores: map[string]eval.PartialScore{
				"tool_correctness": {Score: 0.9, Confidence: 0.95},
				"task_completion":  {Score: 0.5 + float64(i)*0.2, Confidence: 0.8},
			},
		}

		if i == 1 {
			// Add a warning in the middle
			feedback.Alerts = []eval.Alert{
				{
					Level:     eval.AlertWarning,
					Scorer:    "task_completion",
					Score:     0.7,
					Threshold: 0.75,
					Message:   "Approaching threshold",
					Action:    eval.ActionAdjust,
				},
			}
		}

		collector.AddFeedback("test_agent", feedback)
	}

	// Add final scores
	_ = collector.SetFinalScore("tool_correctness", eval.ScoreResult{Score: 0.92})
	_ = collector.SetFinalScore("task_completion", eval.ScoreResult{Score: 0.88})

	var buf bytes.Buffer
	err := WriteJSONL(&buf, collector)
	require.NoError(t, err)

	// Verify output structure
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Greater(t, len(lines), 5) // At least feedback, steps, scores, and summary

	// Verify all lines are parseable
	for i, line := range lines {
		var entry JSONLEntry
		err := json.Unmarshal([]byte(line), &entry)
		require.NoError(t, err, "Line %d should be valid JSON", i)
	}
}
