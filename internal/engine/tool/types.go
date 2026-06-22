package tool

import (
	"time"
)

// ToolDescriptor contains tool metadata for discovery and introspection.
// It provides all the information needed to understand what a tool does
// and how to interact with it, without requiring tool execution.
type ToolDescriptor struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Version           string   `json:"version"`
	Tags              []string `json:"tags"`
	InputMessageType  string   `json:"input_message_type"`
	OutputMessageType string   `json:"output_message_type"`
	IsExternal        bool     `json:"is_external"`
}

// NewToolDescriptor creates a ToolDescriptor from a Tool interface.
// IsExternal is set to false by default; use NewExternalToolDescriptor for external tools.
func NewToolDescriptor(t Tool) ToolDescriptor {
	return ToolDescriptor{
		Name:              t.Name(),
		Description:       t.Description(),
		Version:           t.Version(),
		Tags:              t.Tags(),
		InputMessageType:  t.InputMessageType(),
		OutputMessageType: t.OutputMessageType(),
		IsExternal:        false,
	}
}

// NewExternalToolDescriptor creates a ToolDescriptor for an external tool.
func NewExternalToolDescriptor(t Tool) ToolDescriptor {
	desc := NewToolDescriptor(t)
	desc.IsExternal = true
	return desc
}

// ToolMetrics tracks tool execution statistics for monitoring and observability.
// Metrics are thread-safe and updated automatically by the registry during execution.
type ToolMetrics struct {
	TotalCalls     int64         `json:"total_calls"`
	SuccessCalls   int64         `json:"success_calls"`
	FailedCalls    int64         `json:"failed_calls"`
	TotalDuration  time.Duration `json:"total_duration"`
	AvgDuration    time.Duration `json:"avg_duration"`
	LastExecutedAt *time.Time    `json:"last_executed_at,omitempty"`
}

// NewToolMetrics creates a new ToolMetrics instance with zero values
func NewToolMetrics() *ToolMetrics {
	return &ToolMetrics{}
}

// RecordSuccess records a successful tool execution with the given duration.
// Updates total calls, success calls, duration statistics, and last executed timestamp.
func (m *ToolMetrics) RecordSuccess(duration time.Duration) {
	m.TotalCalls++
	m.SuccessCalls++
	m.TotalDuration += duration
	m.AvgDuration = m.TotalDuration / time.Duration(m.TotalCalls)
	now := time.Now()
	m.LastExecutedAt = &now
}

// RecordFailure records a failed tool execution with the given duration.
// Updates total calls, failed calls, duration statistics, and last executed timestamp.
func (m *ToolMetrics) RecordFailure(duration time.Duration) {
	m.TotalCalls++
	m.FailedCalls++
	m.TotalDuration += duration
	m.AvgDuration = m.TotalDuration / time.Duration(m.TotalCalls)
	now := time.Now()
	m.LastExecutedAt = &now
}

// SuccessRate returns the success rate as a float64 between 0.0 and 1.0.
// Returns 0.0 if no calls have been made.
func (m *ToolMetrics) SuccessRate() float64 {
	if m.TotalCalls == 0 {
		return 0.0
	}
	return float64(m.SuccessCalls) / float64(m.TotalCalls)
}

// FailureRate returns the failure rate as a float64 between 0.0 and 1.0.
// Returns 0.0 if no calls have been made.
func (m *ToolMetrics) FailureRate() float64 {
	if m.TotalCalls == 0 {
		return 0.0
	}
	return float64(m.FailedCalls) / float64(m.TotalCalls)
}
