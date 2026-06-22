package queue

import (
	"fmt"
	"time"
)

// AuthzContext carries per-work-item authorization context dispatched by the
// daemon. The run_id is forwarded to the daemon's HarnessCallbackService.Authorize
// RPC so the daemon can resolve the executing user and tenant for FGA checks.
// TTL-expiry enforcement prevents stale work items from executing after the
// mission has finished.
//
// The HMAC signing fields (signature, secret_keyref) have been removed per
// admin-services-completion Requirement 6.4: the HMAC system was dead
// defense-in-depth (no verifier ever existed in the SDK). Authorization is
// fully covered by FGA tuples binding agent_principal to mission. Consumers
// already ignored the fields.
//
// Field layout intentionally mirrors the design doc proto message.
type AuthzContext struct {
	// RunID is the mission run ID that owns this work item.
	// The daemon uses it to resolve user_id and tenant_id for FGA checks.
	RunID string `json:"run_id"`

	// IssuedAt is the Unix timestamp (seconds) when this context was created.
	IssuedAt int64 `json:"issued_at"`

	// TTLSeconds is the number of seconds this context remains valid.
	// Default: 600 (10 minutes). Configurable via authz.work_ttl_seconds.
	TTLSeconds int32 `json:"ttl_seconds"`
}

// WorkItem represents a single unit of work submitted to a tool's queue.
// It contains all necessary information for a worker to execute a tool and return results.
type WorkItem struct {
	// JobID is a UUID that correlates all work items in a batch
	JobID string `json:"job_id"`

	// Index is the position of this item in the batch (0-based)
	Index int `json:"index"`

	// Total is the total number of items in the batch
	Total int `json:"total"`

	// Tool is the name of the tool to execute
	Tool string `json:"tool"`

	// InputJSON is the protocol buffer input message serialized as JSON
	InputJSON string `json:"input_json"`

	// InputType is the fully-qualified protocol buffer message type name
	// Example: "gibson.tools.mytool.v1.ScanRequest"
	InputType string `json:"input_type"`

	// OutputType is the expected protocol buffer output message type name
	// Example: "gibson.tools.mytool.v1.ScanResponse"
	OutputType string `json:"output_type"`

	// TraceID is the distributed tracing trace ID for observability
	TraceID string `json:"trace_id"`

	// SpanID is the distributed tracing span ID for observability
	SpanID string `json:"span_id"`

	// SubmittedAt is the Unix timestamp in milliseconds when work was submitted
	SubmittedAt int64 `json:"submitted_at"`

	// AuthzContext carries the authorization context for this work item.
	// When present, the SDK serve loop verifies the TTL before executing the work.
	// When nil, the work is treated as dev-mode (no authz check).
	AuthzContext *AuthzContext `json:"authz_context,omitempty"`
}

// Result represents the outcome of executing a WorkItem.
// It is published to a job-specific pub/sub channel for the daemon to collect.
type Result struct {
	// JobID correlates this result with the original work item
	JobID string `json:"job_id"`

	// Index is the position of this result in the batch
	Index int `json:"index"`

	// OutputJSON is the protocol buffer output message serialized as JSON
	// Empty if Error is set
	OutputJSON string `json:"output_json,omitempty"`

	// OutputType is the protocol buffer message type name of the output
	OutputType string `json:"output_type"`

	// Error is the error message if execution failed
	// Empty if execution succeeded
	Error string `json:"error,omitempty"`

	// WorkerID is the unique identifier of the worker that processed this item
	WorkerID string `json:"worker_id"`

	// StartedAt is the Unix timestamp in milliseconds when execution started
	StartedAt int64 `json:"started_at"`

	// CompletedAt is the Unix timestamp in milliseconds when execution completed
	CompletedAt int64 `json:"completed_at"`
}

// ToolMeta contains metadata about a registered tool.
// It is stored as a Redis hash and used for tool discovery.
type ToolMeta struct {
	// Name is the unique tool identifier
	Name string `json:"name"`

	// Version is the semantic version of the tool implementation
	Version string `json:"version"`

	// Description is a human-readable description of the tool's purpose
	Description string `json:"description"`

	// InputMessageType is the fully-qualified protocol buffer input message type
	InputMessageType string `json:"input_type"`

	// OutputMessageType is the fully-qualified protocol buffer output message type
	OutputMessageType string `json:"output_type"`

	// Schema is the JSON schema describing the tool's input/output
	Schema string `json:"schema"`

	// Tags are keywords for categorizing the tool (e.g., "discovery", "recon")
	Tags []string `json:"tags"`

	// WorkerCount is the number of active workers for this tool
	// Updated by IncrementWorkerCount/DecrementWorkerCount
	WorkerCount int `json:"worker_count"`

	// FileDescriptorSet is the base64-encoded serialized protobuf FileDescriptorSet
	// containing the tool's input/output proto definitions for schema introspection
	FileDescriptorSet string `json:"file_descriptor_set,omitempty"`
}

// IsValid checks if the WorkItem has all required fields populated correctly.
// Returns an error describing any validation failures.
func (w *WorkItem) IsValid() error {
	if w.JobID == "" {
		return fmt.Errorf("job_id is required")
	}
	if w.Index < 0 {
		return fmt.Errorf("index must be non-negative, got %d", w.Index)
	}
	if w.Total <= 0 {
		return fmt.Errorf("total must be positive, got %d", w.Total)
	}
	if w.Index >= w.Total {
		return fmt.Errorf("index %d is out of bounds for total %d", w.Index, w.Total)
	}
	if w.Tool == "" {
		return fmt.Errorf("tool name is required")
	}
	if w.InputJSON == "" {
		return fmt.Errorf("input_json is required")
	}
	if w.InputType == "" {
		return fmt.Errorf("input_type is required")
	}
	if w.OutputType == "" {
		return fmt.Errorf("output_type is required")
	}
	if w.SubmittedAt <= 0 {
		return fmt.Errorf("submitted_at must be positive, got %d", w.SubmittedAt)
	}
	return nil
}

// Age returns the duration since this work item was submitted.
// Useful for detecting stale work items and computing queue wait time.
func (w *WorkItem) Age() time.Duration {
	if w.SubmittedAt <= 0 {
		return 0
	}
	now := time.Now().UnixMilli()
	return time.Duration(now-w.SubmittedAt) * time.Millisecond
}

// HasError returns true if the result represents a failed execution.
func (r *Result) HasError() bool {
	return r.Error != ""
}

// Duration returns the wall-clock time the worker spent processing this item.
func (r *Result) Duration() time.Duration {
	if r.StartedAt <= 0 || r.CompletedAt <= 0 {
		return 0
	}
	return time.Duration(r.CompletedAt-r.StartedAt) * time.Millisecond
}

// IsValid checks if the Result has all required fields populated correctly.
func (r *Result) IsValid() error {
	if r.JobID == "" {
		return fmt.Errorf("job_id is required")
	}
	if r.Index < 0 {
		return fmt.Errorf("index must be non-negative, got %d", r.Index)
	}
	if r.OutputType == "" {
		return fmt.Errorf("output_type is required")
	}
	if r.WorkerID == "" {
		return fmt.Errorf("worker_id is required")
	}
	if r.StartedAt <= 0 {
		return fmt.Errorf("started_at must be positive, got %d", r.StartedAt)
	}
	if r.CompletedAt <= 0 {
		return fmt.Errorf("completed_at must be positive, got %d", r.CompletedAt)
	}
	if r.CompletedAt < r.StartedAt {
		return fmt.Errorf("completed_at (%d) cannot be before started_at (%d)", r.CompletedAt, r.StartedAt)
	}
	if !r.HasError() && r.OutputJSON == "" {
		return fmt.Errorf("output_json is required when error is empty")
	}
	return nil
}

// IsValid checks if the ToolMeta has all required fields populated correctly.
func (t *ToolMeta) IsValid() error {
	if t.Name == "" {
		return fmt.Errorf("tool name is required")
	}
	if t.Version == "" {
		return fmt.Errorf("version is required")
	}
	if t.InputMessageType == "" {
		return fmt.Errorf("input_type is required")
	}
	if t.OutputMessageType == "" {
		return fmt.Errorf("output_type is required")
	}
	if t.WorkerCount < 0 {
		return fmt.Errorf("worker_count must be non-negative, got %d", t.WorkerCount)
	}
	return nil
}

// SupportsInput checks if this tool accepts the given input type.
func (t *ToolMeta) SupportsInput(inputType string) bool {
	return t.InputMessageType == inputType
}

// HasTag checks if the tool has the specified tag.
func (t *ToolMeta) HasTag(tag string) bool {
	for _, t := range t.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
