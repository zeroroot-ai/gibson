package agent

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Task represents work assigned to an agent.
// Tasks are the unit of work that agents execute.
type Task struct {
	ID           types.ID       `json:"id"`
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Goal         string         `json:"goal,omitempty"`    // Primary objective for this task
	Context      map[string]any `json:"context,omitempty"` // Additional context metadata (phase, previous findings, etc.)
	Input        map[string]any `json:"input"`             // Deprecated: Use Context instead for new code
	Timeout      time.Duration  `json:"timeout"`
	MissionID    *types.ID      `json:"mission_id,omitempty"`
	ParentTaskID *types.ID      `json:"parent_task_id,omitempty"`
	TargetID     *types.ID      `json:"target_id,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	Priority     int            `json:"priority"` // Higher = more important
	Tags         []string       `json:"tags,omitempty"`
}

// NewTask creates a new task with the given parameters
func NewTask(name, description string, input map[string]any) Task {
	return Task{
		ID:          types.NewID(),
		Name:        name,
		Description: description,
		Input:       input,
		Timeout:     30 * time.Minute, // Default timeout
		CreatedAt:   time.Now(),
		Priority:    0,
		Tags:        []string{},
	}
}

// WithMission sets the mission ID for this task
func (t Task) WithMission(missionID types.ID) Task {
	t.MissionID = &missionID
	return t
}

// WithParent sets the parent task ID for this task
func (t Task) WithParent(parentID types.ID) Task {
	t.ParentTaskID = &parentID
	return t
}

// WithTarget sets the target ID for this task
func (t Task) WithTarget(targetID types.ID) Task {
	t.TargetID = &targetID
	return t
}

// WithTimeout sets the timeout for this task
func (t Task) WithTimeout(timeout time.Duration) Task {
	t.Timeout = timeout
	return t
}

// WithPriority sets the priority for this task
func (t Task) WithPriority(priority int) Task {
	t.Priority = priority
	return t
}

// WithTags sets the tags for this task
func (t Task) WithTags(tags ...string) Task {
	t.Tags = tags
	return t
}

// Result represents the outcome of agent execution
type Result struct {
	TaskID      types.ID       `json:"task_id"`
	Status      ResultStatus   `json:"status"`
	Output      map[string]any `json:"output,omitempty"`
	Findings    []Finding      `json:"findings,omitempty"`
	Error       *ResultError   `json:"error,omitempty"`
	Metrics     TaskMetrics    `json:"metrics"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt time.Time      `json:"completed_at"`
}

// NewResult creates a new result for the given task
func NewResult(taskID types.ID) Result {
	return Result{
		TaskID:    taskID,
		Status:    ResultStatusPending,
		Output:    make(map[string]any),
		Findings:  []Finding{},
		StartedAt: time.Now(),
		Metrics:   TaskMetrics{},
	}
}

// Start marks the result as running
func (r *Result) Start() {
	r.Status = ResultStatusRunning
	r.StartedAt = time.Now()
}

// Complete marks the result as completed with output
func (r *Result) Complete(output map[string]any) {
	r.Status = ResultStatusCompleted
	r.Output = output
	r.CompletedAt = time.Now()
	r.Metrics.Duration = r.CompletedAt.Sub(r.StartedAt)
}

// Fail marks the result as failed with an error
func (r *Result) Fail(err error) {
	r.Status = ResultStatusFailed
	r.Error = &ResultError{
		Message: err.Error(),
		Code:    "EXECUTION_ERROR",
	}
	r.CompletedAt = time.Now()
	r.Metrics.Duration = r.CompletedAt.Sub(r.StartedAt)
}

// Cancel marks the result as cancelled
func (r *Result) Cancel() {
	r.Status = ResultStatusCancelled
	r.CompletedAt = time.Now()
	r.Metrics.Duration = r.CompletedAt.Sub(r.StartedAt)
}

// AddFinding adds a finding to the result
func (r *Result) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
}

// ResultStatus represents the status of a task result
type ResultStatus string

const (
	ResultStatusPending   ResultStatus = "pending"
	ResultStatusRunning   ResultStatus = "running"
	ResultStatusCompleted ResultStatus = "completed"
	ResultStatusFailed    ResultStatus = "failed"
	ResultStatusCancelled ResultStatus = "cancelled"
)

// ResultError contains error information from a failed task
type ResultError struct {
	Message     string         `json:"message"`
	Code        string         `json:"code"`
	Details     map[string]any `json:"details,omitempty"`
	StackTrace  string         `json:"stack_trace,omitempty"`
	Recoverable bool           `json:"recoverable"`
}

// Finding represents a security finding discovered during task execution
type Finding struct {
	ID          types.ID        `json:"id"`
	TenantID    string          `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"` // Multi-tenant isolation
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    FindingSeverity `json:"severity"`
	Confidence  float64         `json:"confidence"` // 0.0 - 1.0
	Category    string          `json:"category"`
	TargetID    *types.ID       `json:"target_id,omitempty"`
	Evidence    []Evidence      `json:"evidence,omitempty"`
	CVSS        *CVSSScore      `json:"cvss,omitempty"`
	CWE         []string        `json:"cwe,omitempty"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// FindingSeverity represents the severity level of a finding
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// Evidence represents evidence supporting a finding
type Evidence struct {
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Data        map[string]any `json:"data"`
	Timestamp   time.Time      `json:"timestamp"`
}

// CVSSScore represents a CVSS scoring
type CVSSScore struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
}

// TaskMetrics contains execution metrics for a task
type TaskMetrics struct {
	Duration      time.Duration  `json:"duration"`
	LLMCalls      int            `json:"llm_calls"`
	ToolCalls     int            `json:"tool_calls"`
	PluginCalls   int            `json:"plugin_calls"`
	TokensUsed    int            `json:"tokens_used"`
	Cost          float64        `json:"cost"` // USD
	FindingsCount int            `json:"findings_count"`
	Errors        int            `json:"errors"`
	Retries       int            `json:"retries"`
	SubTasks      int            `json:"sub_tasks"`
	CustomMetrics map[string]any `json:"custom_metrics,omitempty"`
}

// NewFinding creates a new finding
func NewFinding(title, description string, severity FindingSeverity) Finding {
	return Finding{
		ID:          types.NewID(),
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  1.0,
		Evidence:    []Evidence{},
		CWE:         []string{},
		Metadata:    make(map[string]any),
		CreatedAt:   time.Now(),
	}
}

// WithConfidence sets the confidence level for a finding
func (f Finding) WithConfidence(confidence float64) Finding {
	f.Confidence = confidence
	return f
}

// WithCategory sets the category for a finding
func (f Finding) WithCategory(category string) Finding {
	f.Category = category
	return f
}

// WithEvidence adds evidence to a finding
func (f Finding) WithEvidence(evidence ...Evidence) Finding {
	f.Evidence = append(f.Evidence, evidence...)
	return f
}

// WithCWE sets the CWE IDs for a finding
func (f Finding) WithCWE(cwe ...string) Finding {
	f.CWE = cwe
	return f
}

// WithTarget sets the target ID for a finding
func (f Finding) WithTarget(targetID types.ID) Finding {
	f.TargetID = &targetID
	return f
}

// WithTenant sets the tenant ID for a finding (multi-tenant isolation)
func (f Finding) WithTenant(tenantID string) Finding {
	f.TenantID = tenantID
	return f
}

// NewEvidence creates a new evidence object
func NewEvidence(evidenceType, description string, data map[string]any) Evidence {
	return Evidence{
		Type:        evidenceType,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
	}
}
