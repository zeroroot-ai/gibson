package guardrail

import (
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// GuardrailInput represents input to be checked by a guardrail
type GuardrailInput struct {
	Content        string                  `json:"content"`
	ToolName       string                  `json:"tool_name,omitempty"`
	ToolInput      map[string]any          `json:"tool_input,omitempty"`
	AgentName      string                  `json:"agent_name,omitempty"`
	MissionContext *harness.MissionContext `json:"mission_context,omitempty"`
	TargetInfo     *harness.TargetInfo     `json:"target_info,omitempty"`
	Metadata       map[string]any          `json:"metadata,omitempty"`
}

// GuardrailOutput represents output to be checked by a guardrail
type GuardrailOutput struct {
	Content    string          `json:"content"`
	ToolOutput map[string]any  `json:"tool_output,omitempty"`
	Findings   []agent.Finding `json:"findings,omitempty"`
	Metadata   map[string]any  `json:"metadata,omitempty"`
}

// GuardrailAction defines the action taken by a guardrail
type GuardrailAction string

const (
	GuardrailActionAllow  GuardrailAction = "allow"
	GuardrailActionBlock  GuardrailAction = "block"
	GuardrailActionRedact GuardrailAction = "redact"
	GuardrailActionWarn   GuardrailAction = "warn"
)

// GuardrailResult represents the result of a guardrail check
type GuardrailResult struct {
	Action          GuardrailAction `json:"action"`
	Reason          string          `json:"reason,omitempty"`
	ModifiedContent string          `json:"modified_content,omitempty"`
	Metadata        map[string]any  `json:"metadata,omitempty"`
}

// IsBlocked returns true if the action is block
func (r GuardrailResult) IsBlocked() bool {
	return r.Action == GuardrailActionBlock
}

// IsRedact returns true if the action is redact
func (r GuardrailResult) IsRedact() bool {
	return r.Action == GuardrailActionRedact
}

// AllowContinue returns true if execution should continue (allow or warn)
func (r GuardrailResult) AllowContinue() bool {
	return r.Action == GuardrailActionAllow || r.Action == GuardrailActionWarn
}

// NewAllowResult creates a result that allows the operation
func NewAllowResult() GuardrailResult {
	return GuardrailResult{
		Action:   GuardrailActionAllow,
		Metadata: make(map[string]any),
	}
}

// NewBlockResult creates a result that blocks the operation
func NewBlockResult(reason string) GuardrailResult {
	return GuardrailResult{
		Action:   GuardrailActionBlock,
		Reason:   reason,
		Metadata: make(map[string]any),
	}
}

// NewRedactResult creates a result that redacts the content
func NewRedactResult(reason, modifiedContent string) GuardrailResult {
	return GuardrailResult{
		Action:          GuardrailActionRedact,
		Reason:          reason,
		ModifiedContent: modifiedContent,
		Metadata:        make(map[string]any),
	}
}

// NewWarnResult creates a result that warns but allows the operation
func NewWarnResult(reason string) GuardrailResult {
	return GuardrailResult{
		Action:   GuardrailActionWarn,
		Reason:   reason,
		Metadata: make(map[string]any),
	}
}

// AllowResult is a helper function to create an allow result (alias for NewAllowResult)
func AllowResult(reason string) GuardrailResult {
	result := NewAllowResult()
	if reason != "" {
		result.Reason = reason
	}
	return result
}

// BlockResult is a helper function to create a block result (alias for NewBlockResult)
func BlockResult(reason string) GuardrailResult {
	return NewBlockResult(reason)
}

// RedactResult is a helper function to create a redact result (alias for NewRedactResult)
func RedactResult(reason, modifiedContent string) GuardrailResult {
	return NewRedactResult(reason, modifiedContent)
}

// WarnResult is a helper function to create a warn result (alias for NewWarnResult)
func WarnResult(reason string) GuardrailResult {
	return NewWarnResult(reason)
}
