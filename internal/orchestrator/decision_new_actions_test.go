package orchestrator

import (
	"testing"
)

// Test that new action constants are valid
func TestNewActions_AreValid(t *testing.T) {
	tests := []struct {
		name   string
		action DecisionAction
		want   bool
	}{
		{"request_approval is valid", ActionRequestApproval, true},
		{"abort is valid", ActionAbort, true},
		{"escalate is valid", ActionEscalate, true},
		{"rollback is valid", ActionRollback, true},
		{"reflect is valid", ActionReflect, true},
		{"recall is valid", ActionRecall, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.IsValid(); got != tt.want {
				t.Errorf("DecisionAction.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test that abort is terminal
func TestActionAbort_IsTerminal(t *testing.T) {
	if !ActionAbort.IsTerminal() {
		t.Error("ActionAbort should be terminal")
	}
}

// Test validation for request_approval
func TestValidate_RequestApproval(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid request_approval",
			d: &Decision{
				Reasoning:       "Need approval for SQL injection",
				Action:          ActionRequestApproval,
				TargetNodeID:    "sqli-test",
				ApprovalContext: "About to test SQL injection",
				Confidence:      0.9,
			},
			wantErr: false,
		},
		{
			name: "missing target_node_id",
			d: &Decision{
				Reasoning:       "Need approval",
				Action:          ActionRequestApproval,
				ApprovalContext: "About to test",
				Confidence:      0.9,
			},
			wantErr: true,
		},
		{
			name: "missing approval_context",
			d: &Decision{
				Reasoning:    "Need approval",
				Action:       ActionRequestApproval,
				TargetNodeID: "node1",
				Confidence:   0.9,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test validation for abort
func TestValidate_Abort(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid abort with critical severity",
			d: &Decision{
				Reasoning:     "Scope violation detected",
				Action:        ActionAbort,
				AbortReason:   "Out of scope access",
				AbortSeverity: "critical",
				Confidence:    1.0,
			},
			wantErr: false,
		},
		{
			name: "valid abort with high severity",
			d: &Decision{
				Reasoning:     "Safety violation",
				Action:        ActionAbort,
				AbortReason:   "Unauthorized access",
				AbortSeverity: "high",
				Confidence:    1.0,
			},
			wantErr: false,
		},
		{
			name: "valid abort with medium severity",
			d: &Decision{
				Reasoning:     "Minor issue",
				Action:        ActionAbort,
				AbortReason:   "Rate limit",
				AbortSeverity: "medium",
				Confidence:    1.0,
			},
			wantErr: false,
		},
		{
			name: "missing abort_reason",
			d: &Decision{
				Reasoning:     "Must stop",
				Action:        ActionAbort,
				AbortSeverity: "critical",
				Confidence:    1.0,
			},
			wantErr: true,
		},
		{
			name: "missing abort_severity",
			d: &Decision{
				Reasoning:   "Must stop",
				Action:      ActionAbort,
				AbortReason: "Out of scope",
				Confidence:  1.0,
			},
			wantErr: true,
		},
		{
			name: "invalid abort_severity",
			d: &Decision{
				Reasoning:     "Must stop",
				Action:        ActionAbort,
				AbortReason:   "Out of scope",
				AbortSeverity: "low",
				Confidence:    1.0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test validation for escalate
func TestValidate_Escalate(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid escalate to human with critical urgency",
			d: &Decision{
				Reasoning:         "Potential zero-day found",
				Action:            ActionEscalate,
				EscalationLevel:   "human",
				EscalationUrgency: "critical",
				EscalationContext: "Found unusual vulnerability",
				Confidence:        0.95,
			},
			wantErr: false,
		},
		{
			name: "valid escalate to senior_agent",
			d: &Decision{
				Reasoning:         "Need expert analysis",
				Action:            ActionEscalate,
				EscalationLevel:   "senior_agent",
				EscalationUrgency: "high",
				EscalationContext: "Complex finding",
				Confidence:        0.8,
			},
			wantErr: false,
		},
		{
			name: "valid escalate to specialist",
			d: &Decision{
				Reasoning:         "Need specialist",
				Action:            ActionEscalate,
				EscalationLevel:   "specialist",
				EscalationUrgency: "normal",
				EscalationContext: "Specific domain needed",
				Confidence:        0.7,
			},
			wantErr: false,
		},
		{
			name: "missing escalation_level",
			d: &Decision{
				Reasoning:         "Need escalation",
				Action:            ActionEscalate,
				EscalationUrgency: "critical",
				EscalationContext: "Help needed",
				Confidence:        0.9,
			},
			wantErr: true,
		},
		{
			name: "invalid escalation_level",
			d: &Decision{
				Reasoning:         "Need escalation",
				Action:            ActionEscalate,
				EscalationLevel:   "manager",
				EscalationUrgency: "critical",
				EscalationContext: "Help needed",
				Confidence:        0.9,
			},
			wantErr: true,
		},
		{
			name: "invalid escalation_urgency",
			d: &Decision{
				Reasoning:         "Need escalation",
				Action:            ActionEscalate,
				EscalationLevel:   "human",
				EscalationUrgency: "urgent",
				EscalationContext: "Help needed",
				Confidence:        0.9,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test validation for rollback
func TestValidate_Rollback(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid rollback with checkpoint_id",
			d: &Decision{
				Reasoning:    "Approach failed",
				Action:       ActionRollback,
				CheckpointID: "checkpoint-123",
				Confidence:   0.8,
			},
			wantErr: false,
		},
		{
			name: "valid rollback with rollback_to_node",
			d: &Decision{
				Reasoning:      "Need to retry",
				Action:         ActionRollback,
				RollbackToNode: "scan-node",
				Confidence:     0.8,
			},
			wantErr: false,
		},
		{
			name: "valid rollback with both",
			d: &Decision{
				Reasoning:      "Need to retry",
				Action:         ActionRollback,
				CheckpointID:   "checkpoint-123",
				RollbackToNode: "scan-node",
				Confidence:     0.8,
			},
			wantErr: false,
		},
		{
			name: "missing both checkpoint_id and rollback_to_node",
			d: &Decision{
				Reasoning:  "Need to retry",
				Action:     ActionRollback,
				Confidence: 0.8,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test validation for reflect
func TestValidate_Reflect(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid reflect with mission scope",
			d: &Decision{
				Reasoning:       "Need to assess strategy",
				Action:          ActionReflect,
				ReflectionScope: "mission",
				Confidence:      0.8,
			},
			wantErr: false,
		},
		{
			name: "valid reflect with recent_decisions scope",
			d: &Decision{
				Reasoning:       "Recent failures",
				Action:          ActionReflect,
				ReflectionScope: "recent_decisions",
				Confidence:      0.8,
			},
			wantErr: false,
		},
		{
			name: "valid reflect with specific_node scope",
			d: &Decision{
				Reasoning:       "Node failed",
				Action:          ActionReflect,
				ReflectionScope: "specific_node",
				Confidence:      0.8,
			},
			wantErr: false,
		},
		{
			name: "missing reflection_scope",
			d: &Decision{
				Reasoning:  "Need reflection",
				Action:     ActionReflect,
				Confidence: 0.8,
			},
			wantErr: true,
		},
		{
			name: "invalid reflection_scope",
			d: &Decision{
				Reasoning:       "Need reflection",
				Action:          ActionReflect,
				ReflectionScope: "global",
				Confidence:      0.8,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test validation for recall
func TestValidate_Recall(t *testing.T) {
	tests := []struct {
		name    string
		d       *Decision
		wantErr bool
	}{
		{
			name: "valid recall from mission tier",
			d: &Decision{
				Reasoning:        "Need prior context",
				Action:           ActionRecall,
				RecallQuery:      "previous scans of 192.168.1.0/24",
				RecallMemoryTier: "mission",
				Confidence:       0.8,
			},
			wantErr: false,
		},
		{
			name: "valid recall from long_term tier",
			d: &Decision{
				Reasoning:        "Check historical data",
				Action:           ActionRecall,
				RecallQuery:      "prior findings for target",
				RecallMemoryTier: "long_term",
				Confidence:       0.8,
			},
			wantErr: false,
		},
		{
			name: "valid recall from both tiers",
			d: &Decision{
				Reasoning:        "Need all context",
				Action:           ActionRecall,
				RecallQuery:      "target information",
				RecallMemoryTier: "both",
				Confidence:       0.8,
			},
			wantErr: false,
		},
		{
			name: "missing recall_query",
			d: &Decision{
				Reasoning:        "Need context",
				Action:           ActionRecall,
				RecallMemoryTier: "mission",
				Confidence:       0.8,
			},
			wantErr: true,
		},
		{
			name: "missing recall_memory_tier",
			d: &Decision{
				Reasoning:   "Need context",
				Action:      ActionRecall,
				RecallQuery: "target info",
				Confidence:  0.8,
			},
			wantErr: true,
		},
		{
			name: "invalid recall_memory_tier",
			d: &Decision{
				Reasoning:        "Need context",
				Action:           ActionRecall,
				RecallQuery:      "target info",
				RecallMemoryTier: "cache",
				Confidence:       0.8,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
