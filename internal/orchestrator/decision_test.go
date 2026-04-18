package orchestrator

import (
	"encoding/json"
	"testing"
)

func TestDecisionAction_String(t *testing.T) {
	tests := []struct {
		name   string
		action DecisionAction
		want   string
	}{
		{"execute_agent", ActionExecuteAgent, "execute_agent"},
		{"skip_agent", ActionSkipAgent, "skip_agent"},
		{"modify_params", ActionModifyParams, "modify_params"},
		{"retry", ActionRetry, "retry"},
		{"spawn_agent", ActionSpawnAgent, "spawn_agent"},
		{"complete", ActionComplete, "complete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.String(); got != tt.want {
				t.Errorf("DecisionAction.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecisionAction_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		action DecisionAction
		want   bool
	}{
		{"valid_execute", ActionExecuteAgent, true},
		{"valid_skip", ActionSkipAgent, true},
		{"valid_modify", ActionModifyParams, true},
		{"valid_retry", ActionRetry, true},
		{"valid_spawn", ActionSpawnAgent, true},
		{"valid_complete", ActionComplete, true},
		{"invalid_empty", DecisionAction(""), false},
		{"invalid_unknown", DecisionAction("unknown_action"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.IsValid(); got != tt.want {
				t.Errorf("DecisionAction.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecisionAction_IsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		action DecisionAction
		want   bool
	}{
		{"terminal_complete", ActionComplete, true},
		{"non_terminal_execute", ActionExecuteAgent, false},
		{"non_terminal_skip", ActionSkipAgent, false},
		{"non_terminal_modify", ActionModifyParams, false},
		{"non_terminal_retry", ActionRetry, false},
		{"non_terminal_spawn", ActionSpawnAgent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.IsTerminal(); got != tt.want {
				t.Errorf("DecisionAction.IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecision_Validate(t *testing.T) {
	tests := []struct {
		name     string
		decision *Decision
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "nil_decision",
			decision: nil,
			wantErr:  true,
			errMsg:   "decision is nil",
		},
		{
			name: "missing_reasoning",
			decision: &Decision{
				Action:     ActionExecuteAgent,
				Confidence: 0.9,
			},
			wantErr: true,
			errMsg:  "reasoning is required",
		},
		{
			name: "invalid_action",
			decision: &Decision{
				Reasoning:  "Some reasoning",
				Action:     DecisionAction("invalid"),
				Confidence: 0.9,
			},
			wantErr: true,
			errMsg:  "invalid action",
		},
		{
			name: "confidence_too_low",
			decision: &Decision{
				Reasoning:  "Some reasoning",
				Action:     ActionComplete,
				StopReason: "Done",
				Confidence: -0.1,
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
		{
			name: "confidence_too_high",
			decision: &Decision{
				Reasoning:  "Some reasoning",
				Action:     ActionComplete,
				StopReason: "Done",
				Confidence: 1.5,
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
		{
			name: "execute_agent_missing_target",
			decision: &Decision{
				Reasoning:  "Execute the agent",
				Action:     ActionExecuteAgent,
				Confidence: 0.9,
			},
			wantErr: true,
			errMsg:  "target_node_id is required",
		},
		{
			name: "execute_agent_valid",
			decision: &Decision{
				Reasoning:    "Execute the agent",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   0.9,
			},
			wantErr: false,
		},
		{
			name: "skip_agent_missing_target",
			decision: &Decision{
				Reasoning:  "Skip this agent",
				Action:     ActionSkipAgent,
				Confidence: 0.8,
			},
			wantErr: true,
			errMsg:  "target_node_id is required",
		},
		{
			name: "skip_agent_valid",
			decision: &Decision{
				Reasoning:    "Skip this agent",
				Action:       ActionSkipAgent,
				TargetNodeID: "node-2",
				Confidence:   0.8,
			},
			wantErr: false,
		},
		{
			name: "modify_params_missing_target",
			decision: &Decision{
				Reasoning:     "Modify parameters",
				Action:        ActionModifyParams,
				Modifications: map[string]interface{}{"key": "value"},
				Confidence:    0.85,
			},
			wantErr: true,
			errMsg:  "target_node_id is required",
		},
		{
			name: "modify_params_missing_modifications",
			decision: &Decision{
				Reasoning:    "Modify parameters",
				Action:       ActionModifyParams,
				TargetNodeID: "node-3",
				Confidence:   0.85,
			},
			wantErr: true,
			errMsg:  "modifications are required",
		},
		{
			name: "modify_params_valid",
			decision: &Decision{
				Reasoning:     "Modify parameters",
				Action:        ActionModifyParams,
				TargetNodeID:  "node-3",
				Modifications: map[string]interface{}{"timeout": 30},
				Confidence:    0.85,
			},
			wantErr: false,
		},
		{
			name: "retry_missing_target",
			decision: &Decision{
				Reasoning:  "Retry failed node",
				Action:     ActionRetry,
				Confidence: 0.7,
			},
			wantErr: true,
			errMsg:  "target_node_id is required",
		},
		{
			name: "retry_valid",
			decision: &Decision{
				Reasoning:    "Retry failed node",
				Action:       ActionRetry,
				TargetNodeID: "node-4",
				Confidence:   0.7,
			},
			wantErr: false,
		},
		{
			name: "spawn_agent_missing_config",
			decision: &Decision{
				Reasoning:  "Spawn new agent",
				Action:     ActionSpawnAgent,
				Confidence: 0.95,
			},
			wantErr: true,
			errMsg:  "spawn_config is required",
		},
		{
			name: "spawn_agent_valid",
			decision: &Decision{
				Reasoning:  "Spawn new reconnaissance agent",
				Action:     ActionSpawnAgent,
				Confidence: 0.95,
				SpawnConfig: &SpawnNodeConfig{
					AgentName:   "recon-agent",
					Description: "Gather additional information",
					TaskConfig:  map[string]interface{}{"target": "192.168.1.1"},
					DependsOn:   []string{"node-1"},
				},
			},
			wantErr: false,
		},
		{
			name: "complete_missing_reason",
			decision: &Decision{
				Reasoning:  "All objectives achieved",
				Action:     ActionComplete,
				Confidence: 1.0,
			},
			wantErr: true,
			errMsg:  "stop_reason is required",
		},
		{
			name: "complete_valid",
			decision: &Decision{
				Reasoning:  "All objectives achieved",
				Action:     ActionComplete,
				Confidence: 1.0,
				StopReason: "Successfully completed all mission nodes",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.decision.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Decision.Validate() error = %v, expected to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestSpawnNodeConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *SpawnNodeConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil_config",
			config:  nil,
			wantErr: true,
			errMsg:  "spawn config is nil",
		},
		{
			name: "missing_agent_name",
			config: &SpawnNodeConfig{
				Description: "Test agent",
				TaskConfig:  map[string]interface{}{},
				DependsOn:   []string{},
			},
			wantErr: true,
			errMsg:  "agent_name is required",
		},
		{
			name: "missing_description",
			config: &SpawnNodeConfig{
				AgentName:  "test-agent",
				TaskConfig: map[string]interface{}{},
				DependsOn:  []string{},
			},
			wantErr: true,
			errMsg:  "description is required",
		},
		{
			name: "nil_task_config",
			config: &SpawnNodeConfig{
				AgentName:   "test-agent",
				Description: "Test agent",
				TaskConfig:  nil,
				DependsOn:   []string{},
			},
			wantErr: true,
			errMsg:  "task_config cannot be nil",
		},
		{
			name: "nil_depends_on",
			config: &SpawnNodeConfig{
				AgentName:   "test-agent",
				Description: "Test agent",
				TaskConfig:  map[string]interface{}{},
				DependsOn:   nil,
			},
			wantErr: true,
			errMsg:  "depends_on cannot be nil",
		},
		{
			name: "valid_minimal",
			config: &SpawnNodeConfig{
				AgentName:   "test-agent",
				Description: "Test agent",
				TaskConfig:  map[string]interface{}{},
				DependsOn:   []string{},
			},
			wantErr: false,
		},
		{
			name: "valid_with_data",
			config: &SpawnNodeConfig{
				AgentName:   "exploit-agent",
				Description: "Exploit discovered vulnerability",
				TaskConfig:  map[string]interface{}{"vuln_id": "CVE-2024-1234", "payload": "test"},
				DependsOn:   []string{"recon-1", "scan-1"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SpawnNodeConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("SpawnNodeConfig.Validate() error = %v, expected to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestParseDecision(t *testing.T) {
	tests := []struct {
		name    string
		jsonStr string
		wantErr bool
		errMsg  string
		check   func(*testing.T, *Decision)
	}{
		{
			name:    "empty_string",
			jsonStr: "",
			wantErr: true,
			errMsg:  "empty JSON string",
		},
		{
			name:    "invalid_json",
			jsonStr: `{invalid json}`,
			wantErr: true,
			errMsg:  "failed to extract JSON",
		},
		{
			name:    "valid_execute_agent",
			jsonStr: `{"reasoning":"Execute recon agent","action":"execute_agent","target_node_id":"recon-1","confidence":0.9}`,
			wantErr: false,
			check: func(t *testing.T, d *Decision) {
				if d.Action != ActionExecuteAgent {
					t.Errorf("Expected action execute_agent, got %s", d.Action)
				}
				if d.TargetNodeID != "recon-1" {
					t.Errorf("Expected target_node_id recon-1, got %s", d.TargetNodeID)
				}
				if d.Confidence != 0.9 {
					t.Errorf("Expected confidence 0.9, got %f", d.Confidence)
				}
			},
		},
		{
			name: "valid_spawn_agent",
			jsonStr: `{
				"reasoning": "Need additional scanning",
				"action": "spawn_agent",
				"confidence": 0.85,
				"spawn_config": {
					"agent_name": "port-scanner",
					"description": "Scan discovered hosts",
					"task_config": {"ports": [80, 443]},
					"depends_on": ["recon-1"]
				}
			}`,
			wantErr: false,
			check: func(t *testing.T, d *Decision) {
				if d.Action != ActionSpawnAgent {
					t.Errorf("Expected action spawn_agent, got %s", d.Action)
				}
				if d.SpawnConfig == nil {
					t.Fatal("Expected spawn_config to be present")
				}
				if d.SpawnConfig.AgentName != "port-scanner" {
					t.Errorf("Expected agent_name port-scanner, got %s", d.SpawnConfig.AgentName)
				}
			},
		},
		{
			name:    "valid_complete",
			jsonStr: `{"reasoning":"All nodes completed","action":"complete","confidence":1.0,"stop_reason":"Successfully executed all mission nodes"}`,
			wantErr: false,
			check: func(t *testing.T, d *Decision) {
				if d.Action != ActionComplete {
					t.Errorf("Expected action complete, got %s", d.Action)
				}
				if d.StopReason == "" {
					t.Error("Expected stop_reason to be present")
				}
				if !d.IsTerminal() {
					t.Error("Expected decision to be terminal")
				}
			},
		},
		{
			name:    "invalid_missing_reasoning",
			jsonStr: `{"action":"execute_agent","target_node_id":"node-1","confidence":0.9}`,
			wantErr: true,
			errMsg:  "reasoning is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := ParseDecision(tt.jsonStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDecision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseDecision() error = %v, expected to contain %v", err.Error(), tt.errMsg)
				}
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, decision)
			}
		})
	}
}

func TestDecision_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		decision *Decision
		want     bool
	}{
		{
			name:     "nil_decision",
			decision: nil,
			want:     false,
		},
		{
			name: "terminal_complete",
			decision: &Decision{
				Reasoning:  "Done",
				Action:     ActionComplete,
				StopReason: "All done",
				Confidence: 1.0,
			},
			want: true,
		},
		{
			name: "non_terminal_execute",
			decision: &Decision{
				Reasoning:    "Execute node",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   0.9,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decision.IsTerminal(); got != tt.want {
				t.Errorf("Decision.IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecision_String(t *testing.T) {
	tests := []struct {
		name     string
		decision *Decision
		contains []string
	}{
		{
			name:     "nil_decision",
			decision: nil,
			contains: []string{"<nil decision>"},
		},
		{
			name: "execute_agent",
			decision: &Decision{
				Reasoning:    "Execute the agent",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   0.9,
			},
			contains: []string{"execute_agent", "node-1", "0.90"},
		},
		{
			name: "spawn_agent",
			decision: &Decision{
				Reasoning:  "Spawn new agent",
				Action:     ActionSpawnAgent,
				Confidence: 0.85,
				SpawnConfig: &SpawnNodeConfig{
					AgentName:   "scanner",
					Description: "Port scanner",
					TaskConfig:  map[string]interface{}{},
					DependsOn:   []string{},
				},
			},
			contains: []string{"spawn_agent", "scanner", "0.85"},
		},
		{
			name: "complete",
			decision: &Decision{
				Reasoning:  "Done",
				Action:     ActionComplete,
				StopReason: "All objectives met",
				Confidence: 1.0,
			},
			contains: []string{"complete", "All objectives met", "1.00"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.decision.String()
			for _, substr := range tt.contains {
				if !contains(got, substr) {
					t.Errorf("Decision.String() = %v, expected to contain %v", got, substr)
				}
			}
		})
	}
}

func TestDecision_ToJSON(t *testing.T) {
	tests := []struct {
		name     string
		decision *Decision
		wantErr  bool
	}{
		{
			name:     "nil_decision",
			decision: nil,
			wantErr:  true,
		},
		{
			name: "valid_decision",
			decision: &Decision{
				Reasoning:    "Execute agent",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   0.9,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonStr, err := tt.decision.ToJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decision.ToJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && jsonStr != "" {
				// Verify it's valid JSON
				var parsed Decision
				if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
					t.Errorf("Decision.ToJSON() produced invalid JSON: %v", err)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
