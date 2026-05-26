package observability

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
)

func TestMissionAttributes(t *testing.T) {
	tests := []struct {
		name    string
		mission harness.MissionContext
		want    map[string]any
	}{
		{
			name: "basic mission",
			mission: harness.NewMissionContext(
				types.NewID(),
				"test-mission",
				"agent-1",
			),
			want: map[string]any{
				GibsonMissionName: "test-mission",
				GibsonAgentName:   "agent-1",
			},
		},
		{
			name: "mission with phase",
			mission: harness.NewMissionContext(
				types.NewID(),
				"recon-mission",
				"recon-agent",
			).WithPhase("discovery"),
			want: map[string]any{
				GibsonMissionName:      "recon-mission",
				GibsonAgentName:        "recon-agent",
				"gibson.mission.phase": "discovery",
			},
		},
		{
			name: "mission with empty agent",
			mission: harness.MissionContext{
				ID:           types.NewID(),
				Name:         "solo-mission",
				CurrentAgent: "",
			},
			want: map[string]any{
				GibsonMissionName: "solo-mission",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := MissionAttributes(tt.mission)

			// Convert to map, checking for ID separately
			got := make(map[string]any)
			for _, attr := range attrs {
				key := string(attr.Key)
				if key != GibsonMissionID {
					got[key] = attr.Value.AsInterface()
				} else {
					// Just verify ID exists and is non-empty
					assert.NotEmpty(t, attr.Value.AsString())
				}
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAgentAttributes(t *testing.T) {
	tests := []struct {
		name      string
		agentName string
		version   string
		want      map[string]any
	}{
		{
			name:      "agent with version",
			agentName: "scanner-agent",
			version:   "1.0.0",
			want: map[string]any{
				GibsonAgentName:    "scanner-agent",
				GibsonAgentVersion: "1.0.0",
			},
		},
		{
			name:      "agent without version",
			agentName: "recon-agent",
			version:   "",
			want: map[string]any{
				GibsonAgentName: "recon-agent",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := AgentAttributes(tt.agentName, tt.version)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFindingAttributes(t *testing.T) {
	targetID := types.NewID()

	tests := []struct {
		name    string
		finding agent.Finding
		want    map[string]any
	}{
		{
			name: "critical finding with category",
			finding: agent.NewFinding(
				"SQL Injection",
				"Vulnerable to SQL injection",
				agent.SeverityCritical,
			).WithCategory("injection").WithTarget(targetID),
			want: map[string]any{
				GibsonFindingSeverity:       "critical",
				GibsonFindingCategory:       "injection",
				"gibson.finding.target_id":  targetID.String(),
				"gibson.finding.confidence": 1.0,
			},
		},
		{
			name: "medium finding without category",
			finding: agent.NewFinding(
				"Weak Password",
				"Password strength is low",
				agent.SeverityMedium,
			).WithConfidence(0.75),
			want: map[string]any{
				GibsonFindingSeverity:       "medium",
				"gibson.finding.confidence": 0.75,
			},
		},
		{
			name: "info finding",
			finding: agent.NewFinding(
				"Open Port",
				"Port 80 is open",
				agent.SeverityInfo,
			).WithCategory("network"),
			want: map[string]any{
				GibsonFindingSeverity:       "info",
				GibsonFindingCategory:       "network",
				"gibson.finding.confidence": 1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := FindingAttributes(tt.finding)

			// Convert to map, checking for ID separately
			got := make(map[string]any)
			for _, attr := range attrs {
				key := string(attr.Key)
				if key != GibsonFindingID {
					got[key] = attr.Value.AsInterface()
				} else {
					// Just verify ID exists and is non-empty
					assert.NotEmpty(t, attr.Value.AsString())
				}
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToolAttributes(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     map[string]any
	}{
		{
			name:     "nmap tool",
			toolName: "nmap",
			want: map[string]any{
				GibsonToolName: "nmap",
			},
		},
		{
			name:     "metasploit tool",
			toolName: "metasploit",
			want: map[string]any{
				GibsonToolName: "metasploit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ToolAttributes(tt.toolName)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPluginAttributes(t *testing.T) {
	tests := []struct {
		name       string
		pluginName string
		method     string
		want       map[string]any
	}{
		{
			name:       "plugin with method",
			pluginName: "scanner",
			method:     "ScanPort",
			want: map[string]any{
				GibsonPluginName:   "scanner",
				GibsonPluginMethod: "ScanPort",
			},
		},
		{
			name:       "plugin without method",
			pluginName: "analyzer",
			method:     "",
			want: map[string]any{
				GibsonPluginName: "analyzer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := PluginAttributes(tt.pluginName, tt.method)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDelegationAttributes(t *testing.T) {
	taskID := types.NewID()

	attrs := DelegationAttributes("exploit-agent", taskID)

	got := make(map[string]any)
	for _, attr := range attrs {
		got[string(attr.Key)] = attr.Value.AsInterface()
	}

	want := map[string]any{
		GibsonDelegationTarget: "exploit-agent",
		GibsonDelegationTaskID: taskID.String(),
	}

	assert.Equal(t, want, got)
}

func TestTurnAttributes(t *testing.T) {
	tests := []struct {
		name       string
		turnNumber int
		want       map[string]any
	}{
		{
			name:       "first turn",
			turnNumber: 1,
			want: map[string]any{
				GibsonTurnNumber: int64(1),
			},
		},
		{
			name:       "tenth turn",
			turnNumber: 10,
			want: map[string]any{
				GibsonTurnNumber: int64(10),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := TurnAttributes(tt.turnNumber)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCostAttributes(t *testing.T) {
	tests := []struct {
		name string
		cost float64
		want map[string]any
	}{
		{
			name: "small cost",
			cost: 0.001,
			want: map[string]any{
				GibsonLLMCost: 0.001,
			},
		},
		{
			name: "larger cost",
			cost: 5.50,
			want: map[string]any{
				GibsonLLMCost: 5.50,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := CostAttributes(tt.cost)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTaskAttributes(t *testing.T) {
	missionID := types.NewID()
	parentID := types.NewID()
	targetID := types.NewID()

	tests := []struct {
		name string
		task agent.Task
		want map[string]any
	}{
		{
			name: "basic task",
			task: agent.NewTask("scan", "Scan target", nil),
			want: map[string]any{
				"gibson.task.name":     "scan",
				"gibson.task.priority": int64(0),
			},
		},
		{
			name: "task with mission and parent",
			task: agent.NewTask("exploit", "Exploit vulnerability", nil).
				WithMission(missionID).
				WithParent(parentID).
				WithPriority(5),
			want: map[string]any{
				"gibson.task.name":      "exploit",
				"gibson.task.priority":  int64(5),
				GibsonMissionID:         missionID.String(),
				"gibson.task.parent_id": parentID.String(),
			},
		},
		{
			name: "task with target and tags",
			task: agent.NewTask("analyze", "Analyze data", nil).
				WithTarget(targetID).
				WithTags("critical", "network"),
			want: map[string]any{
				"gibson.task.name":      "analyze",
				"gibson.task.priority":  int64(0),
				"gibson.task.target_id": targetID.String(),
				"gibson.task.tags":      []any{"critical", "network"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := TaskAttributes(tt.task)

			// Convert to map, checking for ID separately
			got := make(map[string]any)
			for _, attr := range attrs {
				key := string(attr.Key)
				if key != "gibson.task.id" {
					value := attr.Value.AsInterface()
					// Convert []string to []any for comparison
					if key == "gibson.task.tags" {
						if strSlice, ok := value.([]string); ok {
							anySlice := make([]any, len(strSlice))
							for i, s := range strSlice {
								anySlice[i] = s
							}
							value = anySlice
						}
					}
					got[key] = value
				} else {
					// Just verify ID exists and is non-empty
					assert.NotEmpty(t, attr.Value.AsString())
				}
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMetricsAttributes(t *testing.T) {
	tests := []struct {
		name    string
		metrics agent.TaskMetrics
		want    map[string]any
	}{
		{
			name: "basic metrics",
			metrics: agent.TaskMetrics{
				LLMCalls:      5,
				ToolCalls:     3,
				PluginCalls:   2,
				TokensUsed:    1000,
				Cost:          0.05,
				FindingsCount: 2,
				Errors:        0,
				Retries:       1,
				SubTasks:      0,
				Duration:      5 * time.Second,
			},
			want: map[string]any{
				"gibson.metrics.llm_calls":      int64(5),
				"gibson.metrics.tool_calls":     int64(3),
				"gibson.metrics.plugin_calls":   int64(2),
				"gibson.metrics.tokens_used":    int64(1000),
				GibsonLLMCost:                   0.05,
				"gibson.metrics.findings_count": int64(2),
				"gibson.metrics.errors":         int64(0),
				"gibson.metrics.retries":        int64(1),
				"gibson.metrics.sub_tasks":      int64(0),
				"gibson.metrics.duration":       "5s",
			},
		},
		{
			name: "metrics without duration",
			metrics: agent.TaskMetrics{
				LLMCalls:    1,
				ToolCalls:   0,
				PluginCalls: 0,
				TokensUsed:  500,
				Cost:        0.01,
			},
			want: map[string]any{
				"gibson.metrics.llm_calls":      int64(1),
				"gibson.metrics.tool_calls":     int64(0),
				"gibson.metrics.plugin_calls":   int64(0),
				"gibson.metrics.tokens_used":    int64(500),
				GibsonLLMCost:                   0.01,
				"gibson.metrics.findings_count": int64(0),
				"gibson.metrics.errors":         int64(0),
				"gibson.metrics.retries":        int64(0),
				"gibson.metrics.sub_tasks":      int64(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := MetricsAttributes(tt.metrics)

			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTargetAttributes(t *testing.T) {
	tests := []struct {
		name   string
		target harness.TargetInfo
		want   map[string]any
	}{
		{
			name: "basic target",
			target: harness.NewTargetInfo(
				types.NewID(),
				"web-server",
				"https://example.com",
				"web",
			),
			want: map[string]any{
				"gibson.target.name": "web-server",
				"gibson.target.type": "web",
				"gibson.target.url":  "https://example.com",
			},
		},
		{
			name: "target with provider",
			target: harness.NewTargetInfo(
				types.NewID(),
				"api-server",
				"https://api.example.com",
				"api",
			).WithProvider("aws"),
			want: map[string]any{
				"gibson.target.name":     "api-server",
				"gibson.target.type":     "api",
				"gibson.target.url":      "https://api.example.com",
				"gibson.target.provider": "aws",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := TargetAttributes(tt.target)

			// Convert to map, checking for ID separately
			got := make(map[string]any)
			for _, attr := range attrs {
				key := string(attr.Key)
				if key != "gibson.target.id" {
					got[key] = attr.Value.AsInterface()
				} else {
					// Just verify ID exists and is non-empty
					assert.NotEmpty(t, attr.Value.AsString())
				}
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCombineAttributes(t *testing.T) {
	attrs1 := []attribute.KeyValue{
		attribute.String("key1", "value1"),
		attribute.String("key2", "value2"),
	}

	attrs2 := []attribute.KeyValue{
		attribute.String("key3", "value3"),
	}

	attrs3 := []attribute.KeyValue{
		attribute.String("key4", "value4"),
		attribute.String("key5", "value5"),
	}

	combined := CombineAttributes(attrs1, attrs2, attrs3)

	assert.Len(t, combined, 5)

	// Convert to map to verify all keys exist
	got := make(map[string]string)
	for _, attr := range combined {
		got[string(attr.Key)] = attr.Value.AsString()
	}

	want := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"key5": "value5",
	}

	assert.Equal(t, want, got)
}

func TestAttributeSet(t *testing.T) {
	t.Run("basic usage", func(t *testing.T) {
		set := NewAttributeSet().
			AddString("name", "test").
			AddInt("count", 42).
			AddFloat64("score", 3.14).
			AddBool("enabled", true)

		attrs := set.Build()
		assert.Len(t, attrs, 4)

		// Convert to map for verification
		got := make(map[string]any)
		for _, attr := range attrs {
			got[string(attr.Key)] = attr.Value.AsInterface()
		}

		want := map[string]any{
			"name":    "test",
			"count":   int64(42),
			"score":   3.14,
			"enabled": true,
		}

		assert.Equal(t, want, got)
	})

	t.Run("skip empty strings", func(t *testing.T) {
		set := NewAttributeSet().
			AddString("name", "test").
			AddString("empty", "")

		attrs := set.Build()
		assert.Len(t, attrs, 1)
		assert.Equal(t, "name", string(attrs[0].Key))
	})

	t.Run("add existing attributes", func(t *testing.T) {
		existing := []attribute.KeyValue{
			attribute.String("existing", "value"),
		}

		set := NewAttributeSet().
			Add(existing...).
			AddString("new", "value2")

		attrs := set.Build()
		assert.Len(t, attrs, 2)
	})

	t.Run("add ID", func(t *testing.T) {
		id := types.NewID()

		set := NewAttributeSet().
			AddID("task_id", id)

		attrs := set.Build()
		require.Len(t, attrs, 1)
		assert.Equal(t, "task_id", string(attrs[0].Key))
		assert.Equal(t, id.String(), attrs[0].Value.AsString())
	})
}

func TestAttributeKeyConstants(t *testing.T) {
	// Test that attribute keys follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Agent Name", GibsonAgentName, "gibson.agent.name"},
		{"Agent Version", GibsonAgentVersion, "gibson.agent.version"},
		{"Mission ID", GibsonMissionID, "gibson.mission.id"},
		{"Mission Name", GibsonMissionName, "gibson.mission.name"},
		{"Turn Number", GibsonTurnNumber, "gibson.turn.number"},
		{"Tool Name", GibsonToolName, "gibson.tool.name"},
		{"Plugin Name", GibsonPluginName, "gibson.plugin.name"},
		{"Plugin Method", GibsonPluginMethod, "gibson.plugin.method"},
		{"Delegation Target", GibsonDelegationTarget, "gibson.delegation.target_agent"},
		{"Delegation Task ID", GibsonDelegationTaskID, "gibson.delegation.task_id"},
		{"Finding ID", GibsonFindingID, "gibson.finding.id"},
		{"Finding Severity", GibsonFindingSeverity, "gibson.finding.severity"},
		{"Finding Category", GibsonFindingCategory, "gibson.finding.category"},
		{"LLM Cost", GibsonLLMCost, "gibson.llm.cost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestSpanNameConstants(t *testing.T) {
	// Test that span names follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Agent Delegate", SpanAgentDelegate, "gibson.agent.delegate"},
		{"Finding Submit", SpanFindingSubmit, "gibson.finding.submit"},
		{"Plugin Query", SpanPluginQuery, "gibson.plugin.query"},
		{"Memory Get", SpanMemoryGet, "gibson.memory.get"},
		{"Memory Set", SpanMemorySet, "gibson.memory.set"},
		{"Memory Search", SpanMemorySearch, "gibson.memory.search"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}
