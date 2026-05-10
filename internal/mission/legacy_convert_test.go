package mission

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestLegacyMirrorJSONToProto_AllNodeTypes(t *testing.T) {
	original := &MissionDefinition{
		ID:          types.ID("11111111-1111-1111-1111-111111111111"),
		Name:        "Legacy Conversion Test",
		Description: "Round-trip across every node type",
		Version:     "1.0.0",
		TargetRef:   "target-legacy-1",
		EntryPoints: []string{"agent-node"},
		ExitPoints:  []string{"join-node"},
		Metadata:    map[string]any{"owner": "qa"},
		Nodes: map[string]*MissionNode{
			"agent-node": {
				ID:        "agent-node",
				Type:      NodeTypeAgent,
				Name:      "Scout",
				AgentName: "scout-agent",
				AgentTask: &agent.Task{
					ID:   types.ID("22222222-2222-2222-2222-222222222222"),
					Goal: "enumerate hosts",
					Context: map[string]any{
						"depth": 3,
						"flag":  true,
					},
				},
				Timeout: 30 * time.Second,
				RetryPolicy: &RetryPolicy{
					MaxRetries:      3,
					BackoffStrategy: BackoffExponential,
					InitialDelay:    time.Second,
					MaxDelay:        60 * time.Second,
					Multiplier:      2.0,
				},
			},
			"tool-node": {
				ID:           "tool-node",
				Type:         NodeTypeTool,
				ToolName:     "nmap",
				ToolInput:    map[string]any{"target": "10.0.0.0/24"},
				Dependencies: []string{"agent-node"},
			},
			"plugin-node": {
				ID:           "plugin-node",
				Type:         NodeTypePlugin,
				PluginName:   "compliance-checker",
				PluginMethod: "verify",
				PluginParams: map[string]any{"framework": "soc2"},
				Dependencies: []string{"tool-node"},
			},
			"condition-node": {
				ID:   "condition-node",
				Type: NodeTypeCondition,
				Condition: &NodeCondition{
					Expression:  "result.success == true",
					TrueBranch:  []string{"parallel-node"},
					FalseBranch: []string{"join-node"},
				},
				Dependencies: []string{"plugin-node"},
			},
			"parallel-node": {
				ID:   "parallel-node",
				Type: NodeTypeParallel,
				SubNodes: []*MissionNode{
					{
						ID:        "p-sub-1",
						Type:      NodeTypeAgent,
						AgentName: "exploit-agent",
					},
				},
			},
			"join-node": {
				ID:           "join-node",
				Type:         NodeTypeJoin,
				Dependencies: []string{"parallel-node"},
			},
		},
		Edges: []MissionEdge{
			{From: "agent-node", To: "tool-node"},
			{From: "tool-node", To: "plugin-node"},
			{From: "plugin-node", To: "condition-node"},
			{From: "condition-node", To: "parallel-node", Condition: "result.success == true"},
			{From: "parallel-node", To: "join-node"},
		},
	}

	bytes, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("mirror marshal: %v", err)
	}

	def, err := LegacyMirrorJSONToProto(bytes)
	if err != nil {
		t.Fatalf("LegacyMirrorJSONToProto: %v", err)
	}

	if def.GetName() != original.Name {
		t.Errorf("Name: got %q want %q", def.GetName(), original.Name)
	}
	if got := def.GetTargetRef(); got != original.TargetRef {
		t.Errorf("TargetRef: got %q want %q", got, original.TargetRef)
	}
	if len(def.GetNodes()) != len(original.Nodes) {
		t.Errorf("Nodes: got %d want %d", len(def.GetNodes()), len(original.Nodes))
	}

	agentNode := def.GetNodes()["agent-node"]
	if agentNode == nil {
		t.Fatal("agent-node missing")
	}
	if agentNode.GetAgentConfig() == nil {
		t.Fatal("agent-node has no AgentConfig — oneof envelope not populated")
	}
	if agentNode.GetAgentConfig().GetAgentName() != "scout-agent" {
		t.Errorf("agent name: got %q", agentNode.GetAgentConfig().GetAgentName())
	}
	if agentNode.GetAgentConfig().GetTask() == nil {
		t.Fatal("agent-node task missing")
	}

	toolNode := def.GetNodes()["tool-node"]
	if toolNode.GetToolConfig() == nil {
		t.Fatal("tool-node has no ToolConfig")
	}
	if toolNode.GetToolConfig().GetToolName() != "nmap" {
		t.Errorf("tool name: got %q", toolNode.GetToolConfig().GetToolName())
	}
	if toolNode.GetToolConfig().GetInput()["target"] != "10.0.0.0/24" {
		t.Errorf("tool input: got %v", toolNode.GetToolConfig().GetInput())
	}

	pluginNode := def.GetNodes()["plugin-node"]
	if pluginNode.GetPluginConfig() == nil {
		t.Fatal("plugin-node has no PluginConfig")
	}
	if pluginNode.GetPluginConfig().GetMethod() != "verify" {
		t.Errorf("plugin method: got %q", pluginNode.GetPluginConfig().GetMethod())
	}

	condNode := def.GetNodes()["condition-node"]
	if condNode.GetConditionConfig() == nil {
		t.Fatal("condition-node has no ConditionConfig")
	}
	if condNode.GetConditionConfig().GetExpression() != "result.success == true" {
		t.Errorf("expression: got %q", condNode.GetConditionConfig().GetExpression())
	}

	parNode := def.GetNodes()["parallel-node"]
	if parNode.GetParallelConfig() == nil {
		t.Fatal("parallel-node has no ParallelConfig")
	}
	if len(parNode.GetParallelConfig().GetSubNodes()) != 1 {
		t.Errorf("sub-nodes: got %d", len(parNode.GetParallelConfig().GetSubNodes()))
	}

	joinNode := def.GetNodes()["join-node"]
	if joinNode.GetJoinConfig() == nil {
		t.Fatal("join-node has no JoinConfig")
	}
}

func TestLegacyMirrorJSONToProto_EmptyInput(t *testing.T) {
	_, err := LegacyMirrorJSONToProto(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestStringifyAnyMap(t *testing.T) {
	in := map[string]any{
		"str":   "hello",
		"int":   42,
		"bool":  true,
		"nilv":  nil,
		"slice": []string{"a", "b"},
	}
	got := stringifyAnyMap(in)
	if got["str"] != "hello" {
		t.Errorf("str: got %q", got["str"])
	}
	if got["int"] != "42" {
		t.Errorf("int: got %q", got["int"])
	}
	if got["bool"] != "true" {
		t.Errorf("bool: got %q", got["bool"])
	}
	if got["nilv"] != "" {
		t.Errorf("nil: got %q", got["nilv"])
	}
}

func TestStringifyAnyMap_Empty(t *testing.T) {
	if stringifyAnyMap(nil) != nil {
		t.Error("nil map: expected nil result")
	}
	if stringifyAnyMap(map[string]any{}) != nil {
		t.Error("empty map: expected nil result")
	}
}

func TestUnmarshalToMirror_LegacyShape(t *testing.T) {
	original := &MissionDefinition{
		ID:        types.ID("11111111-1111-1111-1111-111111111111"),
		Name:      "Legacy Mirror Round-Trip",
		Version:   "1.0.0",
		TargetRef: "target-1",
		Nodes: map[string]*MissionNode{
			"a": {
				ID: "a", Type: NodeTypeAgent, AgentName: "scout",
				AgentTask: &agent.Task{
					ID:   types.ID("22222222-2222-2222-2222-222222222222"),
					Goal: "scan",
				},
			},
			"t": {
				ID: "t", Type: NodeTypeTool, ToolName: "nmap",
				ToolInput: map[string]any{"target": "10.0.0.1"},
			},
		},
	}
	bytes, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalToMirror(bytes)
	if err != nil {
		t.Fatalf("UnmarshalToMirror legacy: %v", err)
	}
	if got.Name != original.Name {
		t.Errorf("Name: got %q want %q", got.Name, original.Name)
	}
	if got.Nodes["a"].AgentName != "scout" {
		t.Errorf("agent name: got %q", got.Nodes["a"].AgentName)
	}
	if got.Nodes["t"].ToolInput["target"] != "10.0.0.1" {
		t.Errorf("tool input: got %v", got.Nodes["t"].ToolInput)
	}
}

func TestUnmarshalToMirror_ProtoShape(t *testing.T) {
	original := &MissionDefinition{
		ID:        types.ID("33333333-3333-3333-3333-333333333333"),
		Name:      "Proto Round-Trip",
		Version:   "1.0.0",
		TargetRef: "target-2",
		Nodes: map[string]*MissionNode{
			"a": {ID: "a", Type: NodeTypeAgent, AgentName: "exploit"},
		},
	}
	proto, err := mirrorDefinitionToProto(original)
	if err != nil {
		t.Fatalf("mirror to proto: %v", err)
	}
	bytes, err := MarshalDefinitionJSON(proto)
	if err != nil {
		t.Fatalf("MarshalDefinitionJSON: %v", err)
	}
	got, err := UnmarshalToMirror(bytes)
	if err != nil {
		t.Fatalf("UnmarshalToMirror proto: %v", err)
	}
	if got.Name != original.Name {
		t.Errorf("Name: got %q want %q", got.Name, original.Name)
	}
	if got.Nodes["a"].AgentName != "exploit" {
		t.Errorf("agent name: got %q", got.Nodes["a"].AgentName)
	}
}
