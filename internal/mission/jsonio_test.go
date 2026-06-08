package mission_test

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/mission"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typesv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMarshalDefinitionJSON_NilInput(t *testing.T) {
	_, err := mission.MarshalDefinitionJSON(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestUnmarshalDefinitionJSON_EmptyInput(t *testing.T) {
	_, err := mission.UnmarshalDefinitionJSON(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = mission.UnmarshalDefinitionJSON([]byte(""))
	if err == nil {
		t.Fatal("expected error for zero-length input")
	}
}

func TestRoundTrip_AllNodeTypes(t *testing.T) {
	original := buildAllNodeTypesDefinition()

	bytes, err := mission.MarshalDefinitionJSON(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	got, err := mission.UnmarshalDefinitionJSON(bytes)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !proto.Equal(original, got) {
		t.Errorf("round trip not equal\noriginal: %+v\n     got: %+v", original, got)
	}
}

func TestMarshalDefinitionJSON_UsesSnakeCaseFieldNames(t *testing.T) {
	def := buildAllNodeTypesDefinition()
	bytes, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	out := string(bytes)

	wantSnake := []string{
		`"agent_config"`,
		`"tool_config"`,
		`"plugin_config"`,
		`"condition_config"`,
		`"parallel_config"`,
		`"agent_name"`,
		`"tool_name"`,
		`"plugin_name"`,
		`"entry_points"`,
		`"exit_points"`,
	}
	for _, want := range wantSnake {
		if !strings.Contains(out, want) {
			t.Errorf("expected snake_case key %s in output, got: %s", want, out)
		}
	}

	rejectCamel := []string{
		`"agentConfig"`,
		`"toolConfig"`,
		`"pluginConfig"`,
		`"conditionConfig"`,
		`"parallelConfig"`,
		`"agentName"`,
		`"toolName"`,
		`"componentName"`,
		`"entryPoints"`,
		`"exitPoints"`,
	}
	for _, reject := range rejectCamel {
		if strings.Contains(out, reject) {
			t.Errorf("did not expect camelCase key %s in output, got: %s", reject, out)
		}
	}
}

func TestUnmarshalDefinitionJSON_DropsLegacyMirrorShape(t *testing.T) {
	// Legacy flat-mirror JSON: `agent_name` at the top level of the node.
	// After PR4c, this shape is not handled at runtime — operators with
	// pre-PR4 stored data run cmd/mission-storage-migrate. The reader
	// silently drops the unrecognized top-level fields (DiscardUnknown),
	// so the node is parsed with an empty oneof config envelope.
	legacy := []byte(`{
		"name": "Legacy",
		"version": "1.0",
		"nodes": {
			"node1": {
				"id": "node1",
				"type": "agent",
				"agent_name": "scout"
			}
		}
	}`)
	got, err := mission.UnmarshalDefinitionJSON(legacy)
	if err != nil {
		t.Fatalf("expected protojson to silently drop unknown fields: %v", err)
	}
	node, ok := got.Nodes["node1"]
	if !ok {
		t.Fatal("expected node1 to be present")
	}
	if node.GetAgentConfig() != nil {
		t.Error("legacy top-level agent_name should not have populated agent_config")
	}
}

func TestUnmarshalDefinitionJSON_DiscardsUnknownFields(t *testing.T) {
	// Forward-compat: the reader tolerates fields the SDK in scope does
	// not yet know about. This guards against in-flight redeploys where
	// a slightly newer writer pushed bytes onto storage that an older
	// reader is now picking up.
	withFutureField := []byte(`{
		"name": "Future",
		"version": "1.0",
		"future_field_not_in_proto": "ignored",
		"nodes": {}
	}`)
	def, err := mission.UnmarshalDefinitionJSON(withFutureField)
	if err != nil {
		t.Fatalf("expected unknown fields to be discarded, got: %v", err)
	}
	if def.GetName() != "Future" {
		t.Errorf("expected Name=Future, got %q", def.GetName())
	}
}

func buildAllNodeTypesDefinition() *missionv1.MissionDefinition {
	return &missionv1.MissionDefinition{
		Id:          "def-1",
		Name:        "Round-Trip Test",
		Description: "Exercises every node type for jsonio round-trip coverage",
		Version:     "1.0.0",
		TargetRef:   "target-1",
		EntryPoints: []string{"agent-node"},
		ExitPoints:  []string{"join-node"},
		Metadata: map[string]string{
			"owner": "qa",
		},
		Nodes: map[string]*missionv1.MissionNode{
			"agent-node": {
				Id:   "agent-node",
				Type: missionv1.NodeType_NODE_TYPE_AGENT,
				Name: "Scout",
				Config: &missionv1.MissionNode_AgentConfig{
					AgentConfig: &missionv1.AgentNodeConfig{
						AgentName: "scout-agent",
						Task: &typesv1.Task{
							Id:   "task-1",
							Goal: "enumerate hosts",
						},
					},
				},
				Timeout: durationpb.New(30_000_000_000),
				RetryPolicy: &missionv1.RetryPolicy{
					MaxRetries:      3,
					BackoffStrategy: missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL,
					InitialDelay:    durationpb.New(1_000_000_000),
					MaxDelay:        durationpb.New(60_000_000_000),
					Multiplier:      2.0,
				},
			},
			"tool-node": {
				Id:           "tool-node",
				Type:         missionv1.NodeType_NODE_TYPE_TOOL,
				Name:         "Probe",
				Dependencies: []string{"agent-node"},
				Config: &missionv1.MissionNode_ToolConfig{
					ToolConfig: &missionv1.ToolNodeConfig{
						ToolName: "nmap",
						Input: map[string]string{
							"target": "10.0.0.0/24",
						},
					},
				},
			},
			"plugin-node": {
				Id:           "plugin-node",
				Type:         missionv1.NodeType_NODE_TYPE_PLUGIN,
				Name:         "Compliance",
				Dependencies: []string{"tool-node"},
				Config: &missionv1.MissionNode_PluginConfig{
					PluginConfig: &missionv1.PluginNodeConfig{
						PluginName: "compliance-checker",
						Method:     "verify",
						Params: map[string]string{
							"framework": "soc2",
						},
					},
				},
			},
			"condition-node": {
				Id:           "condition-node",
				Type:         missionv1.NodeType_NODE_TYPE_CONDITION,
				Dependencies: []string{"plugin-node"},
				Config: &missionv1.MissionNode_ConditionConfig{
					ConditionConfig: &missionv1.ConditionNodeConfig{
						Expression:  "result.success == true",
						TrueBranch:  []string{"parallel-node"},
						FalseBranch: []string{"join-node"},
					},
				},
			},
			"parallel-node": {
				Id:   "parallel-node",
				Type: missionv1.NodeType_NODE_TYPE_PARALLEL,
				Config: &missionv1.MissionNode_ParallelConfig{
					ParallelConfig: &missionv1.ParallelNodeConfig{
						SubNodes: []*missionv1.MissionNode{
							{
								Id:   "p-sub-1",
								Type: missionv1.NodeType_NODE_TYPE_AGENT,
								Config: &missionv1.MissionNode_AgentConfig{
									AgentConfig: &missionv1.AgentNodeConfig{
										AgentName: "exploit-agent",
									},
								},
							},
						},
					},
				},
			},
			"join-node": {
				Id:           "join-node",
				Type:         missionv1.NodeType_NODE_TYPE_JOIN,
				Dependencies: []string{"parallel-node"},
				Config: &missionv1.MissionNode_JoinConfig{
					JoinConfig: &missionv1.JoinNodeConfig{
						Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT,
					},
				},
			},
		},
		Edges: []*missionv1.MissionEdge{
			{From: "agent-node", To: "tool-node"},
			{From: "tool-node", To: "plugin-node"},
			{From: "plugin-node", To: "condition-node"},
			{From: "condition-node", To: "parallel-node", Condition: "result.success == true"},
			{From: "parallel-node", To: "join-node"},
		},
	}
}
