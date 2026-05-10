package join

import (
	"context"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

func joinNode(id string, cfg *missionv1.JoinNodeConfig) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_JOIN,
		Config: &missionv1.MissionNode_JoinConfig{
			JoinConfig: cfg,
		},
	}
}

func mkResult(meta map[string]any) *orchestrator.ActionResult {
	return &orchestrator.ActionResult{
		Metadata: meta,
	}
}

func TestExecute_concat_default(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor:  []string{"a", "b"},
		Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT,
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"a": mkResult(map[string]any{"k": "va"}),
			"b": mkResult(map[string]any{"k": "vb"}),
		},
	}
	got, err := Execute(context.Background(), node, params)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	merged, _ := got.Metadata["join_merged_value"].([]map[string]any)
	if len(merged) != 2 {
		t.Fatalf("merged len=%d want=2", len(merged))
	}
	if merged[0]["node_id"] != "a" || merged[1]["node_id"] != "b" {
		t.Errorf("order-preserving concat broken: %v", merged)
	}
}

func TestExecute_first(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor:  []string{"a", "b"},
		Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_FIRST,
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"a": mkResult(map[string]any{"k": "va"}),
			"b": mkResult(map[string]any{"k": "vb"}),
		},
	}
	got, _ := Execute(context.Background(), node, params)
	merged := got.Metadata["join_merged_value"].(map[string]any)
	if merged["node_id"] != "a" {
		t.Errorf("FIRST returned %v want a", merged["node_id"])
	}
}

func TestExecute_last(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor:  []string{"a", "b"},
		Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_LAST,
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"a": mkResult(map[string]any{"k": "va"}),
			"b": mkResult(map[string]any{"k": "vb"}),
		},
	}
	got, _ := Execute(context.Background(), node, params)
	merged := got.Metadata["join_merged_value"].(map[string]any)
	if merged["node_id"] != "b" {
		t.Errorf("LAST returned %v want b", merged["node_id"])
	}
}

func TestExecute_reduce(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor:  []string{"a", "b"},
		Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_REDUCE,
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"a": mkResult(map[string]any{"shared": "first", "a-only": 1}),
			"b": mkResult(map[string]any{"shared": "second", "b-only": 2}),
		},
	}
	got, _ := Execute(context.Background(), node, params)
	merged := got.Metadata["join_merged_value"].(map[string]any)
	// last-writer-wins on shared
	if merged["shared"] != "second" {
		t.Errorf("REDUCE shared=%v want=second", merged["shared"])
	}
	if merged["a-only"] != 1 || merged["b-only"] != 2 {
		t.Errorf("REDUCE preserved=%v", merged)
	}
}

func TestExecute_custom_requires_aggregator(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor:    []string{"a"},
		Strategy:   missionv1.MergeStrategy_MERGE_STRATEGY_CUSTOM,
		Aggregator: "",
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{"a": mkResult(map[string]any{})},
	}
	_, err := Execute(context.Background(), node, params)
	if err == nil {
		t.Fatal("expected error for empty aggregator")
	}
	if !strings.Contains(err.Error(), "aggregator") {
		t.Errorf("error=%q want substring 'aggregator'", err.Error())
	}
}

func TestExecute_missing_source(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor: []string{"a", "b"},
	})
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"a": mkResult(map[string]any{}),
			// "b" missing
		},
	}
	_, err := Execute(context.Background(), node, params)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	if !strings.Contains(err.Error(), "incomplete sources") {
		t.Errorf("error=%q want substring 'incomplete sources'", err.Error())
	}
}

func TestExecute_empty_wait_for(t *testing.T) {
	node := joinNode("j", &missionv1.JoinNodeConfig{
		WaitFor: nil,
	})
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for empty wait_for")
	}
}

func TestExecute_no_config(t *testing.T) {
	node := &missionv1.MissionNode{
		Id:   "j",
		Type: missionv1.NodeType_NODE_TYPE_JOIN,
		// no config
	}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
