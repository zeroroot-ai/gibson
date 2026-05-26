package condition

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func condNode(id, expr string, lang missionv1.Language) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_CONDITION,
		Config: &missionv1.MissionNode_ConditionConfig{
			ConditionConfig: &missionv1.ConditionNodeConfig{
				Expression:  expr,
				Language:    lang,
				TrueBranch:  []string{"t1", "t2"},
				FalseBranch: []string{"f1"},
			},
		},
	}
}

func TestExecute_true_branch(t *testing.T) {
	node := condNode("c", "1 + 1 == 2", missionv1.Language_LANGUAGE_CEL)
	got, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Metadata["condition_result"] != true {
		t.Errorf("result=%v want true", got.Metadata["condition_result"])
	}
	ready := got.Metadata["branch_ready"].([]string)
	if len(ready) != 2 || ready[0] != "t1" {
		t.Errorf("branch_ready=%v want [t1 t2]", ready)
	}
}

func TestExecute_false_branch(t *testing.T) {
	node := condNode("c", "1 + 1 == 3", missionv1.Language_LANGUAGE_CEL)
	got, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Metadata["condition_result"] != false {
		t.Errorf("result=%v want false", got.Metadata["condition_result"])
	}
	ready := got.Metadata["branch_ready"].([]string)
	if len(ready) != 1 || ready[0] != "f1" {
		t.Errorf("branch_ready=%v want [f1]", ready)
	}
}

func TestExecute_unspecified_treated_as_cel(t *testing.T) {
	node := condNode("c", "true", missionv1.Language_LANGUAGE_UNSPECIFIED)
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Errorf("UNSPECIFIED should default to CEL: %v", err)
	}
}

func TestExecute_compile_error(t *testing.T) {
	node := condNode("c", "this is not valid CEL", missionv1.Language_LANGUAGE_CEL)
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "compile") {
		t.Errorf("error=%q want substring 'compile'", err.Error())
	}
}

func TestExecute_non_boolean(t *testing.T) {
	// Returns int, not bool.
	node := condNode("c", "42", missionv1.Language_LANGUAGE_CEL)
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected non-boolean error")
	}
	if !strings.Contains(err.Error(), "non-boolean") {
		t.Errorf("error=%q want substring 'non-boolean'", err.Error())
	}
}

func TestExecute_uses_node_results(t *testing.T) {
	// Reference upstream node result via the `nodes` variable.
	node := condNode("c", `nodes.scan.findings_count > 0`, missionv1.Language_LANGUAGE_CEL)
	params := orchestrator.HandlerParams{
		PriorResults: map[string]*orchestrator.ActionResult{
			"scan": {Metadata: map[string]any{"findings_count": int64(3)}},
		},
	}
	got, err := Execute(context.Background(), node, params)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Metadata["condition_result"] != true {
		t.Errorf("expected true, got %v", got.Metadata["condition_result"])
	}
}

func TestExecute_empty_expression(t *testing.T) {
	node := condNode("c", "", missionv1.Language_LANGUAGE_CEL)
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for empty expression")
	}
}

func TestExecute_no_config(t *testing.T) {
	node := &missionv1.MissionNode{
		Id:   "c",
		Type: missionv1.NodeType_NODE_TYPE_CONDITION,
	}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
