package tool

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

type stubDelegator struct {
	calledID, calledMission string
	err                     error
}

func (s *stubDelegator) ExecuteAgentNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}
func (s *stubDelegator) ExecuteToolNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	s.calledID = nID
	s.calledMission = mID
	return &orchestrator.ActionResult{TargetNodeID: nID}, s.err
}
func (s *stubDelegator) ExecutePluginNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}

func toolNode(id, name string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_TOOL,
		Config: &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{ToolName: name},
		},
	}
}

func TestExecute_delegates(t *testing.T) {
	d := &stubDelegator{}
	_, err := Execute(context.Background(), toolNode("n1", "nmap"), orchestrator.HandlerParams{
		MissionID: "m1",
		Delegator: d,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if d.calledID != "n1" || d.calledMission != "m1" {
		t.Errorf("delegator args id=%q mission=%q", d.calledID, d.calledMission)
	}
}

func TestExecute_empty_tool_name(t *testing.T) {
	d := &stubDelegator{}
	_, err := Execute(context.Background(), toolNode("n1", ""), orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for empty tool_name")
	}
	if !strings.Contains(err.Error(), "tool_name") {
		t.Errorf("error=%q want substring 'tool_name'", err.Error())
	}
}

func TestExecute_nil_delegator(t *testing.T) {
	_, err := Execute(context.Background(), toolNode("n1", "nmap"), orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for nil delegator")
	}
}

func TestExecute_no_config(t *testing.T) {
	d := &stubDelegator{}
	node := &missionv1.MissionNode{Id: "n1", Type: missionv1.NodeType_NODE_TYPE_TOOL}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for missing tool_config")
	}
}
