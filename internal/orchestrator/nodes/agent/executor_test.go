package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

type stubDelegator struct {
	called    bool
	lastID    string
	lastMission string
	ret       *orchestrator.ActionResult
	err       error
}

func (s *stubDelegator) ExecuteAgentNode(ctx context.Context, nodeID, missionID string) (*orchestrator.ActionResult, error) {
	s.called = true
	s.lastID = nodeID
	s.lastMission = missionID
	return s.ret, s.err
}
func (s *stubDelegator) ExecuteToolNode(ctx context.Context, nodeID, missionID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}
func (s *stubDelegator) ExecutePluginNode(ctx context.Context, nodeID, missionID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}

func agentNode(id string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_AGENT,
		Config: &missionv1.MissionNode_AgentConfig{
			AgentConfig: &missionv1.AgentNodeConfig{AgentName: "a"},
		},
	}
}

func TestExecute_delegates(t *testing.T) {
	want := &orchestrator.ActionResult{TargetNodeID: "n1"}
	d := &stubDelegator{ret: want}
	got, err := Execute(context.Background(), agentNode("n1"), orchestrator.HandlerParams{
		MissionID: "m1",
		Delegator: d,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got != want {
		t.Errorf("got=%v want=%v", got, want)
	}
	if !d.called {
		t.Error("delegator not called")
	}
	if d.lastID != "n1" || d.lastMission != "m1" {
		t.Errorf("delegator args lastID=%q lastMission=%q", d.lastID, d.lastMission)
	}
}

func TestExecute_nil_delegator(t *testing.T) {
	_, err := Execute(context.Background(), agentNode("n1"), orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for nil delegator")
	}
	if !strings.Contains(err.Error(), "Delegator is nil") {
		t.Errorf("error=%q want substring 'Delegator is nil'", err.Error())
	}
}

func TestExecute_no_config(t *testing.T) {
	d := &stubDelegator{}
	node := &missionv1.MissionNode{Id: "n1", Type: missionv1.NodeType_NODE_TYPE_AGENT}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for missing agent_config")
	}
}

func TestExecute_propagates_delegator_error(t *testing.T) {
	want := errors.New("delegate boom")
	d := &stubDelegator{err: want}
	_, err := Execute(context.Background(), agentNode("n1"), orchestrator.HandlerParams{
		Delegator: d,
	})
	if !errors.Is(err, want) {
		t.Errorf("got=%v want=%v (errors.Is)", err, want)
	}
}
