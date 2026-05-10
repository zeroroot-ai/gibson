package plugin

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
}

func (s *stubDelegator) ExecuteAgentNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}
func (s *stubDelegator) ExecuteToolNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	return nil, errors.New("not used")
}
func (s *stubDelegator) ExecutePluginNode(ctx context.Context, nID, mID string) (*orchestrator.ActionResult, error) {
	s.calledID = nID
	s.calledMission = mID
	return &orchestrator.ActionResult{TargetNodeID: nID}, nil
}

func pluginNode(id, name, method string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_PLUGIN,
		Config: &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName: name,
				Method:     method,
			},
		},
	}
}

func TestExecute_delegates(t *testing.T) {
	d := &stubDelegator{}
	_, err := Execute(context.Background(), pluginNode("n1", "shodan", "lookup"), orchestrator.HandlerParams{
		MissionID: "m1",
		Delegator: d,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if d.calledID != "n1" {
		t.Errorf("delegator id=%q want=n1", d.calledID)
	}
}

func TestExecute_empty_plugin_name(t *testing.T) {
	d := &stubDelegator{}
	_, err := Execute(context.Background(), pluginNode("n1", "", "lookup"), orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for empty plugin_name")
	}
	if !strings.Contains(err.Error(), "plugin_name") {
		t.Errorf("error=%q", err.Error())
	}
}

func TestExecute_empty_method(t *testing.T) {
	d := &stubDelegator{}
	_, err := Execute(context.Background(), pluginNode("n1", "shodan", ""), orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for empty method")
	}
	if !strings.Contains(err.Error(), "method") {
		t.Errorf("error=%q", err.Error())
	}
}

func TestExecute_nil_delegator(t *testing.T) {
	_, err := Execute(context.Background(), pluginNode("n1", "shodan", "lookup"), orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for nil delegator")
	}
}

func TestExecute_no_config(t *testing.T) {
	d := &stubDelegator{}
	node := &missionv1.MissionNode{Id: "n1", Type: missionv1.NodeType_NODE_TYPE_PLUGIN}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{Delegator: d})
	if err == nil {
		t.Fatal("expected error for missing plugin_config")
	}
}
