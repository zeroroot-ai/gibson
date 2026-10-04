// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"errors"
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// forEachNode builds a for_each over the target set whose template is one tool
// node, which is the shape every fan-out mission has.
func forEachNode(id, tplID string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
		Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
			Source: missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
			Template: &missionv1.MissionNode{
				Id:   tplID,
				Type: missionv1.NodeType_NODE_TYPE_TOOL,
				Config: &missionv1.MissionNode_ToolConfig{ToolConfig: &missionv1.ToolNodeConfig{
					ToolName: "nmap",
				}},
			},
		}},
	}
}

func joinNode(id string, waitFor []string, strategy missionv1.MergeStrategy, aggregator string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_JOIN,
		Config: &missionv1.MissionNode_JoinConfig{JoinConfig: &missionv1.JoinNodeConfig{
			WaitFor:    waitFor,
			Strategy:   strategy,
			Aggregator: aggregator,
		}},
	}
}

// A merge rule over a fan-out source is accepted: the brain's JoinSystem
// evaluates JoinNodeConfig.strategy and .aggregator (gibson#543), so the
// refusal gibson#527 added as a stopgap is gone. The merge itself is asserted
// in the brain's join tests and the daemon's projection tests.
func TestRefuseUnsupportedFanOut_MergeStrategyOverAFanOutSourceIsAccepted(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"each":   forEachNode("each", "scan"),
		"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, ""),
	}
	if err := RefuseUnsupportedFanOut(nodes); err != nil {
		t.Errorf("a merge strategy over a for_each source must be accepted: %v", err)
	}
}

// An aggregator over a fan-out source is accepted too, whatever the strategy
// field says: the brain evaluates it under MERGE_STRATEGY_CUSTOM and ignores
// it otherwise, and neither is a reason to refuse the mission.
func TestRefuseUnsupportedFanOut_AggregatorOverAFanOutSourceIsAccepted(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"each":   forEachNode("each", "scan"),
		"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_CUSTOM, "sources.each.map(e, e.target)"),
	}
	if err := RefuseUnsupportedFanOut(nodes); err != nil {
		t.Errorf("an aggregator over a for_each source must be accepted: %v", err)
	}
}

// A join over an ordinary node keeps working exactly as it does today, strategy
// and all. Missions in the field already declare CONCAT on ordinary joins, and
// refusing them would break runs that work.
func TestRefuseUnsupportedFanOut_OrdinaryJoinWithAStrategyIsAccepted(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"scan": {
			Id:   "scan",
			Type: missionv1.NodeType_NODE_TYPE_TOOL,
			Config: &missionv1.MissionNode_ToolConfig{ToolConfig: &missionv1.ToolNodeConfig{
				ToolName: "nmap",
			}},
		},
		"report": joinNode("report", []string{"scan"}, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, ""),
	}
	if err := RefuseUnsupportedFanOut(nodes); err != nil {
		t.Errorf("an ordinary join with a strategy must still be accepted: %v", err)
	}
}

// A join over a fan-out source with no merge rule is the supported shape: the
// join is the ordering it actually is.
func TestRefuseUnsupportedFanOut_FanOutJoinWithNoMergeRuleIsAccepted(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"each":   forEachNode("each", "scan"),
		"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_UNSPECIFIED, ""),
	}
	if err := RefuseUnsupportedFanOut(nodes); err != nil {
		t.Errorf("a fan-out join with no merge rule must be accepted: %v", err)
	}
}

// A nested for_each is refused by the same entry point, so the run path gets both
// refusals from one call (gibson#524).
func TestRefuseUnsupportedFanOut_NestedForEach(t *testing.T) {
	outer := forEachNode("outer", "inner")
	outer.GetForEachConfig().Template = forEachNode("inner", "scan")
	err := RefuseUnsupportedFanOut(map[string]*missionv1.MissionNode{"outer": outer})
	if err == nil {
		t.Fatal("want a refusal for a for_each whose template is a for_each")
	}
	if !strings.Contains(err.Error(), "outer") {
		t.Errorf("the refusal does not name the offending node: %s", err)
	}
}

// Nothing to refuse returns a nil literal, not a typed nil in an error
// interface. A *ValidationError returned as `error` would be non-nil whatever it
// held, and every caller's `err != nil` would refuse every mission.
func TestRefuseUnsupportedFanOut_NothingToRefuseIsATrueNil(t *testing.T) {
	if err := RefuseUnsupportedFanOut(nil); err != nil {
		t.Errorf("an empty node set returned %v (%T), want a nil error", err, err)
	}
}

// The analyser accepts the same shape the run path accepts, so the mission
// view and a submitted run cannot disagree about a merge rule over a fan-out.
func TestProject_AcceptsAMergeRuleOverAFanOutSource(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionv1.MissionNode{
			"each":   forEachNode("each", "scan"),
			"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, ""),
		},
	}
	if _, err := Project(def, nil); err != nil {
		t.Fatalf("Project refused a merge rule over a for_each source: %v", err)
	}
}

// asValidationError keeps the unwrapping in one place. errors.As rather than a
// type assertion: an assertion fails the moment a caller wraps the error, and a
// test that stops matching when its subject is wrapped is a test that stops
// testing.
func asValidationError(err error, out **ValidationError) bool {
	return errors.As(err, out)
}
