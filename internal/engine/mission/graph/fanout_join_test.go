// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
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

// A merge rule over a fan-out source is refused, and the message names the
// strategy. Nothing in the daemon evaluates JoinNodeConfig.strategy or
// .aggregator (gibson#543), so accepting one would tell the author their rule
// ran when it never did.
func TestRefuseUnsupportedFanOut_MergeStrategyOverAFanOutSource(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"each":   forEachNode("each", "scan"),
		"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, ""),
	}
	err := RefuseUnsupportedFanOut(nodes)
	if err == nil {
		t.Fatal("want a refusal for a merge strategy declared over a for_each source")
	}
	msg := err.Error()
	for _, want := range []string{"report", "each", "MERGE_STRATEGY_CONCAT", "gibson#543"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
}

// An aggregator is refused even without MERGE_STRATEGY_CUSTOM: an author who
// wrote a CEL expression expects it to run whatever the strategy field says.
func TestRefuseUnsupportedFanOut_AggregatorWithoutCustomStrategy(t *testing.T) {
	nodes := map[string]*missionv1.MissionNode{
		"each":   forEachNode("each", "scan"),
		"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_UNSPECIFIED, "sources.values()"),
	}
	err := RefuseUnsupportedFanOut(nodes)
	if err == nil {
		t.Fatal("want a refusal for an aggregator declared over a for_each source")
	}
	if !strings.Contains(err.Error(), "custom aggregator") {
		t.Errorf("the refusal does not say an aggregator was declared: %s", err)
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

// The analyser reports the same refusal, so an author sees it in the mission view
// and not only when the run fails.
func TestProject_RefusesAMergeRuleOverAFanOutSource(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionv1.MissionNode{
			"each":   forEachNode("each", "scan"),
			"report": joinNode("report", []string{"each"}, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, ""),
		},
	}
	_, err := Project(def, nil)
	if err == nil {
		t.Fatal("Project accepted a merge rule over a for_each source")
	}
	var verr *ValidationError
	if !asValidationError(err, &verr) {
		t.Fatalf("want a *ValidationError, got %T: %v", err, err)
	}
	if len(verr.FanOutJoinMerge) != 1 {
		t.Fatalf("want one FanOutJoinMerge finding, got %d: %+v", len(verr.FanOutJoinMerge), verr.FanOutJoinMerge)
	}
	got := verr.FanOutJoinMerge[0]
	if got.Join != "report" || got.Source != "each" {
		t.Errorf("finding names join %q over source %q, want report over each", got.Join, got.Source)
	}
}

// asValidationError keeps the assertion in one place; errors.As would need the
// type to implement Unwrap, which a leaf validation error has no reason to.
func asValidationError(err error, out **ValidationError) bool {
	v, ok := err.(*ValidationError)
	if ok {
		*out = v
	}
	return ok
}
