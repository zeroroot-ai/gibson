// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// fanTarget builds one resolved target for a for_each source set. The URL is
// what targetbind reads to produce {{target.host}} and {{target.domain}}.
func fanTarget(id, name, url string) forEachTarget {
	return forEachTarget{
		ID: id,
		Target: &types.Target{
			ID:   types.ID(id),
			Name: name,
			Type: "kubernetes",
			URL:  url,
		},
	}
}

// forEachDef is a mission with one for_each tool node whose input carries a
// per-instance placeholder, plus a join that waits on the whole fan-out.
func forEachDef(maxConcurrency int32) *missionpb.MissionDefinition {
	tpl := &missionpb.MissionNode{
		Id:   "scan",
		Type: missionpb.NodeType_NODE_TYPE_TOOL,
		Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
			ToolName: "nmap",
			Input:    map[string]string{"target": "{{target.host}}"},
		}},
	}
	return &missionpb.MissionDefinition{
		Id: "m-fanout",
		Nodes: map[string]*missionpb.MissionNode{
			"each": {
				Id:   "each",
				Type: missionpb.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionpb.MissionNode_ForEachConfig{ForEachConfig: &missionpb.ForEachNodeConfig{
					Source:         missionpb.ForEachNodeConfig_SOURCE_TARGET_SET,
					MaxConcurrency: maxConcurrency,
					Template:       tpl,
				}},
			},
			"report": {
				Id:   "report",
				Type: missionpb.NodeType_NODE_TYPE_JOIN,
				Config: &missionpb.MissionNode_JoinConfig{JoinConfig: &missionpb.JoinNodeConfig{
					WaitFor: []string{"each"},
				}},
			},
		},
	}
}

// Two targets, two dispatches, each bound to its own target. This is the whole
// point of the epic: before fan-out, a two-target mission scanned the primary
// and reported as though it had covered both (gibson#525).
func TestForEach_TwoTargetsTwoDispatchesEachBoundToItsOwn(t *testing.T) {
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "goat-a", "https://10.60.0.11:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "goat-b", "https://10.60.0.12:6443"),
	}

	proj, err := missionDefinitionToProjected(forEachDef(0), "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	// The for_each node itself is collapsed, like parallel and join: only its
	// instances are work.
	byID := map[string]string{} // work node id -> input
	for _, n := range proj.Nodes {
		byID[n.ID] = n.Input
		if n.ID == "each" {
			t.Error("the for_each node must not become a work node; only its instances do")
		}
		if n.ID == "scan" {
			t.Error("the bare template must not become a work node; it has no target")
		}
	}

	wantA := "scan#11111111-1111-1111-1111-111111111111"
	wantB := "scan#22222222-2222-2222-2222-222222222222"
	for _, id := range []string{wantA, wantB} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("instance %q missing; projected ids: %v", id, sortedIDs(proj.Nodes))
		}
	}

	// Each instance carries ITS OWN host, not the primary's.
	if !strings.Contains(byID[wantA], "10.60.0.11") {
		t.Errorf("instance A input = %q, want 10.60.0.11", byID[wantA])
	}
	if !strings.Contains(byID[wantB], "10.60.0.12") {
		t.Errorf("instance B input = %q, want 10.60.0.12", byID[wantB])
	}
	if strings.Contains(byID[wantB], "10.60.0.11") {
		t.Errorf("instance B leaked the first target's host: %q — this is the "+
			"failure mode the epic exists to remove", byID[wantB])
	}

	// No instance may still carry the placeholder: a tool handed the literal
	// text reports a clean run against a host that does not exist.
	for id, in := range byID {
		if strings.Contains(in, "{{target.") {
			t.Errorf("instance %q was never bound: %q", id, in)
		}
	}
}

// A single-target run expands to exactly one instance and is indistinguishable
// from the pre-fan-out behaviour, which is every mission submitted today.
func TestForEach_SingleTargetIsOneInstance(t *testing.T) {
	targets := []forEachTarget{
		fanTarget("33333333-3333-3333-3333-333333333333", "only", "https://10.0.0.1:6443"),
	}
	proj, err := missionDefinitionToProjected(forEachDef(0), "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	instances := 0
	for _, n := range proj.Nodes {
		if strings.HasPrefix(n.ID, "scan#") {
			instances++
		}
	}
	if instances != 1 {
		t.Errorf("single-target run produced %d instances, want 1", instances)
	}
}

// The join waits for EVERY instance, not the first. A join that fired after one
// instance would report a fan-out complete with most of its targets unscanned.
func TestForEach_JoinWaitsForEveryInstance(t *testing.T) {
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "b", "https://10.0.0.2:6443"),
		fanTarget("33333333-3333-3333-3333-333333333333", "c", "https://10.0.0.3:6443"),
	}
	def := forEachDef(0)
	// Something downstream of the join, so the join's resolution is observable
	// in a work node's DependsOn.
	def.Nodes["after"] = agentNode("writer", "report")

	proj, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	var after []string
	for _, n := range proj.Nodes {
		if n.ID == "after" {
			after = n.DependsOn
		}
	}
	if after == nil {
		t.Fatal("the downstream node did not project")
	}
	for _, id := range targets {
		want := "scan#" + id.ID
		found := false
		for _, d := range after {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("a node after the join does not depend on instance %q; DependsOn = %v", want, after)
		}
	}
}

// The concurrency bound is built on DependsOn, because nothing in the brain
// honours MaxConcurrency (gibson#536). With a limit of 2 and five targets,
// instance k waits on instance k-2, so at most two are ever runnable.
func TestForEach_MaxConcurrencyChainsInstances(t *testing.T) {
	var targets []forEachTarget
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("%08d-0000-0000-0000-000000000000", i)
		targets = append(targets, fanTarget(id, fmt.Sprintf("t%d", i), fmt.Sprintf("https://10.0.0.%d:6443", i)))
	}

	proj, err := missionDefinitionToProjected(forEachDef(2), "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	deps := map[string][]string{}
	for _, n := range proj.Nodes {
		if strings.HasPrefix(n.ID, "scan#") {
			deps[n.ID] = n.DependsOn
		}
	}
	if len(deps) != 5 {
		t.Fatalf("want 5 instances, got %d", len(deps))
	}

	ids := make([]string, 0, len(deps))
	for id := range deps {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// The first `limit` instances are unchained; every later one waits on the
	// instance `limit` places ahead.
	for k, id := range ids {
		chained := false
		for _, d := range deps[id] {
			if strings.HasPrefix(d, "scan#") {
				chained = true
				if k >= 2 && d != ids[k-2] {
					t.Errorf("instance %d chains to %q, want %q", k, d, ids[k-2])
				}
			}
		}
		if k < 2 && chained {
			t.Errorf("instance %d is within the limit and must not be chained: %v", k, deps[id])
		}
		if k >= 2 && !chained {
			t.Errorf("instance %d is beyond the limit and must be chained: %v", k, deps[id])
		}
	}
}

// A limit at or above the instance count chains nothing: the author asked for a
// ceiling, not an ordering.
func TestForEach_MaxConcurrencyAtOrAboveCountChainsNothing(t *testing.T) {
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "b", "https://10.0.0.2:6443"),
	}
	for _, limit := range []int32{2, 9} {
		proj, err := missionDefinitionToProjected(forEachDef(limit), "", targets)
		if err != nil {
			t.Fatalf("limit %d: project: %v", limit, err)
		}
		for _, n := range proj.Nodes {
			if !strings.HasPrefix(n.ID, "scan#") {
				continue
			}
			for _, d := range n.DependsOn {
				if strings.HasPrefix(d, "scan#") {
					t.Errorf("limit %d: instance %q chained to %q, want no chain", limit, n.ID, d)
				}
			}
		}
	}
}

// A for_each on a run that resolved no targets is refused rather than expanded
// to nothing. Silently projecting zero instances would complete a mission that
// scanned nothing and report success.
func TestForEach_NoTargetsIsRefused(t *testing.T) {
	_, err := missionDefinitionToProjected(forEachDef(0), "", nil)
	if err == nil {
		t.Fatal("want a refusal when a for_each run resolved no targets")
	}
	if !strings.Contains(err.Error(), "expand to nothing") {
		t.Errorf("error does not explain the refusal: %v", err)
	}
}

// A target in the set that did not resolve fails the projection. Expanding over
// the ones that did resolve would cover less than the author asked for and say
// nothing about it.
func TestForEach_UnresolvedTargetIsRefused(t *testing.T) {
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		{ID: "22222222-2222-2222-2222-222222222222"}, // resolved to nil
	}
	_, err := missionDefinitionToProjected(forEachDef(0), "", targets)
	if err == nil {
		t.Fatal("want a refusal when a target in the set did not resolve")
	}
	if !strings.Contains(err.Error(), "did not resolve") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

// sortedIDs names what actually projected, so a failure says which ids exist
// rather than only which one was missing.
func sortedIDs(nodes []brain.WorkNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	sort.Strings(out)
	return out
}
