// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"fmt"
	"testing"
	"time"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// passMargin is the least time that the node timeout must keep above the coding
// timeout plus the merge wait. It covers the start of the sandbox and the report.
const passMargin = 10 * time.Minute

// timeoutProblem says why the node timeout of a fix-pass definition cannot hold
// one pass. It returns an empty string when the timeout is long enough.
//
// One pass needs the coding timeout plus the merge wait, and the node timeout
// must be above that sum by passMargin. A node with no timeout gets the 30
// minute default of the launcher, which is below the sum for any real pass.
func timeoutProblem(def *missionpb.MissionDefinition, coding, mergeWait time.Duration) string {
	node := def.GetNodes()["pass"]
	if node == nil {
		return "the mission has no pass node"
	}
	if node.GetTimeout() == nil {
		return "the pass node has no timeout, so the launcher default of 30 minutes applies"
	}
	got, need := node.GetTimeout().AsDuration(), coding+mergeWait+passMargin
	if got < need {
		return fmt.Sprintf("the node timeout %s is below the coding timeout %s plus the merge wait %s plus the margin %s",
			got, coding, mergeWait, passMargin)
	}
	return ""
}

func renderPass(t *testing.T, mutate func(map[string]string)) *missionpb.MissionDefinition {
	t.Helper()
	p := paramsFor(t, "fix-pass")
	if mutate != nil {
		mutate(p)
	}
	def, err := Render(context.Background(), "fix-pass", p)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return def
}

// The mission runs fix-agent on one node and gives it each key that the agent
// reads.
func TestFixPass_RunsTheFixAgentWithItsContext(t *testing.T) {
	t.Parallel()
	def := renderPass(t, nil)
	if len(def.GetNodes()) != 1 {
		t.Fatalf("nodes = %d, want one agent node", len(def.GetNodes()))
	}
	node := def.GetNodes()["pass"]
	if node.GetType() != missionpb.NodeType_NODE_TYPE_AGENT {
		t.Fatalf("node type = %v, want an agent", node.GetType())
	}
	cfg := node.GetAgentConfig()
	if cfg.GetAgentName() != "fix-agent" {
		t.Errorf("agent = %q, want fix-agent", cfg.GetAgentName())
	}
	want := map[string]string{
		"application": "customer-portal",
		"bank":        "bank/coding",
		"connector":   "connector/gitlab-fixloop",
		"project":     "examplebank/customer-portal",
		"finding":     "finding-42",
		"target":      "target-7",
		"base_branch": "main",
		"repository":  "customer-portal",
		"timeout":     "45m",
		"merge_wait":  "30m",
	}
	ctx := cfg.GetTask().GetContext()
	for k, v := range want {
		if got := ctx[k].GetStringValue(); got != v {
			t.Errorf("context %q = %q, want %q", k, got, v)
		}
	}
	if len(ctx) != len(want) {
		t.Errorf("context has %d keys, want %d", len(ctx), len(want))
	}
}

// The optional parameters leave their keys out. The durations take the defaults
// of the agent.
func TestFixPass_OptionalParametersTakeDefaults(t *testing.T) {
	t.Parallel()
	def := renderPass(t, func(p map[string]string) {
		for _, k := range []string{"finding", "target", "baseBranch", "repository", "codingTimeout", "mergeWait"} {
			delete(p, k)
		}
	})
	ctx := def.GetNodes()["pass"].GetAgentConfig().GetTask().GetContext()
	for _, k := range []string{"finding", "target", "base_branch", "repository"} {
		if _, ok := ctx[k]; ok {
			t.Errorf("context key %q is set, want it left out", k)
		}
	}
	if ctx["timeout"].GetStringValue() != "45m" || ctx["merge_wait"].GetStringValue() != "30m" {
		t.Errorf("durations = %q and %q, want 45m and 30m", ctx["timeout"].GetStringValue(), ctx["merge_wait"].GetStringValue())
	}
	if p := timeoutProblem(def, 45*time.Minute, 30*time.Minute); p != "" {
		t.Error(p)
	}
}

// The node timeout covers the coding timeout plus the merge wait for the
// defaults and for other values. This is the guard.
func TestFixPass_NodeTimeoutCoversCodingTimeoutPlusMergeWait(t *testing.T) {
	t.Parallel()
	cases := []struct{ coding, mergeWait string }{
		{"45m", "30m"},
		{"5m", "1m"},
		{"90m", "45m"},
		{"8h", "2h"},
		{"1500ms", "500ms"},
	}
	for _, c := range cases {
		t.Run(c.coding+"+"+c.mergeWait, func(t *testing.T) {
			t.Parallel()
			def := renderPass(t, func(p map[string]string) {
				p["codingTimeout"], p["mergeWait"] = c.coding, c.mergeWait
			})
			coding, _ := time.ParseDuration(c.coding)
			mergeWait, _ := time.ParseDuration(c.mergeWait)
			if p := timeoutProblem(def, coding, mergeWait); p != "" {
				t.Error(p)
			}
		})
	}
}

// The default pass is above the 30 minute launcher default, and above the 105
// minutes that one pass of the agent can need.
func TestFixPass_DefaultNodeTimeoutIsAboveTheLongestPass(t *testing.T) {
	t.Parallel()
	got := renderPass(t, nil).GetNodes()["pass"].GetTimeout().AsDuration()
	if got < 105*time.Minute {
		t.Errorf("node timeout = %s, want at least 105m", got)
	}
}

// A duration that is not a duration, or that is not above zero, refuses the render.
func TestFixPass_BadDurationsRefuseTheRender(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ key, val string }{
		{"codingTimeout", "soon"},
		{"codingTimeout", "0s"},
		{"codingTimeout", "-5m"},
		{"mergeWait", "soon"},
		{"mergeWait", "0"},
	} {
		p := paramsFor(t, "fix-pass")
		p[c.key] = c.val
		if _, err := Render(context.Background(), "fix-pass", p); err == nil {
			t.Errorf("render with %s=%q: want an error", c.key, c.val)
		}
	}
}

// The failing fixture of the guard. A definition with no timeout, and one with
// a timeout below the sum, must each be reported.
func TestTimeoutProblem_ReportsATimeoutThatCannotHoldAPass(t *testing.T) {
	t.Parallel()
	node := func(d *time.Duration) *missionpb.MissionDefinition {
		n := &missionpb.MissionNode{Id: "pass"}
		if d != nil {
			n.Timeout = durationpb.New(*d)
		}
		return &missionpb.MissionDefinition{Nodes: map[string]*missionpb.MissionNode{"pass": n}}
	}
	coding, mergeWait := 45*time.Minute, 30*time.Minute
	short, exact, enough := 30*time.Minute, coding+mergeWait, coding+mergeWait+passMargin

	if timeoutProblem(node(nil), coding, mergeWait) == "" {
		t.Error("no timeout: want a problem")
	}
	if timeoutProblem(node(&short), coding, mergeWait) == "" {
		t.Error("30m timeout: want a problem")
	}
	if timeoutProblem(node(&exact), coding, mergeWait) == "" {
		t.Error("a timeout equal to the sum with no margin: want a problem")
	}
	if p := timeoutProblem(node(&enough), coding, mergeWait); p != "" {
		t.Errorf("a long enough timeout: got %q", p)
	}
	if timeoutProblem(&missionpb.MissionDefinition{}, coding, mergeWait) == "" {
		t.Error("no pass node: want a problem")
	}
}
