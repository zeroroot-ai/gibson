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

// passMargin is the least time that the node timeout must keep above the worst
// pass. It covers the start of the sandbox and the report.
const passMargin = 10 * time.Minute

// The model of the worst pass of fix-agent 0.2.0. A coding job takes up to the
// coding timeout plus passStatusRead. The agent starts passMaxAttempts jobs when
// no Finding is named and one job when it is. It waits passMergeWaits times for
// the merge slot: once for an older open merge request and once for its own.
const (
	passStatusRead  = 30 * time.Second
	passMaxAttempts = 3
	passMergeWaits  = 2
)

// passNeed is the least node timeout that holds the worst pass.
func passNeed(coding, mergeWait time.Duration, findingSet bool) time.Duration {
	attempts := time.Duration(passMaxAttempts)
	if findingSet {
		attempts = 1
	}
	return attempts*(coding+passStatusRead) + passMergeWaits*mergeWait + passMargin
}

// timeoutProblem says why the node timeout of a fix-pass definition cannot hold
// the worst pass. It returns an empty string when the timeout is long enough.
//
// A node with no timeout gets the 30 minute default of the launcher, which is
// below the need for any real pass.
func timeoutProblem(def *missionpb.MissionDefinition, coding, mergeWait time.Duration, findingSet bool) string {
	node := def.GetNodes()["pass"]
	if node == nil {
		return "the mission has no pass node"
	}
	if node.GetTimeout() == nil {
		return "the pass node has no timeout, so the launcher default of 30 minutes applies"
	}
	got, need := node.GetTimeout().AsDuration(), passNeed(coding, mergeWait, findingSet)
	if got < need {
		return fmt.Sprintf("the node timeout %s is below %s (coding timeout %s, merge wait %s, finding set %t)",
			got, need, coding, mergeWait, findingSet)
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
	if p := timeoutProblem(def, 45*time.Minute, 30*time.Minute, false); p != "" {
		t.Error(p)
	}
}

// The node timeout holds the worst pass for the defaults and for other values,
// with a named Finding and without one. This is the guard.
func TestFixPass_NodeTimeoutHoldsTheWorstPass(t *testing.T) {
	t.Parallel()
	cases := []struct{ coding, mergeWait string }{
		{"45m", "30m"},
		{"5m", "1m"},
		{"90m", "45m"},
		{"8h", "2h"},
		{"1500ms", "500ms"},
	}
	for _, c := range cases {
		for _, findingSet := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s+%s finding=%t", c.coding, c.mergeWait, findingSet), func(t *testing.T) {
				t.Parallel()
				def := renderPass(t, func(p map[string]string) {
					p["codingTimeout"], p["mergeWait"] = c.coding, c.mergeWait
					if !findingSet {
						delete(p, "finding")
					}
				})
				coding, _ := time.ParseDuration(c.coding)
				mergeWait, _ := time.ParseDuration(c.mergeWait)
				if p := timeoutProblem(def, coding, mergeWait, findingSet); p != "" {
					t.Error(p)
				}
			})
		}
	}
}

// The default pass is above the 30 minute launcher default and above the 105
// minutes of one attempt. With no finding it holds three attempts.
func TestFixPass_DefaultNodeTimeouts(t *testing.T) {
	t.Parallel()
	with := renderPass(t, nil).GetNodes()["pass"].GetTimeout().AsDuration()
	without := renderPass(t, func(p map[string]string) {
		delete(p, "finding")
		delete(p, "codingTimeout")
		delete(p, "mergeWait")
	}).GetNodes()["pass"].GetTimeout().AsDuration()
	if with < 105*time.Minute {
		t.Errorf("node timeout with a finding = %s, want at least 105m", with)
	}
	if want := 3*(45*time.Minute+passStatusRead) + 60*time.Minute; without < want {
		t.Errorf("node timeout without a finding = %s, want at least %s", without, want)
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

// The failing fixtures of the guard. Each timeout below holds a weaker model than
// the worst pass, so each must be reported.
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
	job := coding + passStatusRead
	short := 30 * time.Minute
	noMargin := job + 2*mergeWait
	oneMergeWait := job + mergeWait + passMargin
	oneAttempt := job + 2*mergeWait + passMargin
	threeAttempts := 3*job + 2*mergeWait + passMargin

	for name, c := range map[string]struct {
		def        *missionpb.MissionDefinition
		findingSet bool
	}{
		"no timeout":                  {node(nil), true},
		"the 30 minute default":       {node(&short), true},
		"no margin":                   {node(&noMargin), true},
		"one merge wait, finding set": {node(&oneMergeWait), true},
		"one merge wait, no finding":  {node(&oneMergeWait), false},
		"one attempt, no finding":     {node(&oneAttempt), false},
		"no pass node":                {&missionpb.MissionDefinition{}, true},
	} {
		if timeoutProblem(c.def, coding, mergeWait, c.findingSet) == "" {
			t.Errorf("%s: want a problem", name)
		}
	}
	if p := timeoutProblem(node(&oneAttempt), coding, mergeWait, true); p != "" {
		t.Errorf("one attempt with a finding set: got %q", p)
	}
	if p := timeoutProblem(node(&threeAttempts), coding, mergeWait, false); p != "" {
		t.Errorf("three attempts with no finding: got %q", p)
	}
}
