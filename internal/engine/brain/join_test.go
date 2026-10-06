// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"strings"
	"testing"
)

// engineWithJoin wires scheduler + join + a dispatcher whose results are JSON
// objects, so REDUCE and CUSTOM have something structured to read.
func engineWithJoin(fails map[string]bool, results map[string]string) *Engine {
	e := NewEngine("t1", &memTimelineStore{})
	e.AddSystem(SchedulerSystem)
	e.AddSystem(JoinSystem)
	e.AddSystem(func(w *World) []Event {
		var out []Event
		for _, wi := range w.WorkSnapshot() {
			if wi.State != WorkRunning {
				continue
			}
			n := nodeOf(wi.ID)
			if fails[n] {
				out = append(out, WorkCompleted{ID: wi.ID, Err: "boom"})
				continue
			}
			r, ok := results[n]
			if !ok {
				r = `{"node":"` + n + `"}`
			}
			out = append(out, WorkCompleted{ID: wi.ID, Result: r})
		}
		return out
	})
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	return e
}

func joinSpecJSON(t *testing.T, spec JoinSpec) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fanOutJoinMission: scan#a, scan#b (a fan-out over two targets) and a plain
// node `whois`, joined by `report` with the given strategy, then `summary`
// depends on the join.
func fanOutJoinMission(t *testing.T, strategy, aggregator string) MissionProjected {
	t.Helper()
	spec := JoinSpec{
		Strategy:   strategy,
		Aggregator: aggregator,
		Sources: []JoinSource{
			{ID: "whois", Nodes: []string{"whois"}},
			{ID: "scan", FanOut: true, Nodes: []string{"scan#a", "scan#b"}, Targets: map[string]string{"scan#a": "a", "scan#b": "b"}},
		},
	}
	return MissionProjected{
		ID: "m1",
		Nodes: []WorkNode{
			{ID: "whois", Kind: "tool", Target: "whois"},
			{ID: "scan#a", Kind: "tool", Target: "nmap", DependentsRunOnFailure: true},
			{ID: "scan#b", Kind: "tool", Target: "nmap", DependentsRunOnFailure: true},
			{ID: "report", Kind: "join", Input: joinSpecJSON(t, spec), DependsOn: []string{"whois", "scan#a", "scan#b"}},
			{ID: "summary", Kind: "agent", Target: "writer", DependsOn: []string{"report"}},
		},
	}
}

func joinResult(t *testing.T, e *Engine, node string) any {
	t.Helper()
	wi := workByNode(e.Work(), node)
	if wi.State != WorkDone {
		t.Fatalf("%s: want done, got %s (err=%q)", node, wi.State, wi.Err)
	}
	var v any
	if err := json.Unmarshal([]byte(wi.Result), &v); err != nil {
		t.Fatalf("%s result is not JSON: %q", node, wi.Result)
	}
	return v
}

// The fixture that fails without the change: a join with a declared strategy
// has a result, and the node after it runs on that result.
func TestJoin_ConcatYieldsSourceOrderWithFanOutEntriesInTimelineOrder(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyConcat, ""))
	e.Tick()

	got := joinResult(t, e, "report").([]any)
	if len(got) != 3 {
		t.Fatalf("CONCAT over one plain source and a two-instance fan-out: want 3 entries, got %v", got)
	}
	if got[0].(map[string]any)["node"] != "whois" {
		t.Errorf("source order: want whois first, got %v", got[0])
	}
	targets := []string{got[1].(map[string]any)["target"].(string), got[2].(map[string]any)["target"].(string)}
	if targets[0] == targets[1] || (targets[0] != "a" && targets[0] != "b") {
		t.Errorf("fan-out entries must be one per target: %v", targets)
	}
	if wi := workByNode(e.Work(), "summary"); wi.State != WorkDone {
		t.Errorf("summary after the join: want done, got %s", wi.State)
	}
	if order := dispatchOrder(e); indexOf(order, "summary") < indexOf(order, "scan#b") {
		t.Errorf("summary dispatched before the fan-out finished: %v", order)
	}
}

func TestJoin_NoStrategyIsTheSourcesMap(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyNone, ""))
	e.Tick()

	got := joinResult(t, e, "report").(map[string]any)
	if _, ok := got["whois"]; !ok {
		t.Errorf("sources map lacks whois: %v", got)
	}
	if entries, ok := got["scan"].([]any); !ok || len(entries) != 2 {
		t.Errorf("sources map fan-out: want 2 entries, got %v", got["scan"])
	}
}

func TestJoin_ReduceDeepMergesObjects(t *testing.T) {
	e := engineWithJoin(nil, map[string]string{
		"whois":  `{"host":{"name":"acme"},"n":1}`,
		"scan#a": `{"host":{"ports":[22]},"n":2}`,
		"scan#b": `{"host":{"os":"linux"}}`,
	})
	e.Submit(fanOutJoinMission(t, JoinStrategyReduce, ""))
	e.Tick()

	got := joinResult(t, e, "report").(map[string]any)
	host := got["host"].(map[string]any)
	for _, k := range []string{"name", "ports", "os"} {
		if _, ok := host[k]; !ok {
			t.Errorf("deep merge lost host.%s: %v", k, got)
		}
	}
	if got["n"] != float64(2) {
		t.Errorf("a later key overwrites an earlier one: n=%v", got["n"])
	}
}

func TestJoin_FirstAndLastFollowTimelineOrder(t *testing.T) {
	for _, tc := range []struct{ strategy, want string }{{JoinStrategyFirst, "whois"}, {JoinStrategyLast, "scan#b"}} {
		e := engineWithJoin(nil, nil)
		e.Submit(fanOutJoinMission(t, tc.strategy, ""))
		e.Tick()
		// The fake dispatcher completes running work in WorkSnapshot order
		// (sorted by id): whois, then scan#a, then scan#b... but completion
		// order is what CompletedSeq recorded, so read it back rather than
		// assume.
		var firstSeq, lastSeq uint64 = ^uint64(0), 0
		var first, last string
		for _, wi := range e.Work() {
			if wi.Kind == "join" || wi.Kind == "agent" || wi.CompletedSeq == 0 {
				continue
			}
			if wi.CompletedSeq < firstSeq {
				firstSeq, first = wi.CompletedSeq, nodeOf(wi.ID)
			}
			if wi.CompletedSeq > lastSeq {
				lastSeq, last = wi.CompletedSeq, nodeOf(wi.ID)
			}
		}
		got := joinResult(t, e, "report")
		want := first
		if tc.strategy == JoinStrategyLast {
			want = last
		}
		var node string
		switch v := got.(type) {
		case map[string]any:
			if r, ok := v["result"].(map[string]any); ok {
				node = r["node"].(string) // a fan-out entry
			} else {
				node = v["node"].(string) // a plain value
			}
		default:
			t.Fatalf("%s: unexpected shape %T", tc.strategy, got)
		}
		if node != want {
			t.Errorf("%s: want %s (seq order), got %s", tc.strategy, want, node)
		}
	}
}

func TestJoin_CustomEvaluatesTheAggregatorOverSources(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyCustom, `sources.scan.map(e, e.target)`))
	e.Tick()

	got := joinResult(t, e, "report").([]any)
	if len(got) != 2 {
		t.Fatalf("aggregator over the fan-out: want 2 targets, got %v", got)
	}
}

func TestJoin_MalformedAggregatorFailsTheNodeNamingTheExpression(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyCustom, `sources.scan.(`))
	e.Tick()

	wi := workByNode(e.Work(), "report")
	if wi.State != WorkFailed {
		t.Fatalf("report: want failed, got %s", wi.State)
	}
	if !strings.Contains(wi.Err, "sources.scan.(") {
		t.Errorf("the failure does not name the expression: %q", wi.Err)
	}
	if s := workByNode(e.Work(), "summary"); s.State == WorkDone {
		t.Errorf("summary ran on a failed join")
	}
	if ms := e.Missions(); ms[0].Status != MissionFailed {
		t.Errorf("mission want failed, got %s", ms[0].Status)
	}
}

func TestJoin_PartiallyFailedFanOutKeepsTheFailureVisible(t *testing.T) {
	e := engineWithJoin(map[string]bool{"scan#b": true}, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyConcat, ""))
	e.Tick()

	got := joinResult(t, e, "report").([]any)
	var failed, ok int
	for _, v := range got[1:] {
		m := v.(map[string]any)
		if m["error"] == "boom" && m["result"] == nil {
			failed++
		} else if m["result"] != nil {
			ok++
		}
	}
	if failed != 1 || ok != 1 {
		t.Errorf("want one succeeded and one failed entry, got %v", got)
	}
	if wi := workByNode(e.Work(), "summary"); wi.State != WorkDone {
		t.Errorf("summary still runs after a partially failed fan-out: %s", wi.State)
	}
}

func TestJoin_ReplayReproducesTheMergedValue(t *testing.T) {
	e := engineWithJoin(map[string]bool{"scan#a": true}, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyLast, ""))
	e.Tick()

	replayed := Replay("t1", e.Timeline)
	if !workEqual(replayed.WorkSnapshot(), e.World.WorkSnapshot()) {
		t.Errorf("replay diverged:\n got %+v\nwant %+v", replayed.WorkSnapshot(), e.World.WorkSnapshot())
	}
	for _, wi := range replayed.WorkSnapshot() {
		live := workByNode(e.Work(), nodeOf(wi.ID))
		if wi.CompletedSeq != live.CompletedSeq {
			t.Errorf("%s: completion order diverged on replay: %d vs %d", wi.ID, wi.CompletedSeq, live.CompletedSeq)
		}
	}
}

func TestJoin_SnapshotRestoreKeepsCompletionOrder(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(fanOutJoinMission(t, JoinStrategyFirst, ""))
	e.Tick()

	restored, err := RestoreWorld(SnapshotWorld(e.World, "1-0"), "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, wi := range restored.WorkSnapshot() {
		live := workByNode(e.Work(), nodeOf(wi.ID))
		if wi.CompletedSeq != live.CompletedSeq {
			t.Errorf("%s: restore lost the completion order: %d vs %d", wi.ID, wi.CompletedSeq, live.CompletedSeq)
		}
	}
}
