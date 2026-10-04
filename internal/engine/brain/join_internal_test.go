package brain

import (
	"reflect"
	"strings"
	"testing"
)

func doneWork(mission, node, result string, seq uint64) (string, WorkSnapshot) {
	id := WorkID(mission, node)
	return id, WorkSnapshot{ID: id, MissionID: mission, State: WorkDone, Result: result, CompletedSeq: seq}
}

func joinIndex(items ...func() (string, WorkSnapshot)) map[string]WorkSnapshot {
	idx := map[string]WorkSnapshot{}
	for _, it := range items {
		id, ws := it()
		idx[id] = ws
	}
	return idx
}

func done(node, result string, seq uint64) func() (string, WorkSnapshot) {
	return func() (string, WorkSnapshot) { return doneWork("m", node, result, seq) }
}

// TestMergeJoin_RefusalsNameTheCause proves each join that cannot merge fails
// with an error that names what is wrong, so an author never reads a value
// from a rule that did not run.
func TestMergeJoin_RefusalsNameTheCause(t *testing.T) {
	idx := joinIndex(done("a", `{"x":1}`, 1))
	cases := []struct {
		name string
		spec JoinSpec
		want string
	}{
		{"a fan-out source names unknown work", JoinSpec{Sources: []JoinSource{{ID: "scan", FanOut: true, Nodes: []string{"missing"}}}}, `source "scan" names unknown work "missing"`},
		{"a plain source resolves to two nodes", JoinSpec{Sources: []JoinSource{{ID: "a", Nodes: []string{"a", "b"}}}}, `source "a" resolves to 2 nodes, want one`},
		{"a plain source names unknown work", JoinSpec{Sources: []JoinSource{{ID: "b", Nodes: []string{"b"}}}}, `source "b" names unknown work "b"`},
		{"FIRST has no source", JoinSpec{Strategy: JoinStrategyFirst}, "strategy FIRST over no sources"},
		{"the strategy is unknown", JoinSpec{Strategy: "SHUFFLE", Sources: []JoinSource{{ID: "a", Nodes: []string{"a"}}}}, `unknown merge strategy "SHUFFLE"`},
		{"CUSTOM declares no aggregator", JoinSpec{Strategy: JoinStrategyCustom, Sources: []JoinSource{{ID: "a", Nodes: []string{"a"}}}}, "strategy CUSTOM declares no aggregator"},
		{"the aggregator fails at evaluation", JoinSpec{Strategy: JoinStrategyCustom, Aggregator: "sources.absent.x", Sources: []JoinSource{{ID: "a", Nodes: []string{"a"}}}}, `aggregator "sources.absent.x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mergeJoin(tc.spec, "m", idx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one that contains %q", err, tc.want)
			}
		})
	}
}

// TestMergeJoin_ReduceKeepsValuesThatAreNotObjects proves REDUCE does not
// drop a source whose result is not an object: it collects them under "_",
// and a result that is not JSON is read as the raw string.
func TestMergeJoin_ReduceKeepsValuesThatAreNotObjects(t *testing.T) {
	idx := joinIndex(done("a", `{"x":1}`, 1), done("b", `plain text`, 2), done("c", `7`, 3))
	spec := JoinSpec{Strategy: JoinStrategyReduce, Sources: []JoinSource{
		{ID: "a", Nodes: []string{"a"}}, {ID: "b", Nodes: []string{"b"}}, {ID: "c", Nodes: []string{"c"}},
	}}
	got, err := mergeJoin(spec, "m", idx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"x": float64(1), "_": []any{"plain text", float64(7)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %#v, want %#v", got, want)
	}
}

// TestMergeJoin_CustomSeesAFailedInstance proves the aggregator reads the
// error of a failed fan-out instance next to its target.
func TestMergeJoin_CustomSeesAFailedInstance(t *testing.T) {
	failedID := WorkID("m", "scan-2")
	idx := joinIndex(done("scan-1", `{"open":22}`, 1))
	idx[failedID] = WorkSnapshot{ID: failedID, MissionID: "m", State: WorkFailed, Err: "timeout", CompletedSeq: 2}
	spec := JoinSpec{Strategy: JoinStrategyCustom, Aggregator: `sources.scan.filter(e, has(e.error)).map(e, e.target + ": " + e.error)`,
		Sources: []JoinSource{{ID: "scan", FanOut: true, Nodes: []string{"scan-1", "scan-2"}, Targets: map[string]string{"scan-1": "h1", "scan-2": "h2"}}}}
	got, err := mergeJoin(spec, "m", idx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []any{"h2: timeout"}) {
		t.Fatalf("merged = %#v, want the failed instance named with its error", got)
	}
}

// TestJoinSystem_MalformedSpecFailsTheNode proves a join whose input is not a
// JoinSpec fails with a named error, and does not stay pending forever.
func TestJoinSystem_MalformedSpecFailsTheNode(t *testing.T) {
	e := engineWithJoin(nil, nil)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "whois", Kind: "tool", Target: "whois"},
		{ID: "report", Kind: "join", Input: "{not json", DependsOn: []string{"whois"}},
	}})
	e.Tick()

	wi := workByNode(e.Work(), "report")
	if wi.State != WorkFailed || !strings.Contains(wi.Err, "malformed join node") {
		t.Fatalf("report: state=%s err=%q, want failed with a malformed join node error", wi.State, wi.Err)
	}
}
