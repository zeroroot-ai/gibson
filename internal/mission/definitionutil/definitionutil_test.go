package definitionutil

import (
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func node(id string) *missionv1.MissionNode {
	return &missionv1.MissionNode{Id: id}
}

func edge(from, to string) *missionv1.MissionEdge {
	return &missionv1.MissionEdge{From: from, To: to}
}

func TestGetNode(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"),
			"b": node("b"),
		},
	}
	cases := []struct {
		name    string
		def     *missionv1.MissionDefinition
		id      string
		wantOK  bool
		wantNil bool
	}{
		{"found", def, "a", true, false},
		{"missing", def, "z", false, true},
		{"nil def", nil, "a", false, true},
		{"nil nodes", &missionv1.MissionDefinition{}, "a", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, ok := GetNode(tc.def, tc.id)
			if ok != tc.wantOK {
				t.Errorf("ok=%v want=%v", ok, tc.wantOK)
			}
			if (n == nil) != tc.wantNil {
				t.Errorf("nil=%v want=%v", n == nil, tc.wantNil)
			}
		})
	}
}

func TestEntryNodeIDs_explicit(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"), "b": node("b"), "c": node("c"),
		},
		EntryPoints: []string{"a", "missing", "c"},
	}
	got := EntryNodeIDs(def)
	want := []string{"a", "c"}
	if !equalStrings(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestEntryNodeIDs_computed(t *testing.T) {
	// a -> b -> c; only `a` has no incoming edge.
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"), "b": node("b"), "c": node("c"),
		},
		Edges: []*missionv1.MissionEdge{edge("a", "b"), edge("b", "c")},
	}
	got := EntryNodeIDs(def)
	want := []string{"a"}
	if !equalStrings(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestEntryNodeIDs_disconnected(t *testing.T) {
	// a, b, c with no edges → all three are entry points.
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"), "b": node("b"), "c": node("c"),
		},
	}
	got := EntryNodeIDs(def)
	want := []string{"a", "b", "c"} // sorted
	if !equalStrings(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestEntryNodeIDs_empty(t *testing.T) {
	if got := EntryNodeIDs(nil); len(got) != 0 {
		t.Errorf("nil def: got=%v want empty", got)
	}
	if got := EntryNodeIDs(&missionv1.MissionDefinition{}); len(got) != 0 {
		t.Errorf("empty def: got=%v want empty", got)
	}
}

func TestExitNodeIDs_explicit(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"), "b": node("b"),
		},
		ExitPoints: []string{"b", "missing"},
	}
	got := ExitNodeIDs(def)
	want := []string{"b"}
	if !equalStrings(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestExitNodeIDs_computed(t *testing.T) {
	// a -> b -> c; only `c` has no outgoing edge.
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": node("a"), "b": node("b"), "c": node("c"),
		},
		Edges: []*missionv1.MissionEdge{edge("a", "b"), edge("b", "c")},
	}
	got := ExitNodeIDs(def)
	want := []string{"c"}
	if !equalStrings(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestEntryNodes_resolvesIDs(t *testing.T) {
	a, b := node("a"), node("b")
	def := &missionv1.MissionDefinition{
		Nodes:       map[string]*missionv1.MissionNode{"a": a, "b": b},
		EntryPoints: []string{"a"},
	}
	got := EntryNodes(def)
	if len(got) != 1 || got[0] != a {
		t.Errorf("got=%v want=[a]", got)
	}
}

func TestExitNodes_resolvesIDs(t *testing.T) {
	a, b := node("a"), node("b")
	def := &missionv1.MissionDefinition{
		Nodes:      map[string]*missionv1.MissionNode{"a": a, "b": b},
		ExitPoints: []string{"b"},
	}
	got := ExitNodes(def)
	if len(got) != 1 || got[0] != b {
		t.Errorf("got=%v want=[b]", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
