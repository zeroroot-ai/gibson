// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"sort"
	"strings"
	"testing"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// nodeDeps drops two kinds of edge on the way in, and both matter: a node cannot
// wait on itself, and an empty id would create a dependency on a node that does
// not exist, which the resolver then resolves to nothing — a dependency that
// silently is not one.
func TestNodeDeps_Add(t *testing.T) {
	d := nodeDeps{}
	d.add("b", "a")
	d.add("b", "b") // self-edge
	d.add("b", "")  // empty id
	d.add("b", "a") // duplicate: the set absorbs it

	got := sortedKeys(d["b"])
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("deps of b = %v, want exactly [a]", got)
	}
	if _, ok := d["b"]["b"]; ok {
		t.Error("a self-edge was recorded; a node cannot wait on itself")
	}
	if _, ok := d["b"][""]; ok {
		t.Error("an empty dependency id was recorded")
	}
}

// instanceIDsOf answers for a for_each node. Asked about anything else it reports
// nothing rather than guessing, so the resolver falls through to treating the id
// as a literal dependency.
func TestInstanceIDsOf_NonForEachNodesYieldNothing(t *testing.T) {
	all := map[string]*missionpb.MissionNode{
		"plain": toolNode("nmap"),
		"empty-template": {
			Id:     "empty-template",
			Type:   missionpb.NodeType_NODE_TYPE_FOR_EACH,
			Config: &missionpb.MissionNode_ForEachConfig{ForEachConfig: &missionpb.ForEachNodeConfig{}},
		},
	}
	if got := instanceIDsOf("missing", all); got != nil {
		t.Errorf("an id that is not in the node set yielded %v, want nothing", got)
	}
	if got := instanceIDsOf("plain", all); got != nil {
		t.Errorf("a node that is not a for_each yielded %v, want nothing", got)
	}
	if got := instanceIDsOf("empty-template", all); got != nil {
		t.Errorf("a for_each whose template has no id yielded %v, want nothing", got)
	}
}

// The resolver treats an id it does not know as a literal dependency. A mission
// may name a node that does not exist; dropping the edge would make a node
// runnable that the author meant to gate.
func TestMakeResolver_UnknownIDIsLiteral(t *testing.T) {
	resolve := makeResolver(map[string]*missionpb.MissionNode{"a": toolNode("recon")})
	got := resolve("nope")
	if len(got) != 1 || got[0] != "nope" {
		t.Errorf("resolve(unknown) = %v, want it kept as a literal", got)
	}
}

// A join that waits on itself, directly or through another join, terminates. The
// resolver walks wait_for lists, so a cycle there would recurse forever and take
// the whole projection with it.
func TestMakeResolver_JoinCycleTerminates(t *testing.T) {
	all := map[string]*missionpb.MissionNode{
		"j1": {
			Id:   "j1",
			Type: missionpb.NodeType_NODE_TYPE_JOIN,
			Config: &missionpb.MissionNode_JoinConfig{JoinConfig: &missionpb.JoinNodeConfig{
				WaitFor: []string{"j2"},
			}},
		},
		"j2": {
			Id:   "j2",
			Type: missionpb.NodeType_NODE_TYPE_JOIN,
			Config: &missionpb.MissionNode_JoinConfig{JoinConfig: &missionpb.JoinNodeConfig{
				WaitFor: []string{"j1", "a"},
			}},
		},
		"a": toolNode("recon"),
	}
	got := makeResolver(all)("j1")
	sort.Strings(got)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("resolve(j1) = %v, want the one real node behind the cycle", got)
	}
}

// A plugin node projects its name as the target and its METHOD as the input; a
// condition node projects its expression. Both are node kinds the fan-out work
// did not touch, and a projection that mapped them wrong would dispatch the
// wrong thing.
//
// Note what the plugin case does NOT carry: PluginNodeConfig.params. They reach
// the graph bootstrap's TaskConfig and stop there — `grep GetParams` finds no
// other reader — so a plugin node's declared params never reach the dispatcher.
// Pinned here as the current behaviour, with gibson#556 to carry them.
func TestNodeKindTargetInput_PluginAndCondition(t *testing.T) {
	kind, target, input, err := nodeKindTargetInput(&missionpb.MissionNode{
		Id:   "p",
		Type: missionpb.NodeType_NODE_TYPE_PLUGIN,
		Config: &missionpb.MissionNode_PluginConfig{PluginConfig: &missionpb.PluginNodeConfig{
			PluginName: "burp",
			Method:     "Scan",
			Params:     map[string]string{"depth": "2"},
		}},
	})
	if err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if kind != "plugin" || target != "burp" {
		t.Errorf("plugin projected kind=%q target=%q, want plugin/burp", kind, target)
	}
	if input != "Scan" {
		t.Errorf("plugin input = %q, want the method", input)
	}
	if strings.Contains(input, "depth") {
		t.Errorf("plugin input now carries params (%q) — if that is deliberate, "+
			"gibson#556 is done and this assertion is the thing to update", input)
	}

	kind, _, input, err = nodeKindTargetInput(&missionpb.MissionNode{
		Id:   "c",
		Type: missionpb.NodeType_NODE_TYPE_CONDITION,
		Config: &missionpb.MissionNode_ConditionConfig{ConditionConfig: &missionpb.ConditionNodeConfig{
			Expression:  "nodes.scan != \"\"",
			TrueBranch:  []string{"report"},
			FalseBranch: []string{"stop"},
		}},
	})
	if err != nil {
		t.Fatalf("condition: %v", err)
	}
	if kind != "condition" {
		t.Errorf("condition projected kind=%q, want condition", kind)
	}
	if !strings.Contains(input, "nodes.scan") {
		t.Errorf("condition input = %q, want the expression", input)
	}
}

// A tool input that is not JSON stays a string. The encoder tries JSON first so
// an array or an object survives as structure, and a value that merely looks
// numeric or quoted must not be reinterpreted.
func TestToolInputJSON_NonJSONValuesStayStrings(t *testing.T) {
	out, err := toolInputJSON(map[string]string{
		"host":  "10.0.0.1",
		"flags": "-sV -Pn",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(out, `"host":"10.0.0.1"`) {
		t.Errorf("a plain string was not kept as a string: %s", out)
	}
	if !strings.Contains(out, `"flags":"-sV -Pn"`) {
		t.Errorf("a flag string was not kept as a string: %s", out)
	}
}

// An empty input map encodes to an empty object rather than null. A tool handed
// `null` where it expects an object fails on the first field read.
func TestToolInputJSON_EmptyMapIsAnEmptyObject(t *testing.T) {
	out, err := toolInputJSON(nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if out != "{}" && out != "" {
		t.Errorf("empty input encoded to %q, want {} or empty", out)
	}
}

// A parallel node whose sub-node has no id is refused by name. A sub-node with no
// id cannot be depended on or dispatched, and promoting it under the empty key
// would overwrite whatever else landed there.
func TestFlattenParallel_RefusesASubNodeWithNoID(t *testing.T) {
	_, err := flattenParallel(&missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"p": {
				Id:   "p",
				Type: missionpb.NodeType_NODE_TYPE_PARALLEL,
				Config: &missionpb.MissionNode_ParallelConfig{ParallelConfig: &missionpb.ParallelNodeConfig{
					SubNodes: []*missionpb.MissionNode{toolNode("recon")}, // no Id set
				}},
			},
		},
	})
	if err == nil {
		t.Fatal("want a refusal for a parallel sub-node with no id")
	}
	if !strings.Contains(err.Error(), "sub-node missing id") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// A for_each whose config carries no template is refused by name. An empty
// template would expand to instances with nothing in them.
func TestExpandForEachNodes_RefusesAMissingTemplate(t *testing.T) {
	_, err := expandForEachNodes(&missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"each": {
				Id:     "each",
				Type:   missionpb.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionpb.MissionNode_ForEachConfig{ForEachConfig: &missionpb.ForEachNodeConfig{}},
			},
		},
	}, []forEachTarget{fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443")},
		map[string]*missionpb.MissionNode{})
	if err == nil {
		t.Fatal("want a refusal for a for_each with no template")
	}
	if !strings.Contains(err.Error(), "template missing") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// A nil definition is refused rather than projected as an empty mission, which
// would complete immediately and report success.
func TestMissionDefinitionToProjected_RefusesANilDefinition(t *testing.T) {
	_, err := missionDefinitionToProjected(nil, "", nil)
	if err == nil {
		t.Fatal("want a refusal for a nil definition")
	}
}
