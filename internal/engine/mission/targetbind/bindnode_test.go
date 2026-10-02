// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package targetbind

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func fanTarget(name, url string) *types.Target {
	return &types.Target{
		ID:   types.NewID(),
		Name: name,
		Type: "kubernetes",
		URL:  url,
	}
}

// toolNode is the shape a for_each template usually has: one tool whose input
// carries the placeholders.
func toolNode(id string, input map[string]string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_TOOL,
		Config: &missionv1.MissionNode_ToolConfig{ToolConfig: &missionv1.ToolNodeConfig{
			ToolName: "nmap",
			Input:    input,
		}},
	}
}

// BindNode is how a fan-out instance gets its own values. Bind() skips a for_each
// template on purpose, so without this the template reaches the instance with its
// placeholders intact and the tool is dispatched against the literal text
// (gibson#525).
func TestBindNode_BindsEveryPlaceholderInTheNode(t *testing.T) {
	tgt := fanTarget("goat-a", "https://10.60.0.11:6443")
	node := toolNode("scan", map[string]string{
		"target": "{{target.host}}",
		"cert":   "{{target.domain}}",
		"label":  "run against {{target.name}} ({{target.type}})",
	})

	out, err := BindNode(node, tgt)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	in := out.GetToolConfig().GetInput()
	if got := in["target"]; got != "10.60.0.11:6443" {
		t.Errorf("target = %q, want host:port", got)
	}
	if got := in["cert"]; got != "10.60.0.11" {
		t.Errorf("cert = %q, want the host alone", got)
	}
	if got := in["label"]; got != "run against goat-a (kubernetes)" {
		t.Errorf("label = %q, want both placeholders bound in one string", got)
	}
}

// The input node is never mutated. Expansion binds one template per target, so a
// mutating bind would leave the second instance reading the first one's values.
func TestBindNode_DoesNotMutateTheTemplate(t *testing.T) {
	node := toolNode("scan", map[string]string{"target": "{{target.host}}"})
	if _, err := BindNode(node, fanTarget("a", "https://10.0.0.1:6443")); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if got := node.GetToolConfig().GetInput()["target"]; got != "{{target.host}}" {
		t.Fatalf("the template was mutated to %q; the next instance would inherit it", got)
	}

	// Proven by binding the same template again against a different target.
	out, err := BindNode(node, fanTarget("b", "https://10.0.0.2:6443"))
	if err != nil {
		t.Fatalf("second bind: %v", err)
	}
	if got := out.GetToolConfig().GetInput()["target"]; got != "10.0.0.2:6443" {
		t.Errorf("second instance bound to %q, want its own host", got)
	}
}

// A placeholder that names nothing is refused, with the path to it. A tool handed
// the literal text reports a clean run against a host that does not exist, which
// is the quietest way for a scan to find nothing.
func TestBindNode_RefusesAnUnknownPlaceholder(t *testing.T) {
	node := toolNode("scan", map[string]string{"target": "{{target.nope}}"})
	_, err := BindNode(node, fanTarget("a", "https://10.0.0.1:6443"))
	if err == nil {
		t.Fatal("want a refusal for a placeholder that names nothing")
	}
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("the refusal does not name the node: %v", err)
	}
	if !strings.Contains(err.Error(), "target.nope") {
		t.Errorf("the refusal does not name the unresolved placeholder: %v", err)
	}
}

// A nil node and a nil target are each refused by name rather than panicking or
// binding against nothing.
func TestBindNode_RefusesNilInputs(t *testing.T) {
	if _, err := BindNode(nil, fanTarget("a", "https://10.0.0.1:6443")); err == nil {
		t.Error("want a refusal for a nil node")
	}
	_, err := BindNode(toolNode("scan", nil), nil)
	if err == nil {
		t.Fatal("want a refusal for a nil target")
	}
	if !strings.Contains(err.Error(), "names no target") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// BindNode reaches a nested for_each template, unlike Bind. That is the
// difference between the two functions, and it is why the projection refuses a
// nested for_each before expansion rather than relying on binding to notice.
func TestBindNode_ReachesANestedForEachTemplate(t *testing.T) {
	node := &missionv1.MissionNode{
		Id:   "outer",
		Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
		Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
			Source:   missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
			Template: toolNode("inner", map[string]string{"target": "{{target.host}}"}),
		}},
	}

	out, err := BindNode(node, fanTarget("a", "https://10.0.0.5:6443"))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	got := out.GetForEachConfig().GetTemplate().GetToolConfig().GetInput()["target"]
	if got != "10.0.0.5:6443" {
		t.Errorf("the nested template was not bound: %q", got)
	}
}

// Bind, by contrast, leaves a for_each template alone — the skip the expansion
// depends on. Without it the template would be bound to the mission's primary
// before expansion ever saw it, and every instance would scan that one host.
func TestBind_SkipsAForEachTemplate(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionv1.MissionNode{
			"each": {
				Id:   "each",
				Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
					Source:   missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
					Template: toolNode("scan", map[string]string{"target": "{{target.host}}"}),
				}},
			},
			"other": toolNode("other", map[string]string{"target": "{{target.host}}"}),
		},
	}

	out, err := Bind(def, fanTarget("primary", "https://10.0.0.1:6443"))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	tpl := out.GetNodes()["each"].GetForEachConfig().GetTemplate().GetToolConfig().GetInput()["target"]
	if tpl != "{{target.host}}" {
		t.Errorf("the for_each template was bound to %q; expansion needs it unbound so each "+
			"instance binds to its own target", tpl)
	}
	// Every other node IS bound, so the skip is narrow rather than a hole.
	if got := out.GetNodes()["other"].GetToolConfig().GetInput()["target"]; got != "10.0.0.1:6443" {
		t.Errorf("an ordinary node was not bound: %q", got)
	}
}

// UnboundTarget is what the projection backstop reads. It must see a placeholder
// anywhere in the node, including in a map key, because a key that keeps its
// placeholder while its value resolves is the harder bug to spot.
func TestUnboundTarget_FindsPlaceholdersInKeysAndValues(t *testing.T) {
	node := toolNode("scan", map[string]string{
		"{{target.name}}": "fixed",
		"target":          "{{target.host}}",
	})
	left := UnboundTarget(node)
	if len(left) != 2 {
		t.Fatalf("found %d unbound placeholders, want 2: %v", len(left), left)
	}
	joined := strings.Join(left, " ")
	for _, want := range []string{"target.name", "target.host"} {
		if !strings.Contains(joined, want) {
			t.Errorf("UnboundTarget missed %q: %v", want, left)
		}
	}
}

// A fully bound node reports nothing, so the backstop does not refuse work that
// was bound correctly.
func TestUnboundTarget_SaysNothingAboutABoundNode(t *testing.T) {
	bound, err := BindNode(toolNode("scan", map[string]string{"target": "{{target.host}}"}),
		fanTarget("a", "https://10.0.0.1:6443"))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if left := UnboundTarget(bound); len(left) != 0 {
		t.Errorf("a bound node reported unbound placeholders: %v", left)
	}
}
