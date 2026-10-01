// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package targetbind

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typesv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func goatTarget() *types.Target {
	t := types.NewTarget("kubernetes-goat", "https://goat.internal:8080", types.TargetTypeCustom)
	return t
}

// toolDef is the shape the catalog's scan mission renders: a tool node whose
// input reads the bound target.
func toolDef(input map[string]string) *missionv1.MissionDefinition {
	return &missionv1.MissionDefinition{
		Id:   "scan",
		Name: "scan",
		Nodes: map[string]*missionv1.MissionNode{
			"ports": {
				Id:   "ports",
				Type: missionv1.NodeType_NODE_TYPE_TOOL,
				Config: &missionv1.MissionNode_ToolConfig{
					ToolConfig: &missionv1.ToolNodeConfig{ToolName: "nmap", Input: input},
				},
			},
		},
	}
}

func TestBindings_SplitsHostFromPort(t *testing.T) {
	b := Bindings(goatTarget())
	assert.Equal(t, "https://goat.internal:8080", b["target.url"])
	assert.Equal(t, "goat.internal:8080", b["target.host"], "host keeps the port a dialer needs")
	assert.Equal(t, "goat.internal", b["target.domain"], "domain drops the port a scanner must not see")
	assert.Equal(t, "kubernetes-goat", b["target.name"])
}

func TestBindings_AcceptsASchemelessEndpoint(t *testing.T) {
	// A target registered by a cluster endpoint carries no scheme.
	b := Bindings(types.NewTarget("svc", "goat.gibson.svc:6443", types.TargetTypeCustom))
	assert.Equal(t, "goat.gibson.svc:6443", b["target.host"])
	assert.Equal(t, "goat.gibson.svc", b["target.domain"])
}

func TestBindings_ReadsConnectionURLWhenURLIsUnset(t *testing.T) {
	tgt := &types.Target{
		ID:         types.NewID(),
		Name:       "older-record",
		Connection: map[string]any{"url": "https://legacy.internal"},
	}
	assert.Equal(t, "legacy.internal", Bindings(tgt)["target.domain"])
}

// The gibson#495 regression. The catalog mission's comment said the host was
// "bound from the mission's target at submit"; nothing bound it, so the tool was
// dispatched with the literal text as its hostname.
func TestBind_ReplacesTheTargetPlaceholder(t *testing.T) {
	def := toolDef(map[string]string{"host": "{{target.domain}}", "ports": "1-65535"})

	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	got := out.GetNodes()["ports"].GetToolConfig().GetInput()
	assert.Equal(t, "goat.internal", got["host"])
	assert.Equal(t, "1-65535", got["ports"], "a value with no placeholder is untouched")
	assert.NotContains(t, got["host"], Open, "no placeholder survives into the dispatched input")
}

func TestBind_DoesNotModifyTheInput(t *testing.T) {
	def := toolDef(map[string]string{"host": "{{target.domain}}"})

	_, err := Bind(def, goatTarget())
	require.NoError(t, err)

	assert.Equal(t, "{{target.domain}}", def.GetNodes()["ports"].GetToolConfig().GetInput()["host"],
		"the stored definition is the template and must stay one")
}

func TestBind_BindsEveryStringInTheMessage(t *testing.T) {
	// Not a list of the fields that carry a placeholder today: a list would have
	// to grow with each new node config, and the one that got missed would
	// dispatch the placeholder verbatim.
	def := &missionv1.MissionDefinition{
		Id:          "mixed",
		Name:        "scan {{target.name}}",
		Description: "against {{target.url}}",
		Nodes: map[string]*missionv1.MissionNode{
			"web": {
				Id:   "web",
				Type: missionv1.NodeType_NODE_TYPE_TOOL,
				Config: &missionv1.MissionNode_ToolConfig{
					ToolConfig: &missionv1.ToolNodeConfig{
						ToolName: "httpx",
						Input:    map[string]string{"url": "{{target.url}}/health"},
					},
				},
			},
			"think": {
				Id:   "think",
				Type: missionv1.NodeType_NODE_TYPE_AGENT,
				Config: &missionv1.MissionNode_AgentConfig{
					AgentConfig: &missionv1.AgentNodeConfig{
						AgentName: "recon",
						Task:      &typesv1.Task{Goal: "enumerate {{target.domain}}"},
					},
				},
			},
		},
	}

	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	assert.Equal(t, "scan kubernetes-goat", out.GetName())
	assert.Equal(t, "against https://goat.internal:8080", out.GetDescription())
	assert.Equal(t, "https://goat.internal:8080/health",
		out.GetNodes()["web"].GetToolConfig().GetInput()["url"], "a placeholder inside a longer string binds")
	assert.Equal(t, "enumerate goat.internal",
		out.GetNodes()["think"].GetAgentConfig().GetTask().GetGoal(), "a nested message binds")
	assert.Empty(t, Unbound(out))
}

func TestBind_BindsAMapKey(t *testing.T) {
	def := toolDef(map[string]string{"{{target.name}}": "x"})
	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	got := out.GetNodes()["ports"].GetToolConfig().GetInput()
	assert.Equal(t, "x", got["kubernetes-goat"])
	assert.NotContains(t, got, "{{target.name}}", "a key must not keep a placeholder its value resolved")
}

func TestBind_RefusesAnUnknownFieldAndNamesWhatIsKnown(t *testing.T) {
	def := toolDef(map[string]string{"host": "{{target.hostname}}"})

	out, err := Bind(def, goatTarget())
	require.Error(t, err)
	assert.Nil(t, out, "nothing is bound when anything fails; a half-bound run works against the wrong host")
	assert.Contains(t, err.Error(), "{{target.hostname}}")
	assert.Contains(t, err.Error(), "names no target field")
	assert.Contains(t, err.Error(), "{{target.domain}}", "the message lists the vocabulary")
	assert.Contains(t, err.Error(), "ports", "the message names the node the placeholder sits in")
}

func TestBind_RefusesAFieldEmptyOnThisTarget(t *testing.T) {
	// A target with no URL cannot answer a mission that asks for a host. Binding
	// it to "" would dispatch a scan against nothing and report it clean.
	bare := &types.Target{ID: types.NewID(), Name: "no-endpoint"}
	def := toolDef(map[string]string{"host": "{{target.domain}}"})

	_, err := Bind(def, bare)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty on this target")
}

func TestBind_ReportsEveryProblemAtOnce(t *testing.T) {
	def := toolDef(map[string]string{"a": "{{target.nope}}", "b": "{{target.alsonope}}"})

	_, err := Bind(def, goatTarget())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "{{target.nope}}")
	assert.Contains(t, err.Error(), "{{target.alsonope}}")
}

func TestBind_LeavesAnotherNamespaceAlone(t *testing.T) {
	// Only target.* is this package's vocabulary. A placeholder in another
	// namespace is somebody else's to resolve, and claiming it here would make
	// adding one a breaking change.
	def := toolDef(map[string]string{"host": "{{target.domain}}", "run": "{{var.ref}}"})

	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	got := out.GetNodes()["ports"].GetToolConfig().GetInput()
	assert.Equal(t, "goat.internal", got["host"])
	assert.Equal(t, "{{var.ref}}", got["run"])
	assert.Equal(t, []string{"nodes[ports].tool_config.input[run]: {{var.ref}}"}, Unbound(out),
		"what survived is reported, so the dispatcher can refuse it")
}

func TestBind_LeavesTextThatOnlyLooksLikeAPlaceholder(t *testing.T) {
	def := toolDef(map[string]string{"jq": "{{ unterminated", "brace": "a { b } c"})

	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	got := out.GetNodes()["ports"].GetToolConfig().GetInput()
	assert.Equal(t, "{{ unterminated", got["jq"])
	assert.Equal(t, "a { b } c", got["brace"])
}

func TestBind_ToleratesSpacesInsideTheBraces(t *testing.T) {
	def := toolDef(map[string]string{"host": "{{ target.domain }}"})
	out, err := Bind(def, goatTarget())
	require.NoError(t, err)
	assert.Equal(t, "goat.internal", out.GetNodes()["ports"].GetToolConfig().GetInput()["host"])
}

func TestBind_RefusesANilTarget(t *testing.T) {
	_, err := Bind(toolDef(nil), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "names no target")
}

func TestBind_RefusesANilDefinition(t *testing.T) {
	_, err := Bind(nil, goatTarget())
	require.Error(t, err)
}

func TestBind_ADefinitionWithNoPlaceholderIsUnchanged(t *testing.T) {
	def := toolDef(map[string]string{"host": "example.test"})
	out, err := Bind(def, goatTarget())
	require.NoError(t, err)
	assert.Equal(t, "example.test", out.GetNodes()["ports"].GetToolConfig().GetInput()["host"])
}

func TestUnbound_NamesTheFieldPath(t *testing.T) {
	def := toolDef(map[string]string{"host": "{{target.domain}}"})
	got := Unbound(def)
	require.Len(t, got, 1)
	assert.True(t, strings.HasPrefix(got[0], "nodes[ports].tool_config.input[host]:"), got[0])
	assert.Contains(t, got[0], "{{target.domain}}")
}

func TestUnbound_IsEmptyForANilMessage(t *testing.T) {
	assert.Empty(t, Unbound(nil))
}

// A repeated string field binds too. The walk reaches every string in the
// message, and a list is one of the shapes a string arrives in: a condition's
// branch list, a join's wait list, a mission's tags.
func TestBind_BindsARepeatedStringField(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Id: "branchy",
		Nodes: map[string]*missionv1.MissionNode{
			"gate": {
				Id:   "gate",
				Type: missionv1.NodeType_NODE_TYPE_CONDITION,
				Config: &missionv1.MissionNode_ConditionConfig{
					ConditionConfig: &missionv1.ConditionNodeConfig{
						Expression: `host == "{{target.domain}}"`,
						TrueBranch: []string{"scan-{{target.name}}", "plain"},
					},
				},
			},
		},
	}

	out, err := Bind(def, goatTarget())
	require.NoError(t, err)

	cfg := out.GetNodes()["gate"].GetConditionConfig()
	assert.Equal(t, `host == "goat.internal"`, cfg.GetExpression())
	assert.Equal(t, []string{"scan-kubernetes-goat", "plain"}, cfg.GetTrueBranch())
}

func TestBind_RefusesAnUnknownNameInARepeatedField(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Id: "branchy",
		Nodes: map[string]*missionv1.MissionNode{
			"gate": {
				Id:   "gate",
				Type: missionv1.NodeType_NODE_TYPE_CONDITION,
				Config: &missionv1.MissionNode_ConditionConfig{
					ConditionConfig: &missionv1.ConditionNodeConfig{
						TrueBranch: []string{"{{target.nope}}"},
					},
				},
			},
		},
	}
	_, err := Bind(def, goatTarget())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "true_branch[0]", "the message names the position in the list")
}

func TestUnboundTarget_OnlyReportsTheTargetNamespace(t *testing.T) {
	def := toolDef(map[string]string{
		"host": "{{target.domain}}",
		"ref":  "{{var.ref}}",
	})
	got := UnboundTarget(def)
	require.Len(t, got, 1, "a {{var.*}} is somebody else's to resolve: %v", got)
	assert.Contains(t, got[0], "{{target.domain}}")
}

func TestUnboundTarget_IsEmptyOnABoundDefinition(t *testing.T) {
	out, err := Bind(toolDef(map[string]string{"host": "{{target.domain}}"}), goatTarget())
	require.NoError(t, err)
	assert.Empty(t, UnboundTarget(out))
}

func TestUnboundTarget_IsEmptyForANilMessage(t *testing.T) {
	assert.Empty(t, UnboundTarget(nil))
}

// Names and Known are the vocabulary the validator reads. They must agree with
// Bindings, or a name passes validation and then fails at submit.
func TestNamesAndKnownAgreeWithBindings(t *testing.T) {
	names := Names()
	require.NotEmpty(t, names)
	assert.Equal(t, len(Bindings(goatTarget())), len(names))

	for _, n := range names {
		assert.True(t, Known(n), "%s is in Names but not Known", n)
		_, ok := Bindings(goatTarget())[n]
		assert.True(t, ok, "%s is in Names but Bindings does not resolve it", n)
	}
	assert.Equal(t, names, Names(), "Names is sorted and stable")

	assert.False(t, Known("target.hostname"))
	assert.False(t, Known("var.ref"))
	assert.True(t, Known(" target.domain "), "a name is trimmed before it is looked up")
}
