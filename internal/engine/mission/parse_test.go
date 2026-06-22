package mission

import (
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func TestParseDefinitionYAML_minimal(t *testing.T) {
	yaml := `
name: minimal-mission
version: "1.0.0"
nodes:
  step1:
    id: step1
    type: NODE_TYPE_AGENT
    agent_config:
      agent_name: example-agent
`
	def, err := ParseDefinitionYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if def.Name != "minimal-mission" {
		t.Errorf("name=%q want=minimal-mission", def.Name)
	}
	n, ok := def.Nodes["step1"]
	if !ok {
		t.Fatal("step1 node missing")
	}
	if n.Type != missionv1.NodeType_NODE_TYPE_AGENT {
		t.Errorf("type=%v want=AGENT", n.Type)
	}
	if n.GetAgentConfig().GetAgentName() != "example-agent" {
		t.Errorf("agent_name=%q want=example-agent", n.GetAgentConfig().GetAgentName())
	}
}

func TestParseDefinitionYAML_everyNodeType(t *testing.T) {
	yaml := `
name: every-type
nodes:
  a:
    id: a
    type: NODE_TYPE_AGENT
    agent_config:
      agent_name: a-agent
  t:
    id: t
    type: NODE_TYPE_TOOL
    tool_config:
      tool_name: t-tool
  p:
    id: p
    type: NODE_TYPE_PLUGIN
    plugin_config:
      plugin_name: p-plug
      method: do
  c:
    id: c
    type: NODE_TYPE_CONDITION
    condition_config:
      expression: "true"
      true_branch: ["a"]
  par:
    id: par
    type: NODE_TYPE_PARALLEL
    parallel_config:
      max_concurrency: 2
edges:
  - from: a
    to: t
  - from: t
    to: p
entry_points: ["a"]
exit_points: ["p"]
`
	def, err := ParseDefinitionYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(def.Nodes); got != 5 {
		t.Errorf("nodes=%d want=5", got)
	}
	if got := len(def.Edges); got != 2 {
		t.Errorf("edges=%d want=2", got)
	}
	if got := def.Nodes["c"].GetConditionConfig().GetExpression(); got != "true" {
		t.Errorf("condition expression=%q want=true", got)
	}
	if got := def.Nodes["par"].GetParallelConfig().GetMaxConcurrency(); got != 2 {
		t.Errorf("max_concurrency=%d want=2", got)
	}
}

func TestParseDefinitionYAML_perNounTokenCap(t *testing.T) {
	yaml := `
name: cap-test
nodes:
  a:
    id: a
    type: NODE_TYPE_AGENT
    agent_config:
      agent_name: a
      max_tokens_per_call: 1024
`
	def, err := ParseDefinitionYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cap := def.Nodes["a"].GetAgentConfig().GetMaxTokensPerCall()
	if cap != 1024 {
		t.Errorf("max_tokens_per_call=%d want=1024", cap)
	}
}

func TestParseDefinitionYAML_conditionLanguage(t *testing.T) {
	yaml := `
name: lang-test
nodes:
  c:
    id: c
    type: NODE_TYPE_CONDITION
    condition_config:
      expression: "x > 0"
      language: LANGUAGE_CEL
`
	def, err := ParseDefinitionYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := def.Nodes["c"].GetConditionConfig().GetLanguage(); got != missionv1.Language_LANGUAGE_CEL {
		t.Errorf("language=%v want=CEL", got)
	}
}

func TestParseDefinitionYAML_emptyInput(t *testing.T) {
	_, err := ParseDefinitionYAML(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error=%q want substring 'empty'", err.Error())
	}
}

func TestParseDefinitionYAML_malformedYAML(t *testing.T) {
	// Unclosed bracket → YAML parser surfaces a clear error.
	_, err := ParseDefinitionYAML([]byte("nodes: [unclosed"))
	if err == nil {
		t.Fatal("expected YAML parse error")
	}
	if !strings.Contains(err.Error(), "YAML parse") {
		t.Errorf("error=%q want substring 'YAML parse'", err.Error())
	}
}

func TestParseDefinitionYAML_unknownField(t *testing.T) {
	yaml := `
name: unknown-test
not_a_real_field: oops
nodes:
  a:
    id: a
    type: NODE_TYPE_AGENT
`
	_, err := ParseDefinitionYAML([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "proto unmarshal") {
		t.Errorf("error=%q want substring 'proto unmarshal'", err.Error())
	}
}

func TestParseDefinitionYAML_typeMismatch(t *testing.T) {
	// `nodes` should be a map, not a string.
	yaml := `
name: type-mismatch
nodes: "this should be a map"
`
	_, err := ParseDefinitionYAML([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for type mismatch")
	}
}
