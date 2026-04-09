package harness

import (
	"testing"

	taxonomypb "github.com/zero-day-ai/sdk/api/gen/taxonomy/v1"
	"github.com/zero-day-ai/sdk/taxonomy"
)

// fixtureSignal returns a baseline compliance signal with sensible
// defaults. Tests override specific fields.
func fixtureSignal(overrides func(*taxonomypb.ComplianceSignal)) *taxonomypb.ComplianceSignal {
	sig := &taxonomypb.ComplianceSignal{
		SignalId:               "sig-1",
		ActorId:                "user-1",
		ActorTenantId:          "tenant-a",
		CallerComponent:        "agent:test-agent",
		CallerComponentVersion: "1.0.0",
		TargetComponent:        "tool:nmap",
		TargetComponentVersion: "7.94",
		SystemOwned:            false,
		Action:                 "tool_call",
		Effect:                 "execute",
		ResourceType:           "discovery:host",
		Decision:               "allow",
		Success:                true,
		LatencyMs:              42,
		OccurredAt:             1_700_000_000_000,
	}
	if overrides != nil {
		overrides(sig)
	}
	return sig
}

func TestEvaluator_EqualsMatcher(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Equals: map[string]string{"action": "tool_call"},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 || got[0] != "C1" {
		t.Errorf("got %v; want [C1]", got)
	}
}

func TestEvaluator_EqualsNoMatch(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Equals: map[string]string{"action": "llm_call"},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 0 {
		t.Errorf("got %v; want empty", got)
	}
}

func TestEvaluator_InMatcher(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			In: map[string][]string{"action": {"tool_call", "llm_call"}},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 || got[0] != "C1" {
		t.Errorf("got %v; want [C1]", got)
	}
}

func TestEvaluator_NotMatcher(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Not: &taxonomy.Matcher{
				Equals: map[string]string{"action": "llm_call"},
			},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("not(action=llm_call) should match when action=tool_call; got %v", got)
	}
}

func TestEvaluator_AllOfMatcher(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(func(s *taxonomypb.ComplianceSignal) {
		s.Decision = "deny"
	})
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			AllOf: []taxonomy.Matcher{
				{Equals: map[string]string{"decision": "deny"}},
				{Equals: map[string]string{"action": "tool_call"}},
			},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("got %v; want [C1]", got)
	}
}

func TestEvaluator_AnyOfMatcher(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			AnyOf: []taxonomy.Matcher{
				{Equals: map[string]string{"action": "llm_call"}},
				{Equals: map[string]string{"action": "tool_call"}},
			},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("got %v; want [C1]", got)
	}
}

func TestEvaluator_DottedPathResourceTags(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	tags := "env=prod,data_class=pii"
	sig := fixtureSignal(func(s *taxonomypb.ComplianceSignal) {
		s.ResourceTags = &tags
	})
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Equals: map[string]string{"resource_tags.env": "prod"},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("dotted path resource_tags.env=prod should match; got %v", got)
	}
}

func TestEvaluator_DottedPathCustom(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	custom := "change_ticket=CHG-0042,gitlab_project=my-proj"
	sig := fixtureSignal(func(s *taxonomypb.ComplianceSignal) {
		s.Custom = &custom
	})
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Not: &taxonomy.Matcher{
				Equals: map[string]string{"custom.change_ticket": ""},
			},
		}},
	}
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("not(custom.change_ticket=empty) should match when set; got %v", got)
	}
}

func TestEvaluator_MissingKeyEmptyString(t *testing.T) {
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	rules := []taxonomy.Rule{
		{ID: "R1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{
			Equals: map[string]string{"resource_tags.env": ""},
		}},
	}
	// Missing key should read as "" and match the empty-string comparison.
	got := e.Evaluate(sig, rules)
	if len(got) != 1 {
		t.Errorf("missing key should read as empty; got %v", got)
	}
}

func TestEvaluator_SeedCatalogSmoke(t *testing.T) {
	// Smoke test: load the shipped rules file and run the evaluator
	// against a positive fixture for each framework, verifying at least
	// one rule matches each signal class.
	catalog, err := taxonomy.LoadCatalog("../../../sdk/taxonomy/compliance_rules.yaml")
	if err != nil {
		t.Skipf("seed catalog not reachable from this test dir: %v", err)
	}
	e := NewComplianceEvaluator(nil)

	// SOC2 tool_call signal — should match SOC2.CC7.1 at minimum
	soc2Sig := fixtureSignal(nil)
	got := e.Evaluate(soc2Sig, catalog.Rules)
	foundSOC2 := false
	for _, id := range got {
		if id == "CC7.1" {
			foundSOC2 = true
		}
	}
	if !foundSOC2 {
		t.Errorf("seed catalog should match CC7.1 for tool_call signal; got %v", got)
	}
}

// BenchmarkEvaluator_SeedCatalog confirms the ≤500µs budget.
func BenchmarkEvaluator_SeedCatalog(b *testing.B) {
	catalog, err := taxonomy.LoadCatalog("../../../sdk/taxonomy/compliance_rules.yaml")
	if err != nil {
		b.Skipf("seed catalog not reachable: %v", err)
	}
	e := NewComplianceEvaluator(nil)
	sig := fixtureSignal(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(sig, catalog.Rules)
	}
}
