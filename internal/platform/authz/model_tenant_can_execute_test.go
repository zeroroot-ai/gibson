// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"encoding/json"
	"strings"
	"testing"
)

// The daemon asks tenant_can_execute with the plain tenant as the subject, for a
// call that it makes with no person behind it (catalog.TenantAuthorizer). The
// relation must hold in model.fga and in the JSON that `gibson dump-fga-model`
// seeds into OpenFGA, which is the one way the model reaches a cluster. It must
// read the three tenant tuples and no user or userset.
func TestModel_TenantCanExecuteIsInTheSeededModel(t *testing.T) {
	out, err := ModelJSON()
	if err != nil {
		t.Fatalf("ModelJSON: %v", err)
	}
	var model struct {
		TypeDefinitions []struct {
			Type      string                     `json:"type"`
			Relations map[string]json.RawMessage `json:"relations"`
		} `json:"type_definitions"`
	}
	if err := json.Unmarshal([]byte(out), &model); err != nil {
		t.Fatalf("ModelJSON is not JSON: %v", err)
	}
	var rule string
	for _, td := range model.TypeDefinitions {
		if td.Type == "component" {
			raw, ok := td.Relations["tenant_can_execute"]
			if !ok {
				t.Fatal("component has no tenant_can_execute in the seeded model: the daemon check of its own calls would fail")
			}
			rule = string(raw)
		}
	}
	if rule == "" {
		t.Fatal("the seeded model has no component type")
	}
	for _, want := range []string{`"difference"`, `"intersection"`, `"owner"`, `"tenant_enabled"`, `"tenant_execute_disabled"`} {
		if !strings.Contains(rule, want) {
			t.Errorf("tenant_can_execute = %s, want it to hold %s", rule, want)
		}
	}
	// No other relation may be in the rule: a userset, a team or a user deny
	// would make the rule depend on a person.
	for _, bad := range []string{"direct_execute", "member", "team_execute_disabled", "user_execute_disabled", "in_tenant_catalog"} {
		if strings.Contains(rule, bad) {
			t.Errorf("tenant_can_execute = %s, must not read %s", rule, bad)
		}
	}
}

// The three relations of the rule take the tenant as a direct subject. With
// another type the plain tenant could not hold the tuple, and the rule would
// be false for every call.
func TestModel_TenantCanExecuteReadsDirectTenantTuples(t *testing.T) {
	m := gibsonFGAModel()
	for _, rel := range []string{"owner", "tenant_enabled", "tenant_execute_disabled"} {
		ok, err := m.admitsSubjectType("component", rel, "tenant", map[string]bool{})
		if err != nil {
			t.Fatalf("component.%s: %v", rel, err)
		}
		if !ok {
			t.Errorf("component.%s does not admit a tenant subject", rel)
		}
	}
	// A person or an agent cannot hold the rule: it has no direct subject.
	for _, subject := range []string{"user", "agent_principal", "tool_principal", "plugin_principal"} {
		ok, err := m.admitsSubjectType("component", "tenant_can_execute", subject, map[string]bool{})
		if err != nil {
			t.Fatalf("tenant_can_execute for %s: %v", subject, err)
		}
		if ok {
			t.Errorf("a %s can hold component.tenant_can_execute directly", subject)
		}
	}
}
