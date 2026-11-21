// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import "testing"

// One result of a tool of the buyer names one finding: the same tenant,
// submitter and key give the same id, and any other value gives another
// (gibson#1448, review R6).
func TestResultID_IsStableAndScoped(t *testing.T) {
	a := ResultID("acme", "agent_principal:intake", "intake:abc")
	if a != ResultID("acme", "agent_principal:intake", "intake:abc") {
		t.Fatal("the same result gave two ids")
	}
	for _, other := range []string{
		string(ResultID("other", "agent_principal:intake", "intake:abc")),
		string(ResultID("acme", "agent_principal:red", "intake:abc")),
		string(ResultID("acme", "agent_principal:intake", "intake:abd")),
	} {
		if other == string(a) {
			t.Fatalf("another tenant, submitter or key gave the same id %s", a)
		}
	}
}
