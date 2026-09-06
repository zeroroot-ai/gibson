// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package sandboxed

import "testing"

func TestEgressRulesFromAllow(t *testing.T) {
	if EgressRulesFromAllow(nil) != nil {
		t.Error("empty ceiling must be unrestricted (nil)")
	}
	if EgressRulesFromAllow([]string{"a.com:80", "*", "b.com"}) != nil {
		t.Error(`a "*" entry must mean unrestricted (nil)`)
	}
	if EgressRulesFromAllow([]string{"", "  "}) != nil {
		t.Error("only-blank entries must be unrestricted (nil)")
	}
	got := EgressRulesFromAllow([]string{"gitlab.com:443", "*.slack.com", "x.com:8443"})
	want := []EgressRule{
		{Host: "gitlab.com", Port: 443},
		{Host: "*.slack.com", Port: 443}, // no port -> default 443
		{Host: "x.com", Port: 8443},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
