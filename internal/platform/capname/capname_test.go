// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capname

import "testing"

func TestIsReserved(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{MissionDelegate, true},
		{MissionOriginate, true},
		{"", false},
		{"execute:tool:nmap", false},
		{"mission:delegate ", false}, // trailing space must not match
		{"Mission:Delegate", false},  // case-sensitive
	}
	for _, c := range cases {
		if got := IsReserved(c.name); got != c.want {
			t.Errorf("IsReserved(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDescription(t *testing.T) {
	if d := Description(MissionDelegate); d == "" {
		t.Error("Description(MissionDelegate) must not be empty")
	}
	if d := Description(MissionOriginate); d == "" {
		t.Error("Description(MissionOriginate) must not be empty")
	}
	if d := Description("not-a-reserved-name"); d != "" {
		t.Errorf("Description of an unreserved name = %q, want empty", d)
	}
}

// TestReservedNamesAreDomainScoped guards against a typo that would let an
// arbitrary component-style capability ("execute:tool:x") slip into the
// reserved set and become additively grantable — see appendSessionCapabilities
// in the capabilitygrant package, which trusts IsReserved completely.
func TestReservedNamesAreDomainScoped(t *testing.T) {
	for name := range reserved {
		if len(name) < 8 || name[:8] != "mission:" {
			t.Errorf("reserved capability %q is not in the mission: namespace", name)
		}
	}
}
