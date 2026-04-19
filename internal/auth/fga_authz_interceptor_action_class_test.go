package auth

// Regression guard: authz_deny events emitted by the FGA interceptor must
// populate the per-action context fields (ActionClass + ComponentScope)
// the dashboard relies on for audit display + filtering.
//
// Spec: access-matrix-finish task 22, R6 AC 8.

import (
	"testing"
)

func TestRelationToActionClass(t *testing.T) {
	cases := []struct {
		relation string
		want     string
	}{
		{"can_read", "read"},
		{"can_configure", "write"},
		{"can_execute", "execute"},

		{"component_read_enabled", "read"},
		{"component_write_enabled", "write"},
		{"component_execute_enabled", "execute"},

		{"tenant_read_disabled", "read"},
		{"tenant_write_disabled", "write"},
		{"tenant_execute_disabled", "execute"},
		{"team_read_disabled", "read"},
		{"team_write_disabled", "write"},
		{"team_execute_disabled", "execute"},
		{"user_read_disabled", "read"},
		{"user_write_disabled", "write"},
		{"user_execute_disabled", "execute"},

		{"member", ""},
		{"admin", ""},
		{"", ""},
		{"nonsense", ""},
	}
	for _, tc := range cases {
		t.Run(tc.relation, func(t *testing.T) {
			got := relationToActionClass(tc.relation)
			if got != tc.want {
				t.Fatalf("relationToActionClass(%q) = %q, want %q", tc.relation, got, tc.want)
			}
		})
	}
}
