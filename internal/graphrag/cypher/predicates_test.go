// Package cypher — predicates_test.go
//
// TenantPredicate is now a no-op stub retained for build compatibility while
// call sites are migrated away. This test verifies the stub returns an empty
// string (C1/C2/C3/C18 closure: no WHERE tenant_id clauses in Cypher).
package cypher

import "testing"

func TestTenantPredicate(t *testing.T) {
	tests := []struct {
		varName   string
		paramName string
	}{
		{"n", "tenant_id"},
		{"f", "tenant"},
		{"host", "tid"},
	}

	for _, tc := range tests {
		t.Run(tc.varName+"/"+tc.paramName, func(t *testing.T) {
			got := TenantPredicate(tc.varName, tc.paramName)
			if got != "" {
				t.Errorf("TenantPredicate(%q, %q) = %q, want empty string (C18 closure: no tenant_id property predicates in per-tenant DB)",
					tc.varName, tc.paramName, got)
			}
		})
	}
}
