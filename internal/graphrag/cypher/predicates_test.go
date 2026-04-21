package cypher

import "testing"

func TestTenantPredicate(t *testing.T) {
	tests := []struct {
		varName   string
		paramName string
		want      string
	}{
		{
			varName:   "n",
			paramName: "tenant_id",
			want:      "n.tenant_id = $tenant_id",
		},
		{
			varName:   "f",
			paramName: "tenant",
			want:      "f.tenant_id = $tenant",
		},
		{
			varName:   "host",
			paramName: "tid",
			want:      "host.tenant_id = $tid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.varName+"/"+tc.paramName, func(t *testing.T) {
			got := TenantPredicate(tc.varName, tc.paramName)
			if got != tc.want {
				t.Errorf("TenantPredicate(%q, %q) = %q, want %q", tc.varName, tc.paramName, got, tc.want)
			}
		})
	}
}
