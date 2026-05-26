package datapool

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
)

func TestMultiDBResolver_URIAndDatabaseName(t *testing.T) {
	t.Parallel()

	r := newMultiDBResolver("bolt+routing://shared-cluster:7687", "admin", "pass")
	tenant := auth.MustNewTenantID("acme")

	ep, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.BoltURI != "bolt+routing://shared-cluster:7687" {
		t.Errorf("BoltURI: got %q, want bolt+routing://shared-cluster:7687", ep.BoltURI)
	}
	if ep.Username != "admin" {
		t.Errorf("Username: got %q, want admin", ep.Username)
	}
	if ep.Password != "pass" {
		t.Errorf("Password: got %q, want pass", ep.Password)
	}
	// "acme" → "acme" (no hyphens to replace)
	want := "tenant_acme"
	if ep.Database != want {
		t.Errorf("Database: got %q, want %q", ep.Database, want)
	}
}

func TestMultiDBResolver_SanitizationMatchesConvention(t *testing.T) {
	t.Parallel()

	r := newMultiDBResolver("bolt://cluster:7687", "user", "pw")

	cases := []struct {
		tenantID string
		wantDB   string
	}{
		{"simple", "tenant_simple"},
		{"tenant-with-hyphens", "tenant_tenant_with_hyphens"},
		{"all_underscores", "tenant_all_underscores"},
		{"abc123", "tenant_abc123"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.tenantID, func(t *testing.T) {
			t.Parallel()
			ep, err := r.Resolve(context.Background(), auth.MustNewTenantID(tc.tenantID))
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.tenantID, err)
			}
			if ep.Database != tc.wantDB {
				t.Errorf("Database: got %q, want %q", ep.Database, tc.wantDB)
			}
		})
	}
}
