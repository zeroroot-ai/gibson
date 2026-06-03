package tenant_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

// TestDeriveTenantKEK_KAT verifies known-answer-test vectors. These values
// are computed by HKDF-SHA256 with the documented parameters and MUST match
// the legacy operator (tenant-operator/internal/dataplane/kek.go) and
// daemon (core/gibson/internal/datapool/kek.go) implementations byte-for-
// byte. A regression here breaks every existing dev-mode tenant.
func TestDeriveTenantKEK_KAT(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0xAA}, 32)

	cases := []struct {
		name     string
		tenantID string
		// Expected first 16 bytes (32 hex chars) — the value used as the
		// Postgres password. Computed from HKDF-SHA256(0xAA*32, salt=<id>,
		// info="gibson/v1/tenant-kek") with the legacy implementations.
		wantPasswordPrefix string
	}{
		{
			// Computed via HKDF-SHA256(0xAA*32, salt="zeroroot-ai",
			// info="gibson/v1/tenant-kek"); first 32 hex chars (16 bytes)
			// matches what the legacy operator + daemon produced.
			name:               "zeroroot-ai",
			tenantID:           "zeroroot-ai",
			wantPasswordPrefix: "35dbd310788793743e47dad9c43cbe58",
		},
		{
			name:               "smoke-solo",
			tenantID:           "smoke-solo",
			wantPasswordPrefix: "d5a833a6014abb069617293d0e1acf76",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			id := auth.MustNewTenantID(c.tenantID)
			kek, err := tenant.DeriveTenantKEK(masterKEK, id)
			if err != nil {
				t.Fatalf("DeriveTenantKEK: %v", err)
			}
			defer tenant.Zeroize(kek)

			if len(kek) != tenant.KEKLength {
				t.Errorf("KEK length = %d, want %d", len(kek), tenant.KEKLength)
			}

			pwd, err := tenant.PostgresPasswordFromKEK(kek)
			if err != nil {
				t.Fatalf("PostgresPasswordFromKEK: %v", err)
			}
			if len(pwd) != tenant.KEKLength {
				t.Errorf("password length = %d, want %d hex chars", len(pwd), tenant.KEKLength)
			}
			if _, err := hex.DecodeString(pwd); err != nil {
				t.Errorf("password is not valid hex: %v", err)
			}
			if c.wantPasswordPrefix != "" && pwd != c.wantPasswordPrefix {
				t.Errorf("Postgres password = %q, want %q (KAT vector — regression breaks every existing dev-mode tenant)", pwd, c.wantPasswordPrefix)
			}

			// Determinism: re-derive and compare.
			kek2, err := tenant.DeriveTenantKEK(masterKEK, id)
			if err != nil {
				t.Fatalf("DeriveTenantKEK (second call): %v", err)
			}
			defer tenant.Zeroize(kek2)
			if !bytes.Equal(kek, kek2) {
				t.Errorf("DeriveTenantKEK is not deterministic")
			}
		})
	}
}

// TestDeriveTenantKEK_DistinctTenants ensures different tenant IDs produce
// different KEKs (sanity check that the salt is wired through correctly).
func TestDeriveTenantKEK_DistinctTenants(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0xAA}, 32)
	a, _ := tenant.DeriveTenantKEK(masterKEK, auth.MustNewTenantID("acme"))
	b, _ := tenant.DeriveTenantKEK(masterKEK, auth.MustNewTenantID("beta"))
	defer tenant.Zeroize(a)
	defer tenant.Zeroize(b)
	if bytes.Equal(a, b) {
		t.Error("different tenants produced identical KEKs (HKDF salt not wired)")
	}
}

// TestDeriveTenantKEK_DistinctMasters ensures different master KEKs produce
// different per-tenant KEKs.
func TestDeriveTenantKEK_DistinctMasters(t *testing.T) {
	id := auth.MustNewTenantID("acme")
	a, _ := tenant.DeriveTenantKEK(bytes.Repeat([]byte{0xAA}, 32), id)
	b, _ := tenant.DeriveTenantKEK(bytes.Repeat([]byte{0xBB}, 32), id)
	defer tenant.Zeroize(a)
	defer tenant.Zeroize(b)
	if bytes.Equal(a, b) {
		t.Error("different master KEKs produced identical per-tenant KEKs")
	}
}

func TestDeriveTenantKEK_ShortMaster(t *testing.T) {
	short := bytes.Repeat([]byte{0xAA}, 16)
	_, err := tenant.DeriveTenantKEK(short, auth.MustNewTenantID("acme"))
	if err == nil {
		t.Error("DeriveTenantKEK with 16-byte master succeeded; expected error")
	}
}

func TestDeriveTenantKEK_ZeroTenant(t *testing.T) {
	master := bytes.Repeat([]byte{0xAA}, 32)
	_, err := tenant.DeriveTenantKEK(master, auth.TenantID{})
	if err == nil {
		t.Error("DeriveTenantKEK with zero TenantID succeeded; expected error")
	}
	// Should NOT match a generic error type — we do not export a sentinel
	// for this case, so just verify it's an error.
	if errors.Is(err, nil) {
		t.Error("returned error is nil-equivalent")
	}
}

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	tenant.Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("Zeroize: b[%d] = %d, want 0", i, v)
		}
	}
}

// TestPostgresPasswordFromKEK_ShortKEK rejects KEKs shorter than KEKLength.
func TestPostgresPasswordFromKEK_ShortKEK(t *testing.T) {
	short := []byte{1, 2, 3}
	_, err := tenant.PostgresPasswordFromKEK(short)
	if err == nil {
		t.Error("PostgresPasswordFromKEK with short KEK succeeded; expected error")
	}
}
