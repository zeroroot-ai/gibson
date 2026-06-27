// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

func TestNewVaultTransitDeriver_NilClient(t *testing.T) {
	if _, err := NewVaultTransitDeriver(nil, "k"); err == nil {
		t.Error("NewVaultTransitDeriver(nil) succeeded")
	}
}

func TestVaultTransitDeriver_Derive(t *testing.T) {
	// Mock Vault returns a fixed 32-byte HMAC.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ones := make([]byte, 32)
		for i := range ones {
			ones[i] = 0x42
		}
		_, _ = fmt.Fprintf(w, `{"data":{"hmac":"vault:v1:%s"}}`,
			base64.StdEncoding.EncodeToString(ones))
	}))
	defer srv.Close()

	tc, _ := vault.NewTransitClient(vault.TransitConfig{
		Address:    srv.URL,
		AuthToken:  "tok",
		HTTPClient: srv.Client(),
	})
	d, err := NewVaultTransitDeriver(tc, "")
	if err != nil {
		t.Fatalf("NewVaultTransitDeriver: %v", err)
	}

	out, err := d.DeriveTenantKEK(context.Background(), auth.MustNewTenantID("acme"))
	if err != nil {
		t.Fatalf("DeriveTenantKEK: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}
	for i, b := range out {
		if b != 0x42 {
			t.Errorf("byte[%d] = %d, want 0x42", i, b)
			break
		}
	}
}

func TestVaultTransitDeriver_ZeroTenantRejected(t *testing.T) {
	tc, _ := vault.NewTransitClient(vault.TransitConfig{Address: "https://v", AuthToken: "tok"})
	d, _ := NewVaultTransitDeriver(tc, "k")
	if _, err := d.DeriveTenantKEK(context.Background(), auth.TenantID{}); err == nil {
		t.Error("DeriveTenantKEK with zero TenantID succeeded")
	}
}

// Compile-time guard.
var _ KEKDeriver = (*vaultTransitDeriver)(nil)
