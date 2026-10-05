// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trainerid

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestTenant(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("install.example")
	if got, ok := TenantOfString("spiffe://install.example/trainer/acme-2", td); !ok || got != "acme-2" {
		t.Fatalf("tenant = %q, %v; want acme-2", got, ok)
	}
	for _, bad := range []string{
		"spiffe://other.example/trainer/acme",
		"spiffe://install.example/trainer",
		"spiffe://install.example/trainer/",
		"spiffe://install.example/trainer/acme/x",
		"spiffe://install.example/trainer/Acme",
		"spiffe://install.example/trainer/a.b",
		"spiffe://install.example/trainer/-acme",
		"spiffe://install.example/platform/tenant-operator",
		"not a spiffe id",
		"",
	} {
		if got, ok := TenantOfString(bad, td); ok {
			t.Errorf("%q gave the tenant %q, want no tenant", bad, got)
		}
	}
}
