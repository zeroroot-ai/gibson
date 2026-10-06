// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"strings"
	"testing"
)

// The reconciler needs the connect address of Zitadel. The address comes
// from ZITADEL_URL, never from a field of the PlatformBootstrap (gibson#665).
func TestPlatformBootstrapReconciler_RequiresTheZitadelURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "")
	err := (&PlatformBootstrapReconciler{}).SetupWithManager(nil)
	if err == nil || !strings.Contains(err.Error(), "ZitadelURL is required") {
		t.Fatalf("SetupWithManager = %v, want the ZitadelURL error", err)
	}
}

// With ZITADEL_URL set, the reconciler takes its connect base.
func TestPlatformBootstrapReconciler_ReadsTheZitadelURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://gibson-zitadel:8080")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com")
	r := &PlatformBootstrapReconciler{}
	// A nil manager panics after the address is read, so the check runs in
	// the deferred function either way.
	defer func() {
		_ = recover()
		if r.ZitadelURL != "http://gibson-zitadel:8080" {
			t.Errorf("ZitadelURL = %q", r.ZitadelURL)
		}
	}()
	_ = r.SetupWithManager(nil)
}
