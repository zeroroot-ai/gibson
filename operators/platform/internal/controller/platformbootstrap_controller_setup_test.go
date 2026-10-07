// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
)

// The reconciler needs the connect address of Zitadel. The address comes
// from ZITADEL_URL, never from a field of the PlatformBootstrap (gibson#665).
func TestPlatformBootstrapReconciler_RequiresTheZitadelURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "")
	err := (&PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t)}).SetupWithManager(nil)
	if err == nil || !strings.Contains(err.Error(), "ZitadelURL is required") {
		t.Fatalf("SetupWithManager = %v, want the ZitadelURL error", err)
	}
}

// With ZITADEL_URL set, the reconciler takes its connect base.
func TestPlatformBootstrapReconciler_ReadsTheZitadelURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://gibson-zitadel:8080")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com")
	r := &PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t)}
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

// Neither controller of the platform operator starts without the audit
// emitter (gibson#583).
func TestPlatformReconcilers_RefuseToStartWithoutAudit(t *testing.T) {
	if err := (&PlatformBootstrapReconciler{}).SetupWithManager(nil); !errors.Is(err, errNoAuditEmitter) {
		t.Errorf("PlatformBootstrapReconciler.SetupWithManager = %v, want errNoAuditEmitter", err)
	}
	if err := (&OIDCClientReconciler{}).SetupWithManager(nil); !errors.Is(err, errNoAuditEmitter) {
		t.Errorf("OIDCClientReconciler.SetupWithManager = %v, want errNoAuditEmitter", err)
	}
}
