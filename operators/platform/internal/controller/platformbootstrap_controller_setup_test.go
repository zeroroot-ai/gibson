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
	err := (&PlatformBootstrapReconciler{}).SetupWithManager(nil)
	if err == nil || !strings.Contains(err.Error(), "ZitadelURL is required") {
		t.Fatalf("SetupWithManager = %v, want the ZitadelURL error", err)
	}
}
