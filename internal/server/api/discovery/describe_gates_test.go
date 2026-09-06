// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package discovery

import (
	"context"
	"slices"
	"strings"
	"testing"

	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
)

// TestDescribeDenyingGates_Truthful verifies the tooltip reports the REAL cause,
// not a fabricated tenant_*_disabled for every denial (the live bug).
func TestDescribeDenyingGates_Truthful(t *testing.T) {
	const subject = "user:alice"
	const object = "component:agent/zerocool"

	t.Run("denied with no deny tuple and no catalog entry names the catalog", func(t *testing.T) {
		// read denied, no *_disabled applies, and the tenant never enabled the
		// item: the gate is the catalog, not a kill switch (gibson#1610).
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{}}
		s := NewServer(az, nil, nil, nil)
		gates := s.describeDenyingGates(context.Background(),
			&discoverypb.ActionCapabilities{Read: false, Write: true, Execute: true}, subject, object, "acme")
		if len(gates) != 1 || !strings.Contains(gates[0], "not in tenant catalog") || strings.Contains(gates[0], "kill switch") {
			t.Fatalf("gates = %v, want exactly one 'not in tenant catalog' gate", gates)
		}
	})
	t.Run("denied with no deny tuple but in the catalog names the missing grant", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
			"tenant:acme|tenant_enabled|" + object: true,
		}}
		s := NewServer(az, nil, nil, nil)
		gates := s.describeDenyingGates(context.Background(),
			&discoverypb.ActionCapabilities{Read: false, Write: true, Execute: true}, subject, object, "acme")
		if len(gates) != 1 || !strings.Contains(gates[0], "no direct grant") {
			t.Fatalf("gates = %v, want exactly one 'no direct grant' gate", gates)
		}
	})

	t.Run("real user deny is named precisely", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
			subject + "|any_read_deny|" + object:      true,
			subject + "|user_read_disabled|" + object: true,
		}}
		s := NewServer(az, nil, nil, nil)
		gates := s.describeDenyingGates(context.Background(),
			&discoverypb.ActionCapabilities{Read: false, Write: true, Execute: true}, subject, object, "acme")
		want := "user_read_disabled@" + subject + "→" + object
		if !slices.Contains(gates, want) {
			t.Fatalf("gates = %v, want it to name %q", gates, want)
		}
	})

	t.Run("tenant/team deny reported as a kill switch", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
			subject + "|any_execute_deny|" + object: true, // deny applies, but not user-scoped
		}}
		s := NewServer(az, nil, nil, nil)
		gates := s.describeDenyingGates(context.Background(),
			&discoverypb.ActionCapabilities{Read: true, Write: true, Execute: false}, subject, object, "acme")
		if len(gates) != 1 {
			t.Fatalf("gates = %v, want exactly one execute gate", gates)
		}
		if !strings.Contains(gates[0], "kill switch") || !strings.Contains(gates[0], "execute") {
			t.Fatalf("gate %q, want an execute tenant/team kill-switch message", gates[0])
		}
	})
}
