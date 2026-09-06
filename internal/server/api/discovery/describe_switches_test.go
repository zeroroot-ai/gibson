// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package discovery

import (
	"context"
	"testing"

	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
)

// TestDescribeSwitches pins dashboard#1135: a switch shows the deny tuple it
// writes, never the effective capability, and the catalog gate is reported
// on its own.
func TestDescribeSwitches(t *testing.T) {
	const object = "component:agent/zerocool-claude"
	const user = "user:alice"

	t.Run("tenant-wide: two real denies and no catalog entry", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
			"tenant:acme|tenant_read_disabled|" + object:  true,
			"tenant:acme|tenant_write_disabled|" + object: true,
		}}
		s := NewServer(az, nil, nil, nil)
		sw, inCatalog := s.describeSwitches(context.Background(), &discoverypb.ListQuery{Scope: discoverypb.Scope_SCOPE_USER_ENABLED}, user, "acme", object)
		if sw == nil || sw.Tenant == nil {
			t.Fatalf("tenant layer must be set, got %+v", sw)
		}
		if !sw.Tenant.Read || !sw.Tenant.Write || sw.Tenant.Execute {
			t.Fatalf("tenant layer = %+v, want read+write denied, execute not", sw.Tenant)
		}
		if sw.User == nil || sw.User.Read {
			t.Fatalf("user layer must be set for the caller and clean, got %+v", sw.User)
		}
		if sw.Team != nil {
			t.Fatalf("no team layer without SCOPE_TEAM_VIEW, got %+v", sw.Team)
		}
		if inCatalog {
			t.Fatal("no tenant_enabled tuple, so in_tenant_catalog must be false")
		}
	})

	t.Run("team view reports the viewed team's denies and the catalog entry", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
			"team:red#member|team_execute_disabled|" + object: true,
			"tenant:acme|tenant_enabled|" + object:            true,
		}}
		s := NewServer(az, nil, nil, nil)
		sw, inCatalog := s.describeSwitches(context.Background(), &discoverypb.ListQuery{Scope: discoverypb.Scope_SCOPE_TEAM_VIEW, TargetId: "red"}, user, "acme", object)
		if sw == nil || sw.Team == nil || !sw.Team.Execute || sw.Team.Read {
			t.Fatalf("team layer = %+v, want execute denied only", sw.GetTeam())
		}
		if !inCatalog {
			t.Fatal("tenant_enabled exists, so in_tenant_catalog must be true")
		}
	})

	t.Run("a check failure leaves the switches unset instead of guessing", func(t *testing.T) {
		az := &stubDiscoveryAuthorizer{err: context.DeadlineExceeded}
		s := NewServer(az, nil, nil, nil)
		sw, inCatalog := s.describeSwitches(context.Background(), &discoverypb.ListQuery{}, user, "acme", object)
		if sw != nil || inCatalog {
			t.Fatalf("want nil,false on error, got %+v,%v", sw, inCatalog)
		}
	})
}
