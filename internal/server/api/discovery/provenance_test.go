// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
)

// TestDescribeProvenance: a row says what it is, who holds it, and when it
// last checked in, so a tenant-enrolled laptop agent is never mistaken for a
// platform deployment.
func TestDescribeProvenance(t *testing.T) {
	const object = "component:agent/zerocool-claude"
	t0 := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)

	t.Run("tenant-enrolled: two instances fold to count, newest heartbeat, oldest start", func(t *testing.T) {
		var sum *instanceSummary
		sum = sum.fold(component.ComponentInfo{TenantID: "acme", StartedAt: t0, LastHeartbeat: t0.Add(5 * time.Minute)})
		sum = sum.fold(component.ComponentInfo{TenantID: "acme", StartedAt: t0.Add(time.Minute), LastHeartbeat: t0.Add(9 * time.Minute)})
		s := NewServer(&stubDiscoveryAuthorizer{allowed: map[string]bool{}}, nil, nil, nil)
		item := &discoverypb.CatalogItem{Name: "zerocool-claude"}
		s.describeProvenance(context.Background(), item, object, sum)
		if item.Source != discoverypb.Source_SOURCE_TENANT_ENROLLED {
			t.Fatalf("source = %v, want TENANT_ENROLLED", item.Source)
		}
		if item.OwnerTenant != "acme" || item.Instances != 2 {
			t.Fatalf("owner/instances = %q/%d, want acme/2", item.OwnerTenant, item.Instances)
		}
		if item.LastHeartbeatUnix != t0.Add(9*time.Minute).Unix() || item.StartedAtUnix != t0.Unix() {
			t.Fatalf("heartbeat/started = %d/%d, want newest heartbeat and oldest start", item.LastHeartbeatUnix, item.StartedAtUnix)
		}
	})

	t.Run("platform catalog item with nothing registered", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{allowed: map[string]bool{"system_tenant:_system|platform_enabled|" + object: true}}, nil, nil, nil)
		item := &discoverypb.CatalogItem{Name: "zerocool-claude"}
		s.describeProvenance(context.Background(), item, object, nil)
		if item.Source != discoverypb.Source_SOURCE_PLATFORM_CATALOG {
			t.Fatalf("source = %v, want PLATFORM_CATALOG", item.Source)
		}
		if item.Instances != 0 || item.LastHeartbeatUnix != 0 {
			t.Fatalf("nothing registered must read as zero, got %d/%d", item.Instances, item.LastHeartbeatUnix)
		}
	})

	t.Run("a check failure leaves source unknown", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{err: context.DeadlineExceeded}, nil, nil, nil)
		item := &discoverypb.CatalogItem{Name: "x"}
		s.describeProvenance(context.Background(), item, object, nil)
		if item.Source != discoverypb.Source_SOURCE_UNSPECIFIED {
			t.Fatalf("source = %v, want UNSPECIFIED on error", item.Source)
		}
	})
}
