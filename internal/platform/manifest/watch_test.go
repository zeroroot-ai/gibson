// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"testing"

	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
)

func TestWatchHub_HeartbeatBuilder(t *testing.T) {
	ev := BuildHeartbeat("tenant-a")
	if ev.EventType != manifestpb.ManifestInvalidationEvent_EVENT_TYPE_HEARTBEAT {
		t.Fatalf("event type = %v", ev.EventType)
	}
	if ev.TenantId != "tenant-a" {
		t.Fatalf("tenant = %q", ev.TenantId)
	}
	if ev.EmittedAt == nil {
		t.Fatalf("EmittedAt should be set")
	}
}
