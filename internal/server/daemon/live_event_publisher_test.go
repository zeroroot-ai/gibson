// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
)

func TestNewLiveEventPublisher_NilRegistryIsNil(t *testing.T) {
	if p := newLiveEventPublisher(nil); p != nil {
		t.Fatalf("nil registry -> %#v; want nil publisher", p)
	}
}

func TestLiveEventPublisher_RegistersWithMissionScope(t *testing.T) {
	reg := liveagents.NewRegistry()
	p := newLiveEventPublisher(reg)
	started := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	publish, finish := p.RegisterInstance("tenant-a", sandboxed.LiveInstance{
		RunID:        "run-1",
		AgentName:    "claude",
		SandboxID:    "sbx-1",
		SandboxClass: "agent",
		StartedAt:    started,
		MissionID:    "m-1",
		MissionRunID: "mr-1",
	})
	defer finish()
	publish([]byte("hello"))

	got := reg.List("tenant-a")
	if len(got) != 1 {
		t.Fatalf("List = %d instances; want 1", len(got))
	}
	want := liveagents.Instance{RunID: "run-1", AgentName: "claude", SandboxID: "sbx-1", SandboxClass: "agent", StartedAt: started, MissionID: "m-1", MissionRunID: "mr-1"}
	if got[0] != want {
		t.Fatalf("instance = %+v; want %+v", got[0], want)
	}
	backlog, _, cancel, err := reg.Subscribe("tenant-a", "run-1", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	if len(backlog) != 1 || string(backlog[0].Data) != "hello" {
		t.Fatalf("backlog = %+v; want one chunk hello", backlog)
	}
}
