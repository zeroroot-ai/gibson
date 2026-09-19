// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	agentconsolev1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

// A run the gate refused never reaches the console. The wait must say so at
// once, with the node's reason, instead of timing out in silence.
func TestRunningAgentOrFailure_NamesTheNodeReasonAtOnce(t *testing.T) {
	events := make(chan helpers.MissionEvent, 4)
	events <- helpers.MissionEvent{EventType: "node.started", NodeID: "zerocool-node"}
	events <- helpers.MissionEvent{EventType: "node.failed", NodeID: "zerocool-node", Error: `agent "zerocool" is not enabled for tenant "primary"`}
	events <- helpers.MissionEvent{EventType: "mission_failed", Error: "a work item failed"}

	nothing := func() []*agentconsolev1.RunningAgent { return nil }
	start := time.Now()
	_, err := runningAgentOrFailure(context.Background(), nothing, "zerocool", events, time.Minute)
	if err == nil {
		t.Fatal("a failed mission must end the wait")
	}
	if !strings.Contains(err.Error(), `not enabled for tenant "primary"`) {
		t.Fatalf("the error must carry the node's reason, got: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the wait took %s; a terminal event must end it at once", time.Since(start))
	}
}

func TestRunningAgentOrFailure_ReturnsTheRunningInstance(t *testing.T) {
	events := make(chan helpers.MissionEvent)
	want := &agentconsolev1.RunningAgent{AgentName: "zerocool", RunId: "r1"}
	list := func() []*agentconsolev1.RunningAgent { return []*agentconsolev1.RunningAgent{want} }
	got, err := runningAgentOrFailure(context.Background(), list, "zerocool", events, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetRunId() != "r1" {
		t.Fatalf("got %v, want the running instance", got)
	}
}

func TestRunningAgentOrFailure_ClosedStreamIsNamed(t *testing.T) {
	events := make(chan helpers.MissionEvent)
	close(events)
	nothing := func() []*agentconsolev1.RunningAgent { return nil }
	_, err := runningAgentOrFailure(context.Background(), nothing, "zerocool", events, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "stream closed") {
		t.Fatalf("a closed stream must be named, got: %v", err)
	}
}
