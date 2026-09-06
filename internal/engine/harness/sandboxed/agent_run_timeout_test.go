// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"testing"
	"time"
)

// A launcher serves every agent run in the process, so its RunTimeout is a
// deployment default and cannot express what one node declared. That capped a
// live session at thirty minutes no matter what its node asked for, which is
// what made an always-on agent impossible (gibson#1602). The bound now arrives
// per dispatch.

// launchTimeoutProbe returns a client that records the sandbox lifetime it was
// asked for and then completes the run.
func launchTimeoutProbe(got *time.Duration) *mockClient {
	return &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			*got = req.Timeout
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("working\n")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
}

func TestLaunchAgent_TheDispatchRunTimeoutBoundsTheSandbox(t *testing.T) {
	var got time.Duration
	l := newAgentLauncher(t, launchTimeoutProbe(&got)) // launcher default: 5s

	dispatch := AgentDispatch{
		Grant:      "cg",
		MissionID:  "m1",
		RunTimeout: 8 * time.Hour,
	}
	if _, err := l.LaunchAgent(context.Background(), agentSpec, dispatch); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	// The sandbox lifetime is the run timeout plus the kill grace, so the node's
	// eight hours must be visible in it — not the launcher's five seconds.
	if got <= 7*time.Hour {
		t.Fatalf("sandbox lifetime = %s, want the node's 8h bound, not the launcher default", got)
	}
}

func TestLaunchAgent_WithoutADispatchBoundTheLauncherDefaultStands(t *testing.T) {
	// A dispatch that declares nothing must behave exactly as before.
	var got time.Duration
	l := newAgentLauncher(t, launchTimeoutProbe(&got)) // launcher default: 5s

	if _, err := l.LaunchAgent(context.Background(), agentSpec, AgentDispatch{Grant: "cg", MissionID: "m1"}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if got > time.Minute {
		t.Fatalf("sandbox lifetime = %s, want the launcher's 5s default plus grace", got)
	}
}
