// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

// TestDenialVerdict is the gibson#14 fixture: the outcomes that used to read
// as denials and prove nothing are inconclusive now, and only the gate's own
// refusal is a denial.
func TestDenialVerdict(t *testing.T) {
	ev := func(kind, msg string) helpers.MissionEvent { return helpers.MissionEvent{EventType: kind, Error: msg} }
	cases := []struct {
		name         string
		openErr      error
		terminal     helpers.MissionEvent
		waitErr      error
		wantDenied   bool
		inconclusive bool
	}{
		{name: "gate refuses at open", openErr: status.Error(codes.PermissionDenied, "tool not enabled for tenant"), wantDenied: true},
		{name: "gate refuses as precondition", openErr: status.Error(codes.FailedPrecondition, "tool access not granted for tenant"), wantDenied: true},
		{name: "missing target at open is not a denial", openErr: status.Error(codes.InvalidArgument, "target_id is required"), inconclusive: true},
		{name: "closed stream is not a denial", waitErr: helpers.ErrStreamClosed, inconclusive: true},
		{name: "deadline is not a denial", waitErr: helpers.ErrStreamDeadlineExceeded, inconclusive: true},
		{name: "mission failed by the gate", terminal: ev("mission_failed", "dispatch: tool not enabled for tenant primary"), wantDenied: true},
		{name: "mission failed by an absent manifest", terminal: ev("mission_failed", "tool e2e-tool-that-does-not-exist: no catalog manifest"), wantDenied: true},
		{name: "stream error by the gate", terminal: ev("stream_error", "rpc error: code = PermissionDenied desc = agent not enabled for tenant"), wantDenied: true},
		{name: "mission failed for another reason is not a denial", terminal: ev("mission_failed", "sandbox launch: image pull back-off"), inconclusive: true},
		{name: "completed is not a denial", terminal: ev("mission_completed", ""), wantDenied: false},
		{name: "unknown terminal is inconclusive", terminal: ev("node_started", ""), inconclusive: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, denied, inconclusive := denialVerdict(tc.openErr, tc.terminal, nil, tc.waitErr)
			if (inconclusive != "") != tc.inconclusive {
				t.Fatalf("inconclusive = %q, want inconclusive=%v", inconclusive, tc.inconclusive)
			}
			if !tc.inconclusive && denied != tc.wantDenied {
				t.Fatalf("denied = %v (reason %q), want %v", denied, reason, tc.wantDenied)
			}
			if denied && reason == "" {
				t.Fatal("a denial must carry its reason")
			}
		})
	}
	if _, _, inc := denialVerdict(errors.New("dial tcp: connection refused"), helpers.MissionEvent{}, nil, nil); inc == "" {
		t.Fatal("a transport error at open must be inconclusive")
	}
}

// TestDenialVerdict_ReadsTheNodeReason: "a work item failed" is the mission's
// summary; the node.failed event behind it carries the gate's wording, and
// that is what the verdict reads (gibson#14, run 35426325346).
func TestDenialVerdict_ReadsTheNodeReason(t *testing.T) {
	terminal := helpers.MissionEvent{EventType: "mission_failed", Error: "a work item failed"}
	gate := []helpers.MissionEvent{
		{EventType: "node.started"},
		{EventType: "node.failed", Error: "dispatch tool nmap: tool not enabled for tenant"},
	}
	reason, denied, inc := denialVerdict(nil, terminal, gate, nil)
	if inc != "" || !denied || reason != gate[1].Error {
		t.Fatalf("got reason=%q denied=%v inconclusive=%q", reason, denied, inc)
	}
	other := []helpers.MissionEvent{{EventType: "node.failed", Error: "sandbox: image pull back-off"}}
	if _, _, inc := denialVerdict(nil, terminal, other, nil); inc == "" || !strings.Contains(inc, "image pull") {
		t.Fatalf("a node failure for another reason must be inconclusive and name it: %q", inc)
	}
	if _, _, inc := denialVerdict(nil, terminal, nil, nil); inc == "" || !strings.Contains(inc, "a work item failed") {
		t.Fatalf("no node event: the summary is the reason: %q", inc)
	}
}
