// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

// gateReason matches the daemon's wording when the per-tenant dispatch gate
// or the catalog refuses a run: ErrToolNotEnabled / ErrAgentNotEnabled
// ("... not enabled for tenant"), ErrToolAccessDenied ("... access not granted
// for tenant"), and a tool or agent that no manifest names.
var gateReason = regexp.MustCompile(`(?i)not enabled for tenant|access not granted|no (catalog )?manifest|not in (the )?catalog|unknown (tool|agent)|catalog.*(not found|unknown)|permission denied`)

// denialVerdict decides what a RunMission outcome proves. Only a refusal the
// gate produced counts as a denial. An InvalidArgument at open, a stream that
// closed with no terminal event, a deadline, or a failure for some other
// reason is inconclusive: the run never reached the gate, so it proves
// nothing about it. The old helper returned "denied" for every one of those,
// which is how two assertions read PASS while the daemon rejected every run
// for a missing target_id (gibson#14).
//
// It returns the reason and whether it was a denial; inconclusive is non-empty
// when the outcome proves nothing, and the caller fails the test with it.
func denialVerdict(openErr error, terminal helpers.MissionEvent, collected []helpers.MissionEvent, waitErr error) (reason string, denied bool, inconclusive string) {
	if openErr != nil {
		switch status.Code(openErr) {
		case codes.PermissionDenied, codes.FailedPrecondition:
			return openErr.Error(), true, ""
		}
		return "", false, fmt.Sprintf("RunMission open failed before the gate: %v", openErr)
	}
	if waitErr != nil {
		return "", false, fmt.Sprintf("no terminal event: %v", waitErr)
	}
	switch terminal.EventType {
	case "mission_completed":
		return terminal.EventType, false, ""
	case "mission_failed", "stream_error":
		// The mission-level error is a summary ("a work item failed"); the
		// node that failed says why. Judge the most specific reason we have.
		why := failureReason(terminal, collected)
		if gateReason.MatchString(why) {
			return why, true, ""
		}
		return "", false, fmt.Sprintf("%s for a reason that is not the gate: %s", terminal.EventType, why)
	}
	return "", false, fmt.Sprintf("unexpected terminal event %q", terminal.EventType)
}

// failureReason returns the node-level error behind a failed mission when
// the stream carried one (the last node.failed / node_failed event with an
// error), else the terminal event's own error, else its message.
func failureReason(terminal helpers.MissionEvent, collected []helpers.MissionEvent) string {
	for i := len(collected) - 1; i >= 0; i-- {
		ev := collected[i]
		if (ev.EventType == "node.failed" || ev.EventType == "node_failed") && ev.Error != "" {
			return ev.Error
		}
	}
	if terminal.Error != "" {
		return terminal.Error
	}
	return terminal.Message
}

// runMissionExpectingGateDenial opens RunMission for defID against targetID
// and returns the gate's reason. It fails the test on an inconclusive
// outcome; see denialVerdict.
func runMissionExpectingGateDenial(t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, defID, targetID string) (string, bool) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var terminal helpers.MissionEvent
	var collected []helpers.MissionEvent
	eventCh, openErr := helpers.Subscribe(runCtx, daemon, defID, targetID)
	var waitErr error
	if openErr == nil {
		terminal, collected, waitErr = helpers.WaitForTerminal(runCtx, eventCh, 90*time.Second)
	}
	reason, denied, inconclusive := denialVerdict(openErr, terminal, collected, waitErr)
	if inconclusive != "" {
		t.Fatalf("the run never reached the dispatch gate, so this proves nothing: %s", inconclusive)
	}
	return reason, denied
}
