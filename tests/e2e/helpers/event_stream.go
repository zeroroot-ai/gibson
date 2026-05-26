//go:build e2e
// +build e2e

// Package helpers — event_stream.go
//
// Typed wrapper around the daemon's RunMission streaming RPC.
// Provides deadline-bound event consumption, ordered-substring assertion,
// and terminal-event wait — all without raw blocking reads.
//
// Design Component 2 / Requirements: R1.5, R1.6, NFR Reliability.
package helpers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// MissionEvent is the typed event record captured from the RunMission stream.
// It mirrors the fields of RunMissionResponse that the e2e test cares about.
type MissionEvent struct {
	EventType string // e.g., "mission_started", "node_started", "mission_completed"
	MissionID string
	NodeID    string
	Message   string
	Error     string
	Timestamp int64 // unix seconds
}

// String formats the event for diagnostic output (NFR Usability).
func (e MissionEvent) String() string {
	if e.Error != "" {
		return fmt.Sprintf("[%s] %s node=%s err=%s", e.EventType, e.MissionID, e.NodeID, e.Error)
	}
	return fmt.Sprintf("[%s] %s node=%s msg=%s", e.EventType, e.MissionID, e.NodeID, e.Message)
}

// IsTerminal reports whether the event signals the end of a mission run.
// Terminal events: "mission_completed" and "mission_failed".
func (e MissionEvent) IsTerminal() bool {
	return strings.EqualFold(e.EventType, "mission_completed") ||
		strings.EqualFold(e.EventType, "mission_failed")
}

// ErrStreamDeadlineExceeded is returned by WaitForTerminal when the deadline
// elapses before a terminal event arrives.
var ErrStreamDeadlineExceeded = errors.New("event_stream: deadline exceeded waiting for terminal event")

// ErrStreamClosed is returned when the event channel was closed without a
// terminal event (stream EOF without mission_completed / mission_failed).
var ErrStreamClosed = errors.New("event_stream: stream closed without terminal event")

// Subscribe opens the RunMission streaming RPC and pumps events into a channel.
//
// The channel is closed exactly once: either when a terminal event is received,
// when the stream returns EOF, or when ctx is cancelled. The caller must drain
// the channel or it will block the goroutine.
//
// NFR Reliability: no raw blocking reads. The goroutine is bounded by ctx.
//
// Requirements: R1.5, R1.6.
func Subscribe(ctx context.Context, client daemonpb.DaemonServiceClient, missionID string) (<-chan MissionEvent, error) {
	stream, err := client.RunMission(ctx, &daemonpb.RunMissionRequest{
		MissionDefinitionId: missionID, // RunMission takes the run's mission ID in this field
		// Note: RunMission actually takes missionDefinitionId + targetId to start a run.
		// For the Subscribe use-case (post-CreateMission), we use the Subscribe RPC instead.
		// This function wraps the RunMission stream — see SubscribeToMission for the
		// post-CreateMission streaming consumer.
	})
	if err != nil {
		return nil, fmt.Errorf("event_stream: Subscribe: RunMission open: %w", err)
	}

	ch := make(chan MissionEvent, 64) // buffered to avoid blocking under load

	go func() {
		defer close(ch)
		for {
			// Check context first — handles cancellation without blocking on Recv.
			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, recvErr := stream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) {
					return // stream ended normally
				}
				// Propagate non-EOF errors as a synthetic terminal event.
				select {
				case ch <- MissionEvent{
					EventType: "stream_error",
					MissionID: missionID,
					Error:     recvErr.Error(),
				}:
				case <-ctx.Done():
				}
				return
			}

			evt := MissionEvent{
				EventType: resp.GetEventType(),
				MissionID: resp.GetMissionId(),
				NodeID:    resp.GetNodeId(),
				Message:   resp.GetMessage(),
				Error:     resp.GetError(),
				Timestamp: resp.GetTimestamp(),
			}

			select {
			case ch <- evt:
			case <-ctx.Done():
				return
			}

			// Stop pumping after terminal event — channel will be closed by defer.
			if evt.IsTerminal() {
				return
			}
		}
	}()

	return ch, nil
}

// SubscribeToMission opens the Subscribe streaming RPC (NOT RunMission) and
// pumps MissionEvent records for the given missionID into a channel.
//
// This is the preferred post-CreateMission streaming consumer. The RunMission
// RPC starts a new run; Subscribe attaches to an existing run's event stream.
//
// Requirements: R1.5.
func SubscribeToMission(ctx context.Context, client daemonpb.DaemonServiceClient, missionID string) (<-chan MissionEvent, error) {
	stream, err := client.Subscribe(ctx, &daemonpb.SubscribeRequest{
		MissionId:  missionID,
		EventTypes: []string{"mission_started", "node_started", "node_completed", "mission_completed", "mission_failed"},
	})
	if err != nil {
		return nil, fmt.Errorf("event_stream: SubscribeToMission: Subscribe open for mission %s: %w", missionID, err)
	}

	ch := make(chan MissionEvent, 64)

	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, recvErr := stream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) {
					return
				}
				select {
				case ch <- MissionEvent{
					EventType: "stream_error",
					MissionID: missionID,
					Error:     recvErr.Error(),
				}:
				case <-ctx.Done():
				}
				return
			}

			// SubscribeResponse wraps events in a oneof; extract MissionEvent if present.
			me := resp.GetMissionEvent()
			if me == nil {
				continue // AgentEvent, FindingEvent, etc. — skip for this helper
			}

			evt := MissionEvent{
				EventType: me.GetEventType(),
				MissionID: me.GetMissionId(),
				NodeID:    me.GetNodeId(),
				Message:   me.GetMessage(),
				Error:     me.GetError(),
				Timestamp: me.GetTimestamp(),
			}

			select {
			case ch <- evt:
			case <-ctx.Done():
				return
			}

			if evt.IsTerminal() {
				return
			}
		}
	}()

	return ch, nil
}

// CollectEvents drains ch until it is closed, capturing all received events.
// It respects ctx cancellation — a cancelled context returns whatever was
// collected so far (without an error, to allow partial assertion).
//
// Requirements: R1.5 (diagnostic dump — last 5 events on failure per NFR Usability).
func CollectEvents(ctx context.Context, ch <-chan MissionEvent) []MissionEvent {
	var collected []MissionEvent
	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return collected
			}
			collected = append(collected, evt)
		case <-ctx.Done():
			return collected
		}
	}
}

// WaitForTerminal blocks until a terminal event (mission_completed or
// mission_failed) arrives on ch, the channel is closed, or the deadline elapses.
//
// Returns (terminalEvent, nil) on success.
// Returns (zero, ErrStreamDeadlineExceeded) if deadline elapses.
// Returns (zero, ErrStreamClosed) if the channel closes without a terminal event.
//
// NFR Reliability: uses ctx deadline, no raw time.Sleep.
// Requirements: R1.6, R8.1 (≤60s budget for mock LLM runs).
func WaitForTerminal(ctx context.Context, ch <-chan MissionEvent, deadline time.Duration) (MissionEvent, []MissionEvent, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	var collected []MissionEvent

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				// Channel closed without terminal event.
				return MissionEvent{}, collected, ErrStreamClosed
			}
			collected = append(collected, evt)
			if evt.IsTerminal() {
				return evt, collected, nil
			}
		case <-deadlineCtx.Done():
			if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
				return MissionEvent{}, collected, fmt.Errorf(
					"%w: waited %s for terminal event on mission stream; collected %d events",
					ErrStreamDeadlineExceeded, deadline, len(collected),
				)
			}
			// Parent context cancelled.
			return MissionEvent{}, collected, ctx.Err()
		}
	}
}

// AssertEventOrder asserts that the collected events contain each expected
// substring in order (subsequence, not exact match).
//
// On failure, t.Errorf is called with the name of the FIRST missing event,
// the full ordered list of collected event types, and a MISSION-B catalog hint.
//
// Requirements: R1.5.
func AssertEventOrder(t *testing.T, events []MissionEvent, expected []string) {
	t.Helper()

	collectedTypes := make([]string, len(events))
	for i, e := range events {
		collectedTypes[i] = e.EventType
	}

	// Walk expected substrings in order through the collected events.
	ei := 0 // index into expected
	for _, evt := range events {
		if ei >= len(expected) {
			break
		}
		if strings.Contains(strings.ToLower(evt.EventType), strings.ToLower(expected[ei])) {
			ei++
		}
	}

	if ei < len(expected) {
		t.Errorf(
			"event_stream: AssertEventOrder: missing event %q at position %d in ordered stream\n"+
				"Expected order: %v\n"+
				"Collected types: %v\n"+
				"Last 5 events: %v\n"+
				"MISSION-B catalog: Candidate D — orchestrator buffer drops events under load "+
				"(see design.md); if node_completed is missing, check internal/daemon/eventbus.go",
			expected[ei], ei,
			expected,
			collectedTypes,
			last5(events),
		)
	}
}

// PrintEventTimeline writes a human-readable event timeline to t.Log.
// Used in the failure diagnostic dump (NFR Usability: last 5 events from the stream).
//
// Requirements: NFR Usability.
func PrintEventTimeline(t *testing.T, events []MissionEvent) {
	t.Helper()
	t.Log("event_stream: event timeline:")
	for i, e := range events {
		t.Logf("  [%d] t=%d type=%s node=%s msg=%s err=%s",
			i, e.Timestamp, e.EventType, e.NodeID, e.Message, e.Error)
	}
}

// last5 returns up to the last 5 events as a summary slice for error messages.
func last5(events []MissionEvent) []string {
	start := len(events) - 5
	if start < 0 {
		start = 0
	}
	out := make([]string, 0, len(events)-start)
	for _, e := range events[start:] {
		out = append(out, e.EventType)
	}
	return out
}
