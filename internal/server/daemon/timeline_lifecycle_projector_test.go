package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestProjectBrainEvent is an input→output table for the pure projector.
// Each row verifies that a specific brain.Event produces the expected
// api.EventData shape (or nil for non-lifecycle events).
func TestProjectBrainEvent(t *testing.T) {
	type row struct {
		name      string
		ev        brain.Event
		missionID string // resolved mission ID passed by wiring layer

		wantNil       bool   // expect nil return
		wantEventType string // top-level EventType
		wantMissionID string // MissionEvent.MissionID
		wantNodeID    string // MissionEvent.NodeID (empty for status events)
		wantStatus    string // MissionEvent.Payload["status"] (empty for node events)
		wantError     string // MissionEvent.Error (non-empty on failure)
	}

	rows := []row{
		// ---- WorkDispatched → node.started --------------------------------
		{
			name: "WorkDispatched maps to node.started",
			ev: brain.WorkDispatched{
				ID:        "node-abc",
				MissionID: "mission-1",
				ItemKind:  "agent",
				Target:    "recon",
			},
			missionID:     "mission-1",
			wantEventType: "node.started",
			wantMissionID: "mission-1",
			wantNodeID:    "node-abc",
		},
		{
			name: "WorkDispatched uses MissionID from event when missionID arg is empty",
			ev: brain.WorkDispatched{
				ID:        "node-xyz",
				MissionID: "mission-from-event",
				ItemKind:  "tool",
				Target:    "scan",
			},
			missionID:     "", // caller didn't resolve it; projector falls back to event field
			wantEventType: "node.started",
			wantMissionID: "mission-from-event",
			wantNodeID:    "node-xyz",
		},

		// ---- WorkCompleted(ok) → node.completed ---------------------------
		{
			name:          "WorkCompleted ok maps to node.completed",
			ev:            brain.WorkCompleted{ID: "node-abc", Result: "done"},
			missionID:     "mission-1",
			wantEventType: "node.completed",
			wantMissionID: "mission-1",
			wantNodeID:    "node-abc",
		},

		// ---- WorkCompleted(err) → node.failed -----------------------------
		{
			name:          "WorkCompleted err maps to node.failed",
			ev:            brain.WorkCompleted{ID: "node-bad", Err: "connection refused"},
			missionID:     "mission-1",
			wantEventType: "node.failed",
			wantMissionID: "mission-1",
			wantNodeID:    "node-bad",
			wantError:     "connection refused",
		},
		{
			name:    "WorkCompleted without resolved missionID returns nil",
			ev:      brain.WorkCompleted{ID: "node-orphan"},
			missionID: "", // can't project without a mission
			wantNil: true,
		},

		// ---- MissionStarted → status:running ------------------------------
		{
			name:          "MissionStarted maps to status running",
			ev:            brain.MissionStarted{ID: "mission-2"},
			wantEventType: "status",
			wantMissionID: "mission-2",
			wantStatus:    "running",
		},

		// ---- MissionDone(completed) → status:completed -------------------
		{
			name: "MissionDone completed maps to status completed",
			ev: brain.MissionDone{
				ID:      "mission-2",
				Outcome: brain.MissionCompleted,
				Reason:  "all done",
			},
			wantEventType: "status",
			wantMissionID: "mission-2",
			wantStatus:    "completed",
		},

		// ---- MissionDone(failed) → status:failed -------------------------
		{
			name: "MissionDone failed maps to status failed",
			ev: brain.MissionDone{
				ID:      "mission-3",
				Outcome: brain.MissionFailed,
				Reason:  "work item failed",
			},
			wantEventType: "status",
			wantMissionID: "mission-3",
			wantStatus:    "failed",
			wantError:     "work item failed",
		},

		// ---- non-lifecycle events return nil -----------------------------
		{
			name:    "HostObserved returns nil",
			ev:      brain.HostObserved{ScopeID: "s1", Address: "1.2.3.4"},
			wantNil: true,
		},
		{
			name:    "WorkRetried returns nil",
			ev:      brain.WorkRetried{ID: "node-abc"},
			wantNil: true,
		},
		{
			name:    "MissionPauseRequested returns nil",
			ev:      brain.MissionPauseRequested{ID: "mission-1"},
			wantNil: true,
		},
		{
			name:    "MissionResumed returns nil",
			ev:      brain.MissionResumed{ID: "mission-1"},
			wantNil: true,
		},
		{
			name:    "DecisionRequested returns nil",
			ev:      brain.DecisionRequested{MissionID: "mission-1"},
			wantNil: true,
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := ProjectBrainEvent(r.ev, r.missionID)

			if r.wantNil {
				if got != nil {
					t.Errorf("expected nil, got EventData with EventType=%q", got.EventType)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected non-nil EventData, got nil")
			}

			if got.EventType != r.wantEventType {
				t.Errorf("EventType: want %q, got %q", r.wantEventType, got.EventType)
			}
			if got.Source != "timeline-projector" {
				t.Errorf("Source: want %q, got %q", "timeline-projector", got.Source)
			}
			if got.MissionEvent == nil {
				t.Fatalf("MissionEvent is nil")
			}
			me := got.MissionEvent
			if me.MissionID != r.wantMissionID {
				t.Errorf("MissionEvent.MissionID: want %q, got %q", r.wantMissionID, me.MissionID)
			}
			if me.NodeID != r.wantNodeID {
				t.Errorf("MissionEvent.NodeID: want %q, got %q", r.wantNodeID, me.NodeID)
			}
			if me.Error != r.wantError {
				t.Errorf("MissionEvent.Error: want %q, got %q", r.wantError, me.Error)
			}
			if r.wantStatus != "" {
				if me.Payload == nil {
					t.Fatalf("MissionEvent.Payload is nil, want status=%q", r.wantStatus)
				}
				got, ok := me.Payload["status"].(string)
				if !ok || got != r.wantStatus {
					t.Errorf("MissionEvent.Payload[status]: want %q, got %q", r.wantStatus, got)
				}
			} else {
				// For node events: status should NOT be in the payload
				if me.Payload != nil {
					if _, hasStatus := me.Payload["status"]; hasStatus {
						t.Errorf("unexpected status key in Payload for node event %q", r.wantEventType)
					}
				}
			}
		})
	}
}
