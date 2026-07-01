// Package daemon — timeline_lifecycle_projector.go
//
// TimelineLifecycleProjector is the single, canonical source of coarse
// dashboard lifecycle events (status + node.*) as required by ADR-0011
// decision 4 and gibson#1116.
//
// The old path emitted MissionEventData directly from mission_manager
// executeMission via scattered emitEvent calls. This projector replaces that
// path entirely: it taps the live brain.Event stream (via engine.Subscribe)
// and derives the same MissionEventData wire shape from first principles, so
// the dashboard SSE bridge, Subscribe filter, and Redis stream shape are
// unchanged — only the source moves.
//
// Mapping (brain.Event → api.EventData):
//
//	WorkDispatched       → node.started   (nodeId = work.ID = CUE node id)
//	WorkCompleted(ok)    → node.completed (nodeId = work.ID)
//	WorkCompleted(err)   → node.failed    (nodeId = work.ID)
//	MissionStarted       → status event   (status: running)
//	MissionDone(ok)      → status event   (status: completed)
//	MissionDone(fail)    → status event   (status: failed)
//
// All other brain.Event kinds return nil (not a lifecycle event).
//
// The projector is a pure function (ProjectBrainEvent) — unit-testable as an
// input→output table — plus a thin wiring layer (InstallLifecycleProjector)
// that hooks one projector per engine via engine.Subscribe and fans the
// resulting api.EventData to both the in-process EventBus and the tenant's
// Redis Stream.
package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// ProjectBrainEvent maps a single brain.Event to the coarse dashboard
// lifecycle api.EventData. Returns nil for events that are not lifecycle
// transitions the dashboard cares about.
//
// This is the pure, stateless projection kernel. It has no side-effects and
// can be called from tests with an arbitrary sequence of events to verify the
// table.
//
// WorkNode.ID is the CUE node id (WorkDispatched.ID / WorkCompleted.ID).
// MissionID is carried directly on mission events; for work events it is
// carried on WorkDispatched.MissionID. WorkCompleted only carries WorkID, so
// the caller passes the resolved missionID (looked up from the in-flight work
// table by the wiring layer).
func ProjectBrainEvent(ev brain.Event, missionID string) *api.EventData {
	now := time.Now()
	switch e := ev.(type) {

	// ---- node lifecycle -----------------------------------------------

	case brain.WorkDispatched:
		// work.dispatched → node.started
		// nodeId = CUE node id (WorkDispatched.ID is the work item ID which IS
		// the CUE node id, per ADR-0011 decision 4: "WorkNode.ID is the CUE
		// node id").
		mid := e.MissionID
		if mid == "" {
			mid = missionID
		}
		return missionEventData(now, "node.started", mid, e.ID, "", "")

	case brain.WorkCompleted:
		// work.completed(ok) → node.completed
		// work.completed(err) → node.failed
		if missionID == "" {
			// Can't attribute without a missionID — skip.
			return nil
		}
		if e.Err != "" {
			return missionEventData(now, "node.failed", missionID, e.ID, "", e.Err)
		}
		return missionEventData(now, "node.completed", missionID, e.ID, "", "")

	// ---- mission lifecycle -------------------------------------------

	case brain.MissionStarted:
		return missionEventData(now, "status", e.ID, "", "running", "")

	case brain.MissionDone:
		status := "completed"
		errMsg := ""
		if e.Outcome == brain.MissionFailed {
			status = "failed"
			errMsg = e.Reason
		}
		return missionEventData(now, "status", e.ID, "", status, errMsg)
	}

	return nil
}

// missionEventData builds the api.EventData wrapper around a MissionEventData
// payload. eventType is the top-level event type (e.g. "node.started");
// status (non-empty) is stored in the payload for status events; errMsg is
// stored in the Error field when non-empty.
func missionEventData(
	ts time.Time,
	eventType string,
	missionID string,
	nodeID string,
	status string,
	errMsg string,
) *api.EventData {
	med := &api.MissionEventData{
		EventType: eventType,
		Timestamp: ts,
		MissionID: missionID,
		NodeID:    nodeID,
		Error:     errMsg,
	}
	if status != "" {
		med.Payload = map[string]interface{}{"status": status}
	}
	return &api.EventData{
		EventType: eventType,
		Timestamp: ts,
		Source:    "timeline-projector",
		MissionEvent: med,
	}
}

// lifecycleProjectorTap is installed as an engine.Subscribe tap. It projects
// each live brain.Event (in Timeline order, inside the tick) to the coarse
// lifecycle vocabulary and fans it out to the in-process EventBus + the
// tenant's Redis Stream.
//
// WorkCompleted events carry only a WorkID; the tap must resolve the owning
// missionID from the engine's live work snapshot. This read is safe because
// the tap runs inside the tick (the same single-writer context that produced
// the event), so the World reflects the event just applied.
type lifecycleProjectorTap struct {
	tenant      string
	eng         *brain.Engine
	eventBus    *EventBus
	redisStream *RedisEventStream
	logger      *slog.Logger
}

// apply is called inside the engine tick after an event is applied. It must
// not block or do I/O directly. Publishing to Redis is a network call but it
// is already the established pattern used by OrchestratorEventBusAdapter
// (which also runs inside Publish calls originating from the tick). To keep
// the tap non-blocking the publish is launched in a goroutine.
func (p *lifecycleProjectorTap) apply(ev brain.Event) {
	var missionID string

	// WorkCompleted carries only a work ID; resolve the owning mission from
	// the current World snapshot (read-safe inside the tick because Reduce has
	// already applied the event to the World in this same tick sweep).
	if wc, ok := ev.(brain.WorkCompleted); ok {
		for _, ws := range p.eng.Work() {
			if ws.ID == wc.ID {
				missionID = ws.MissionID
				break
			}
		}
		if missionID == "" {
			// Unknown work — can't project. This can happen for work created
			// before this projector was installed or for work with no owning
			// mission; safe to skip.
			return
		}
	}

	projected := ProjectBrainEvent(ev, missionID)
	if projected == nil {
		return // not a lifecycle event
	}

	// Fan out in a goroutine so the tick is never blocked on I/O.
	out := *projected // copy: goroutine must not hold a pointer into the stack
	go func() {
		ctx := context.Background()

		// In-process EventBus.
		if p.eventBus != nil {
			if err := p.eventBus.Publish(ctx, out); err != nil {
				p.logger.Debug("lifecycle projector: eventbus publish error", "error", err)
			}
		}

		// Redis stream (optional; matches existing fanout pattern in
		// OrchestratorEventBusAdapter.Publish).
		if p.redisStream != nil {
			if err := p.redisStream.PublishEvent(ctx, p.tenant, out); err != nil {
				p.logger.Debug("lifecycle projector: redis publish error", "error", err)
			}
		}
	}()
}

// InstallLifecycleProjector registers a lifecycle projector tap on the given
// engine. It is called once per engine creation via brain.Registry.OnEngine.
// The projector converts brain.Events to the coarse dashboard vocabulary and
// publishes them to eventBus + redisStream (ADR-0011 decision 4, gibson#1116).
//
// The tap must be installed before the tick loop starts (before the first
// engine.Run call), which is guaranteed because OnEngine hooks fire inside
// Registry.For before go e.Run(ctx).
//
// eventBus and redisStream may be nil; the projector is nil-safe for both.
func InstallLifecycleProjector(
	tenant string,
	eng *brain.Engine,
	eventBus *EventBus,
	redisStream *RedisEventStream,
	logger *slog.Logger,
) {
	if logger == nil {
		logger = slog.Default()
	}
	tap := &lifecycleProjectorTap{
		tenant:      tenant,
		eng:         eng,
		eventBus:    eventBus,
		redisStream: redisStream,
		logger:      logger.With("component", "lifecycle-projector", "tenant", tenant),
	}
	eng.Subscribe(tap.apply)
}
