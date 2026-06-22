package brain

import "sync"

// dispatch.go is the side-effect boundary of the brain (ADR-0009). Systems and
// the reducer stay pure (replayable); a DispatchHandler subscribes to **live**
// WorkDispatched events (a tap that Replay never fires) and actuates the real
// launch off the tick via a Dispatcher. Completion arrives later as a
// WorkCompleted event submitted by whoever the result lands on (the existing SDK
// callback path). Crash-resume re-folds the Timeline silently — no effects
// re-fire — and in-flight work is failed (ResumeFailInFlight), not blindly
// re-dispatched (which would double-fire a side-effectful tool).

// DispatchRequest is the launch actuation passed to a Dispatcher.
type DispatchRequest struct {
	WorkID    string
	MissionID string
	Kind      string // tool | agent | plugin
	Target    string // capability name
	Input     string // opaque dispatch input (CUE node config)
}

// Dispatcher actuates a single unit of work against the real world. It is the
// seam to the existing dispatch infra (Redis work-queue / agent-runner); the
// concrete binding is wired at the cutover (gibson#851). Dispatch is fire-and-
// forget: the result returns later as a WorkCompleted event, not from this call.
type Dispatcher interface {
	Dispatch(req DispatchRequest)
}

// DispatchHandler bridges live WorkDispatched events to a Dispatcher. The tap
// runs inside the locked tick, so it only buffers requests; Drain actuates them
// off the tick (call it from a goroutine, or directly in tests).
type DispatchHandler struct {
	dispatcher Dispatcher
	mu         sync.Mutex
	pending    []DispatchRequest
}

// NewDispatchHandler returns a handler delegating to d. Register Tap as an engine
// subscriber and run Drain off the tick.
func NewDispatchHandler(d Dispatcher) *DispatchHandler {
	return &DispatchHandler{dispatcher: d}
}

// Tap is the engine subscriber: it buffers a DispatchRequest for each live
// WorkDispatched. It does no I/O (it runs inside the tick).
func (h *DispatchHandler) Tap(ev Event) {
	d, ok := ev.(WorkDispatched)
	if !ok {
		return
	}
	h.mu.Lock()
	h.pending = append(h.pending, DispatchRequest{
		WorkID:    d.ID,
		MissionID: d.MissionID,
		Kind:      d.ItemKind,
		Target:    d.Target,
		Input:     d.Input,
	})
	h.mu.Unlock()
}

// Drain actuates all buffered dispatch requests via the Dispatcher, off the tick.
// Returns the number actuated.
func (h *DispatchHandler) Drain() int {
	h.mu.Lock()
	reqs := h.pending
	h.pending = nil
	h.mu.Unlock()
	for _, r := range reqs {
		h.dispatcher.Dispatch(r)
	}
	return len(reqs)
}

// ResumeFailInFlight returns a WorkFailed for every WorkItem still `running` —
// the crash-resume reconciliation (ADR-0009). A crash IS a failure; the retry
// System / Decider decide whether to re-run, so a side-effectful tool is never
// silently re-fired. Call once on resume, after rebuilding the World from the
// Timeline.
func ResumeFailInFlight(w *World) []Event {
	var out []Event
	for _, wi := range w.WorkSnapshot() {
		if wi.State == WorkRunning {
			out = append(out, WorkCompleted{ID: wi.ID, Err: "interrupted: daemon restarted mid-flight"})
		}
	}
	return out
}

// RetrySystem re-arms failed scripted work for another attempt, up to the node's
// CUE RetryPolicy.max_retries (count-based, deterministic — backoff delay is a
// dispatch-layer concern, not part of the replayable core). It must run before
// MissionCompletionSystem so a retryable failure does not prematurely fail a
// no-goal mission.
func RetrySystem(w *World) []Event {
	halted := pausedMissions(w)
	var out []Event
	for _, wi := range w.WorkSnapshot() {
		if wi.Kind == "condition" {
			continue // conditions are evaluated, not dispatched — never retried
		}
		if wi.MissionID != "" && halted[wi.MissionID] {
			continue // mission paused/terminal — do not re-arm its work
		}
		if wi.State == WorkFailed && wi.Attempts <= wi.MaxRetries {
			out = append(out, WorkRetried{ID: wi.ID})
		}
	}
	return out
}
