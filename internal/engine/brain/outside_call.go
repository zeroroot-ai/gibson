// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// OutsideAgentCall is one delegation of a mission agent to an outside A2A agent
// (epic gibson#1366, gibson#1403). An outside call has no work item in the
// daemon, so the daemon records it from the span of the Agent gateway. The World
// keeps each call with the caller, the target, the times and the outcome, so the
// Timeline shows the delegation.
type OutsideAgentCall struct {
	// CallID is stable for the span. A second delivery of the same span gives the
	// same ID, and the reducer keeps one call for it.
	CallID    string `json:"call_id"`
	MissionID string `json:"mission_id"`
	// TaskID is the task of the grant of the caller. It is the nearest id of the
	// calling run that the gateway span holds.
	TaskID string `json:"task_id,omitempty"`
	// Subject is the trusted subject that ext-authz set for the call.
	Subject string `json:"subject,omitempty"`
	// Target is the name of the outside agent.
	Target string `json:"target"`
	// Method is the A2A method of the call, for example SendMessage.
	Method string `json:"method,omitempty"`
	// StartUnixNano and EndUnixNano are the times of the span.
	StartUnixNano int64 `json:"start_unix_nano"`
	EndUnixNano   int64 `json:"end_unix_nano"`
	// Status is "ok" or "error".
	Status string `json:"status"`
	// HTTPStatus is the status code of the answer of the outside agent.
	HTTPStatus int `json:"http_status,omitempty"`
	// RecordedAtUnixNano is set by the daemon and carried on the event, so a
	// replay gives the same World.
	RecordedAtUnixNano int64 `json:"recorded_at_unix_nano"`
}

// OutsideAgentCalled records one delegation to an outside agent.
type OutsideAgentCalled OutsideAgentCall

// Kind identifies this event on the Timeline.
func (OutsideAgentCalled) Kind() string { return "outside_agent.called" }

func applyOutsideAgentCalled(w *World, e OutsideAgentCalled) {
	for i := range w.outsideAgentCalls {
		if w.outsideAgentCalls[i].CallID == e.CallID {
			w.outsideAgentCalls[i] = OutsideAgentCall(e)
			return
		}
	}
	w.outsideAgentCalls = append(w.outsideAgentCalls, OutsideAgentCall(e))
}

// OutsideAgentCalls returns each delegation to an outside agent, in the order of
// the Timeline.
func (w *World) OutsideAgentCalls() []OutsideAgentCall {
	return append([]OutsideAgentCall(nil), w.outsideAgentCalls...)
}

// OutsideAgentCallSnapshot returns the calls for a snapshot.
func (w *World) OutsideAgentCallSnapshot() []OutsideAgentCall {
	if len(w.outsideAgentCalls) == 0 {
		return nil
	}
	return w.OutsideAgentCalls()
}
