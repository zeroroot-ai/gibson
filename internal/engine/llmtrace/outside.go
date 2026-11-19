// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The attributes of an A2A span of the Agent gateway that the daemon reads, in
// addition to the trusted values of ext-authz. The agentgateway adds the first
// three itself. The last one is a CEL field of the trace policy that reads the
// route header of the caller, after ext-authz checked it.
const (
	attrProtocol  = "protocol"
	attrA2AMethod = "a2a.method"
	attrA2AResult = "a2a.response.outcome"
	attrHTTPCode  = "http.response.status_code"
	// AttrRouteAgent is the name of the target agent of the call.
	AttrRouteAgent = "gibson.route_agent"
)

// ErrNotAnA2ACall means that the span is not an A2A call of the Agent gateway.
var ErrNotAnA2ACall = errors.New("llmtrace: the span is not an A2A call")

// OutsideCall is one A2A call that a mission agent made through the Agent
// gateway, read from a span. Whether the target is an outside agent is not in
// the span. The caller of OutsideCallFromSpan decides that from the records of
// the tenant.
type OutsideCall struct {
	CallID        string
	Tenant        string
	Subject       string
	Mission       string
	Task          string
	Target        string
	Method        string
	StartUnixNano int64
	EndUnixNano   int64
	HTTPStatus    int
	// Outcome is "ok" or "error".
	Outcome string
}

// OutsideCallFromSpan reads an A2A call from a span. It returns ErrNotAnA2ACall
// for a span of another protocol, and an error for an A2A span that lacks a
// value that the event needs.
func OutsideCallFromSpan(sp Span) (OutsideCall, error) {
	a := sp.Attributes
	if attrString(a, attrProtocol) != "a2a" {
		return OutsideCall{}, fmt.Errorf("%w: protocol %q", ErrNotAnA2ACall, attrString(a, attrProtocol))
	}
	c := OutsideCall{
		CallID:        "gw-" + attrString(a, attrTraceID) + "-" + attrString(a, attrSpanID),
		Tenant:        attrString(a, AttrTenant),
		Subject:       attrString(a, AttrSubject),
		Mission:       attrString(a, AttrMission),
		Task:          attrString(a, AttrTask),
		Target:        attrString(a, AttrRouteAgent),
		Method:        attrString(a, attrA2AMethod),
		StartUnixNano: sp.StartUnixNano,
		EndUnixNano:   sp.EndUnixNano,
		HTTPStatus:    int(attrInt(a, attrHTTPCode)),
	}
	if c.CallID == "gw--" {
		return OutsideCall{}, errors.New("llmtrace: an A2A span has no trace id and no span id")
	}
	if c.Target == "" {
		return OutsideCall{}, fmt.Errorf("llmtrace: an A2A span has no %s", AttrRouteAgent)
	}
	if c.StartUnixNano == 0 || c.EndUnixNano < c.StartUnixNano {
		return OutsideCall{}, errors.New("llmtrace: an A2A span has no valid start and end time")
	}
	c.Outcome = "ok"
	if c.HTTPStatus >= 400 || (attrString(a, attrA2AResult) != "" && attrString(a, attrA2AResult) != "success") {
		c.Outcome = "error"
	}
	return c, nil
}

// Event returns the Timeline event of a delegation. recordedAt is the time that
// the daemon read the span.
func (c OutsideCall) Event(recordedAt time.Time) brain.Event {
	return brain.OutsideAgentCalled{
		CallID: c.CallID, MissionID: c.Mission, TaskID: c.Task, Subject: c.Subject, Target: c.Target,
		Method: c.Method, StartUnixNano: c.StartUnixNano, EndUnixNano: c.EndUnixNano, Status: c.Outcome,
		HTTPStatus: c.HTTPStatus, RecordedAtUnixNano: recordedAt.UnixNano(),
	}
}
