// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package incidentreport reads the report of one incident (ADR-0180,
// gibson#1480). The report holds the alerts of the incident, what the incident
// reaches, each response action with its result and the grant that allowed it,
// the cause with its fix and the proof of the fix. Each line names the position
// of its event on the Timeline, so a person can replay it.
//
// The reader joins two sources. The graph of the tenant says what exists. The
// Timeline of the tenant says when it happened and in which order. The graph
// has one database for each tenant, and the Timeline has one stream for each
// tenant. No call takes a tenant from the caller. The tenant comes from the
// context of the call, which the identity of the caller sets.
//
// The report holds evidence only. It states no verdict about a control.
package incidentreport

import "time"

// Frame is the position of one line on the Timeline of the tenant.
//
// TimelineSeq is the 0-based position of the event, the number that
// WorldService.GetTimeline gives for it when the request names no mission.
// ReplaySeq is the value to send to WorldService.GetFrameAt, with no mission,
// to get the World as it stood after that event. It is TimelineSeq plus one.
// Known is false when the Timeline holds no event for the line. A line with no
// event is still in the report, because the graph holds it.
type Frame struct {
	TimelineSeq uint64
	ReplaySeq   uint64
	Known       bool
}

// AlertLine is one alert of the incident.
type AlertLine struct {
	Key      string
	Title    string
	Source   string
	Severity string
	Frame    Frame
}

// ReachedLine is one thing that the incident reaches, with the alert that names
// it through an AFFECTS edge.
type ReachedLine struct {
	Label    string
	Key      string
	AlertKey string
	Frame    Frame
}

// Outcome is the result of one response action.
type Outcome string

const (
	// OutcomeDone means that the connector accepted the call.
	OutcomeDone Outcome = "done"
	// OutcomeRefused means that the daemon refused the call because the grant
	// of the agent does not allow it.
	OutcomeRefused Outcome = "refused"
	// OutcomePending means that the call waits in the approval queue (ADR-0132).
	OutcomePending Outcome = "pending_authorization"
	// OutcomeFailed means that the call ran and returned an error.
	OutcomeFailed Outcome = "failed"
)

// GrantLine is the grant that allowed one response action.
type GrantLine struct {
	ID         string
	Capability string
	// GrantedBy is the person who gave the grant. It is never the owner of the
	// agent, and it is empty when no audit record names the grantor.
	GrantedBy string
	// GrantedAtUnix is the time of the grant, in seconds.
	GrantedAtUnix int64
}

// ActionLine is one response action.
type ActionLine struct {
	// ToolID is the canonical tool id, "mcp:<connector>:<tool>".
	ToolID    string
	Connector string
	Tool      string
	AgentName string
	// GrantID is the grant that the Timeline event of the call names. Grant
	// holds the grant that it reads.
	GrantID string
	// CalledAt is the time of the call. It is zero when the event has no time.
	CalledAt time.Time
	Outcome  Outcome
	// Error is the error that the call returned. It is empty for a call that
	// the connector accepted.
	Error string
	// Result is the result of the call, after the redaction of the tenant.
	Result string
	// Controls holds the ids of the NIST 800-53 controls that the action is
	// evidence for.
	Controls []string
	// Grant is nil when the grant is not recorded. A refused call has no grant.
	Grant *GrantLine
	Frame Frame
}

// StatusLine is one change of the status of a finding.
type StatusLine struct {
	Status string
	Frame  Frame
}

// CauseLine is the cause of the incident: a finding that the Incident node
// names with CAUSED_BY.
type CauseLine struct {
	FindingKey string
	Title      string
	Severity   string
	// Status is the status in the graph now.
	Status string
	// Raised is the frame of the event that raised the finding.
	Raised Frame
	// History holds each change of status, in Timeline order. The proof of the
	// fix is the change to `verified`.
	History []StatusLine
}

// FixLine is one merge request that fixes the cause.
type FixLine struct {
	FindingKey      string
	MergeRequestKey string
	URL             string
	Ref             string
	Frame           Frame
	// VerifiedBy is the key of the pipeline that verified the finding. It is
	// empty when no pipeline verified it.
	VerifiedBy string
	// Verified is the frame of the change of the finding to `verified`. Known
	// is false when the finding is not verified.
	Verified Frame
}

// Report is the report of one incident.
type Report struct {
	IncidentKey string
	Alerts      []AlertLine
	Reached     []ReachedLine
	Actions     []ActionLine
	Causes      []CauseLine
	Fixes       []FixLine
	// TimelineTotal is the number of events in the Timeline when the reader
	// read it. A frame is valid for a report with the same total.
	TimelineTotal uint64
}
