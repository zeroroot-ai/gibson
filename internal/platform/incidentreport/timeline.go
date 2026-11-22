// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
)

// Labels of the nodes that the report reads.
const (
	labelIncident     = "Incident"
	labelAlert        = "Alert"
	labelMergeRequest = "MergeRequest"
)

// statusVerified is the finding status that closes the exposure window.
const statusVerified = "verified"

// call is one tool call on the Timeline.
type call struct {
	seq uint64
	ev  brain.AgentToolCallObserved
}

// Index is what the reader needs from the Timeline. BuildIndex makes it in one
// pass, so a report costs one read of the history.
type Index struct {
	total    uint64
	entity   map[string]uint64          // label + key -> first position
	raised   map[string]uint64          // finding id -> position of finding.raised
	status   map[string][]statusEvent   // finding id -> changes, in order
	runs     map[string]string          // run id -> agent name
	missions map[string]map[string]bool // label + key -> mission and run ids that observed it
	calls    []call
}

type statusEvent struct {
	seq    uint64
	status string
}

func entityKey(label, key string) string { return label + "\x00" + key }

// BuildIndexFrom walks the history of the tenant once. The position of an event is
// its index in the history, which is the number that GetTimeline gives when the
// request names no mission.
//
// BuildIndexFrom takes a part of the history that starts at the position
// offset of the whole history, and the index keeps the positions of the whole
// history (review R5).
func BuildIndexFrom(history []brain.Event, offset uint64) *Index {
	ix := &Index{
		total:    offset + uint64(len(history)),
		entity:   map[string]uint64{},
		raised:   map[string]uint64{},
		status:   map[string][]statusEvent{},
		runs:     map[string]string{},
		missions: map[string]map[string]bool{},
	}
	for i, ev := range history {
		seq := offset + uint64(i)
		// The codec decodes an event of the durable history as a pointer, and a
		// live Submit carries a value. Both forms count (review m23).
		switch e := derefEvent(ev).(type) {
		case brain.EntityObserved:
			k := entityKey(e.Label, e.Key)
			if _, ok := ix.entity[k]; !ok {
				ix.entity[k] = seq
			}
			set := ix.missions[k]
			if set == nil {
				set = map[string]bool{}
				ix.missions[k] = set
			}
			if e.MissionID != "" {
				set[e.MissionID] = true
			}
			if e.MissionRunID != "" {
				set[e.MissionRunID] = true
			}
		case brain.FindingRaised:
			if _, ok := ix.raised[e.ID]; !ok {
				ix.raised[e.ID] = seq
			}
		case brain.FindingStatusChanged:
			ix.status[e.ID] = append(ix.status[e.ID], statusEvent{seq: seq, status: e.Status})
		case brain.AgentRunObserved:
			if e.AgentName != "" {
				ix.runs[e.RunID] = e.AgentName
			}
		case brain.AgentToolCallObserved:
			ix.calls = append(ix.calls, call{seq: seq, ev: e})
		}
	}
	return ix
}

func frameAt(seq uint64) Frame { return Frame{TimelineSeq: seq, ReplaySeq: seq + 1, Known: true} }

// entityFrame is the frame of the first sighting of a node.
func (ix *Index) entityFrame(label, key string) Frame {
	if seq, ok := ix.entity[entityKey(label, key)]; ok {
		return frameAt(seq)
	}
	return Frame{}
}

// findingFrame is the frame of the event that raised a finding. A finding that
// a job linked, and that no finding.raised event names, falls back to the first
// sighting of its node.
func (ix *Index) findingFrame(id string) Frame {
	if seq, ok := ix.raised[id]; ok {
		return frameAt(seq)
	}
	return ix.entityFrame("Finding", id)
}

// statusHistory returns the changes of the status of a finding, in order.
func (ix *Index) statusHistory(id string) []StatusLine {
	out := make([]StatusLine, 0, len(ix.status[id]))
	for _, s := range ix.status[id] {
		out = append(out, StatusLine{Status: s.status, Frame: frameAt(s.seq)})
	}
	return out
}

// verifiedFrame is the frame of the last change of a finding to `verified`.
// A later change to another status clears it, because a check that finds the
// flaw again sets the finding to `open` (ADR-0178).
func (ix *Index) verifiedFrame(id string) Frame {
	var out Frame
	for _, s := range ix.status[id] {
		if s.status == statusVerified {
			out = frameAt(s.seq)
		} else {
			out = Frame{}
		}
	}
	return out
}

// missionIDs returns the mission ids and run ids that observed the incident or
// one of its alerts. They scope the tool calls that belong to the incident.
func (ix *Index) missionIDs(incident string, alerts []string) map[string]bool {
	out := map[string]bool{}
	add := func(k string) {
		for id := range ix.missions[k] {
			out[id] = true
		}
	}
	add(entityKey(labelIncident, incident))
	for _, a := range alerts {
		add(entityKey(labelAlert, a))
	}
	return out
}

// classify maps a call to an outcome. The typed code that the daemon records
// decides (gibson#1575). An event that has no code, because it came before the
// code or the call succeeded, falls back to the words of the error. A text
// that matches nothing is a failure, never a success.
func classify(code, errText, result string) Outcome {
	switch metatool.ErrCode(code) {
	case metatool.ErrCodeNotAuthorized, metatool.ErrCodeRefused:
		return OutcomeRefused
	case metatool.ErrCodePendingAuthorization, metatool.ErrCodeMergeNotGranted:
		return OutcomePending
	case metatool.ErrCodeFailed:
		return OutcomeFailed
	}
	e := strings.ToLower(errText)
	r := strings.ToLower(result)
	switch {
	case strings.Contains(e, "pending authorization") || strings.Contains(e, "pending_authorization") ||
		strings.Contains(r, "pending authorization") || strings.Contains(r, "pending_authorization"):
		return OutcomePending
	case strings.Contains(e, "permission denied") || strings.Contains(e, "permission_denied") ||
		strings.Contains(e, "not allowed") || strings.Contains(e, "grant"):
		return OutcomeRefused
	case errText != "":
		return OutcomeFailed
	default:
		return OutcomeDone
	}
}

// derefEvent turns a pointer event of the kinds that BuildIndex reads into its
// value. Any other event passes through.
func derefEvent(ev brain.Event) brain.Event {
	switch e := ev.(type) {
	case *brain.EntityObserved:
		return *e
	case *brain.FindingRaised:
		return *e
	case *brain.FindingStatusChanged:
		return *e
	case *brain.AgentRunObserved:
		return *e
	case *brain.AgentToolCallObserved:
		return *e
	}
	return ev
}
