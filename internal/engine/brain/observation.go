// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"maps"
	"sort"

	"github.com/mlange-42/ark/ecs"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// Observation is the open-world escape hatch: a shape an agent perceived that
// the global Taxonomy does not admit (ADR-0012). It is what makes "an agent can
// always write, and can never invent schema" true — an out-of-taxonomy shape is
// never rejected and never lost, it just lands here instead of becoming a typed
// node. Sensing later promotes a recurring Observation shape into the Taxonomy;
// the residue stays.
//
// Identity is EventID, the Timeline event id, so projection is replayable:
// folding the same event twice yields the same node.
type Observation struct {
	ID uint64

	// EventID is the Timeline event id — the identity of this Observation and
	// of the graph node it projects to.
	EventID string

	// ScopeID and MissionID are resolved server-side (ADR-0012); an agent has
	// no field with which to state either.
	ScopeID   string
	MissionID string

	// Shape is the label the agent asked for, verbatim. It is data, never
	// structure: the node's label is the constant Observation.
	Shape string

	// ContentHash is the recurrence key, computed by the reducer rather than
	// carried on the event, so an emitter cannot forge it.
	ContentHash string

	// Payload is the unschematized residue.
	Payload map[string]string

	// ObservedAt is when the agent saw it, in Unix milliseconds.
	ObservedAt int64
}

// ObservationRecorded records an out-of-taxonomy shape. It is append-only: there
// is no event that updates or deletes an Observation (ADR-0012, "Write
// contract").
type ObservationRecorded struct {
	// EventID is the Timeline event id and therefore the Observation's
	// identity. An event without one records nothing — there would be no
	// replay-stable key to project.
	EventID    string
	ScopeID    string
	MissionID  string
	Shape      string
	Payload    map[string]string
	ObservedAt int64
}

// Kind identifies the observation.recorded brain event.
func (ObservationRecorded) Kind() string { return "observation.recorded" }

// applyObservationRecorded creates an Observation keyed by the Timeline event
// id.
//
// Folding the same event id twice is a no-op, which is what makes replay
// reproduce identical nodes. Two *different* sightings of the same fact carry
// different event ids and therefore stay distinct, even when their content
// hashes match — "seen again three weeks later" is signal in this domain, and
// it is the input Sensing needs to decide what to promote.
func applyObservationRecorded(w *World, e ObservationRecorded) {
	if e.EventID == "" {
		return
	}

	q := ecs.NewFilter1[Observation](w.ecs).Query()
	for q.Next() {
		if q.Get().EventID == e.EventID {
			q.Close()
			return
		}
	}

	w.observations.NewEntity(&Observation{
		ID:          w.newObservationID(),
		EventID:     e.EventID,
		ScopeID:     e.ScopeID,
		MissionID:   e.MissionID,
		Shape:       e.Shape,
		ContentHash: taxonomy.ContentHash(e.Shape, e.Payload),
		Payload:     maps.Clone(e.Payload),
		ObservedAt:  e.ObservedAt,
	})
}

// ObservationSnapshot is a stable view of an Observation.
type ObservationSnapshot struct {
	ID          uint64
	EventID     string
	ScopeID     string
	MissionID   string
	Shape       string
	ContentHash string
	Payload     map[string]string
	ObservedAt  int64
}

// ObservationSnapshot returns observations in deterministic event-id order.
func (w *World) ObservationSnapshot() []ObservationSnapshot {
	var out []ObservationSnapshot
	q := ecs.NewFilter1[Observation](w.ecs).Query()
	for q.Next() {
		o := q.Get()
		out = append(out, ObservationSnapshot{
			ID:          o.ID,
			EventID:     o.EventID,
			ScopeID:     o.ScopeID,
			MissionID:   o.MissionID,
			Shape:       o.Shape,
			ContentHash: o.ContentHash,
			Payload:     maps.Clone(o.Payload),
			ObservedAt:  o.ObservedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out
}
