// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"maps"
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// Entity is a typed application-lifecycle node the global Taxonomy admits but
// the World has no bespoke component for: Application, Repository, Image,
// Package, Deployment, Vulnerability, MergeRequest, Pipeline, Control
// (gibson#1656, CONTEXT.md "Application lifecycle").
//
// Identity is (Label, Key): the Taxonomy label plus the stable key the emitter
// derived from the entity's identifying properties (an image digest, a package
// name and version, a CVE id). Folding a second sighting of the same (Label,
// Key) enriches the same entity: properties overlay, edges union. That is what
// makes one CVE across four Applications one Vulnerability node.
//
// Label is never caller-influenced structure: the ingest path puts the
// requested type to the Taxonomy first, and only an admitted label reaches
// here. An out-of-taxonomy type is counted as skipped by the ingest, never
// invented into the World.
type Entity struct {
	ID        uint64
	Label     string
	Key       string
	ScopeID   string
	MissionID string
	Props     map[string]string
	Edges     []EntityEdge
}

// EntityEdge is one outgoing relationship from an Entity to another typed node,
// by (label, key). Type is a Taxonomy relationship type, admitted at ingest.
type EntityEdge struct {
	Type        string
	TargetLabel string
	TargetKey   string
}

// EntityObserved records a sighting of a typed lifecycle entity. It is
// additive: the reducer merges it into the existing (Label, Key) entity when
// one exists.
type EntityObserved struct {
	Label     string
	Key       string
	ScopeID   string
	MissionID string
	Props     map[string]string
	Edges     []EntityEdge
}

// Kind identifies the entity.observed brain event.
func (EntityObserved) Kind() string { return "entity.observed" }

// applyEntityObserved merges the sighting into the World: a new (Label, Key)
// creates an entity; a known one takes the sighting's properties over its own
// and gains any edge it did not already have. An event without a label or a
// key records nothing, because there would be no stable node to project.
func applyEntityObserved(w *World, e EntityObserved) {
	if e.Label == "" || e.Key == "" {
		return
	}

	q := ecs.NewFilter1[Entity](w.ecs).Query()
	for q.Next() {
		ent := q.Get()
		if ent.Label != e.Label || ent.Key != e.Key {
			continue
		}
		if ent.Props == nil {
			ent.Props = map[string]string{}
		}
		maps.Copy(ent.Props, e.Props)
		ent.Edges = unionEdges(ent.Edges, e.Edges)
		if ent.MissionID == "" {
			ent.MissionID = e.MissionID
		}
		q.Close()
		return
	}

	w.entities.NewEntity(&Entity{
		ID:        w.newEntityID(),
		Label:     e.Label,
		Key:       e.Key,
		ScopeID:   e.ScopeID,
		MissionID: e.MissionID,
		Props:     maps.Clone(e.Props),
		Edges:     unionEdges(nil, e.Edges),
	})
}

// unionEdges appends every edge in add that base does not already hold,
// preserving order so replay is deterministic.
func unionEdges(base, add []EntityEdge) []EntityEdge {
	out := append([]EntityEdge(nil), base...)
	for _, edge := range add {
		if edge.Type == "" || edge.TargetLabel == "" || edge.TargetKey == "" {
			continue
		}
		dup := false
		for _, have := range out {
			if have == edge {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, edge)
		}
	}
	return out
}

// EntitySnapshot is a stable, comparable view of an Entity.
type EntitySnapshot struct {
	ID        uint64
	Label     string
	Key       string
	ScopeID   string
	MissionID string
	Props     map[string]string
	Edges     []EntityEdge
}

// EntitySnapshot returns entities in deterministic (Label, Key) order.
func (w *World) EntitySnapshot() []EntitySnapshot {
	var out []EntitySnapshot
	q := ecs.NewFilter1[Entity](w.ecs).Query()
	for q.Next() {
		e := q.Get()
		out = append(out, EntitySnapshot{
			ID:        e.ID,
			Label:     e.Label,
			Key:       e.Key,
			ScopeID:   e.ScopeID,
			MissionID: e.MissionID,
			Props:     maps.Clone(e.Props),
			Edges:     append([]EntityEdge(nil), e.Edges...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		return out[i].Key < out[j].Key
	})
	return out
}
