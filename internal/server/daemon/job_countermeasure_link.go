// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// job_countermeasure_link.go records the countermeasure that a fix applies
// (gibson#1487). The agent that plans the fix names it in the context of the
// job spec (jobnode.CountermeasureContextKey). The value is the D3FEND id, for
// example "D3-FA". The link is the edge
// (:MergeRequest)-[:APPLIES_COUNTERMEASURE]->(:Countermeasure).
//
// The link is optional. A job with no countermeasure, an id that
// the D3FEND pack does not hold (for example a finding with no technique),
// and a Taxonomy that does not admit the label and the edge type all give no
// edge and no error. The close of the job never fails on a countermeasure.

// countermeasureLookup returns the countermeasure with the id.
type countermeasureLookup func(id string) (ontology.Countermeasure, bool)

// embeddedD3FEND holds the D3FEND pack of the embedded catalog.
var embeddedD3FEND = sync.OnceValue(func() *ontology.DomainPack {
	pack, ok := ontology.EmbeddedCatalog().Get(ontology.D3FENDPackName)
	if !ok {
		return nil
	}
	return &pack
})

// embeddedCountermeasure looks a countermeasure up in the embedded catalog.
func embeddedCountermeasure(id string) (ontology.Countermeasure, bool) {
	pack := embeddedD3FEND()
	if pack == nil {
		return ontology.Countermeasure{}, false
	}
	return pack.Countermeasure(id)
}

// countermeasureAdmitted reports whether the Taxonomy admits the label and the
// edge type of the link. The projector writes only what the Taxonomy admits.
func countermeasureAdmitted() bool {
	return taxonomy.Global.ClassifyNode(ontology.CountermeasureLabel).InTaxonomy &&
		taxonomy.Global.ClassifyRelationship(ontology.AppliesCountermeasureRelationshipType).InTaxonomy
}

// withCountermeasure adds the events of the countermeasure link to the events
// of a closed fix job. mrKey is the key of the merge request of the job.
func withCountermeasure(c jobnode.ClosedJob, mrKey string, events []brain.Event) []brain.Event {
	return append(events, countermeasureEvents(c, mrKey, embeddedCountermeasure, countermeasureAdmitted())...)
}

// countermeasureEvents returns the events that record the countermeasure of a
// closed fix job: the Countermeasure node and the merge request with its edge.
// It returns nothing when the Taxonomy does not admit the link, when the job
// names no countermeasure, or when the countermeasure that it names is not
// one that lookup holds. The merge request has one countermeasure.
func countermeasureEvents(c jobnode.ClosedJob, mrKey string, lookup countermeasureLookup, admitted bool) []brain.Event {
	if !admitted || mrKey == "" {
		return nil
	}
	if c.Countermeasure == "" {
		return nil
	}
	cm, ok := lookup(c.Countermeasure)
	if !ok {
		return nil
	}
	return []brain.Event{
		brain.EntityObserved{
			Label: ontology.CountermeasureLabel, Key: cm.ID, MissionID: c.MissionRunID,
			Props: map[string]string{"name": cm.Name, "tactic": cm.Tactic},
		},
		brain.EntityObserved{
			Label: labelMergeRequest, Key: mrKey, MissionID: c.MissionRunID,
			Edges: []brain.EntityEdge{{
				Type: ontology.AppliesCountermeasureRelationshipType, TargetLabel: ontology.CountermeasureLabel, TargetKey: cm.ID,
			}},
		},
	}
}
