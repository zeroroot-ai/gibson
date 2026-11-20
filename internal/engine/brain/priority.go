// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"maps"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// priority.go holds the typed priority of a Finding (gibson#1522).
//
// The cve-triage agent writes the priority of a Finding as properties of a
// Finding entity: priority, priority_rule and priority_reason. The World does
// not keep them as free properties. It folds them into the Finding, and only a
// priority from P1 to P4 lands. Any other value is dropped.

// Property names that an agent uses to write the priority of a Finding.
const (
	propPriority       = "priority"
	propPriorityRule   = "priority_rule"
	propPriorityReason = "priority_reason"

	// findingLabel is the Taxonomy label of a Finding node.
	findingLabel = "Finding"
)

// FindingPrioritized sets the priority of one Finding. An empty Rule or Reason
// leaves the stored one as it is, because a rule table writes the priority and
// a model writes the reason, in separate steps.
type FindingPrioritized struct {
	ID        string
	Priority  string
	Rule      string
	Reason    string
	MissionID string
}

// Kind identifies the finding.prioritized brain event.
func (FindingPrioritized) Kind() string { return "finding.prioritized" }

// applyFindingPrioritized updates the Finding in place. A priority outside P1 to
// P4 is not applied, and an unknown Finding changes nothing.
func applyFindingPrioritized(w *World, e FindingPrioritized) {
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.ID != e.ID {
			continue
		}
		if finding.Priority(e.Priority).IsValid() {
			f.Priority = e.Priority
		}
		if e.Rule != "" {
			f.PriorityRule = e.Rule
		}
		if e.Reason != "" {
			f.PriorityReason = e.Reason
		}
		q.Close()
		return
	}
}

// foldFindingPriority moves the priority properties of a Finding entity into
// the Finding and returns the event without them. Any other entity passes
// through unchanged.
func foldFindingPriority(w *World, e EntityObserved) EntityObserved {
	if e.Label != findingLabel {
		return e
	}
	priority, hasP := e.Props[propPriority]
	rule, hasR := e.Props[propPriorityRule]
	reason, hasReason := e.Props[propPriorityReason]
	if !hasP && !hasR && !hasReason {
		return e
	}
	applyFindingPrioritized(w, FindingPrioritized{ID: e.Key, Priority: priority, Rule: rule, Reason: reason})
	props := maps.Clone(e.Props)
	delete(props, propPriority)
	delete(props, propPriorityRule)
	delete(props, propPriorityReason)
	e.Props = props
	return e
}
