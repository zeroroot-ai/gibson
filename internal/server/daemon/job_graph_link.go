// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
)

const (
	mergeRequestDeliverable = "merge_request"
	labelFinding            = "Finding"
	labelMergeRequest       = "MergeRequest"
	edgeFixedBy             = "FIXED_BY"
)

// jobGraphLink turns a closed fix job into the graph edge
// (:Finding)-[:FIXED_BY]->(:MergeRequest) (gibson#477). It submits ordinary
// entity events to the tenant World. The graph projector stays the one writer.
type jobGraphLink struct {
	submit func(tenant string, ev brain.Event)
	// findings returns the ids and scopes of the findings in the tenant World.
	findings func(tenant string) map[string]string
	logger   *slog.Logger
}

var _ jobnode.CloseObserver = (*jobGraphLink)(nil)

func newJobGraphLink(reg *brain.Registry, logger *slog.Logger) *jobGraphLink {
	return &jobGraphLink{
		submit: func(tenant string, ev brain.Event) { reg.For(tenant).Submit(ev) },
		findings: func(tenant string) map[string]string {
			out := map[string]string{}
			for _, f := range reg.For(tenant).Findings() {
				out[f.ID] = f.ScopeID
			}
			return out
		},
		logger: logger,
	}
}

// JobClosed submits the events for one accomplished close.
func (l *jobGraphLink) JobClosed(_ context.Context, c jobnode.ClosedJob) {
	events, skipped := fixedByEvents(c, l.findings)
	if skipped > 0 {
		l.logger.Info("job inputs that are not findings were left out of the FIXED_BY link",
			"job_id", c.JobID, "skipped", skipped)
	}
	for _, ev := range events {
		l.submit(c.TenantID, ev)
	}
}

// fixedByEvents builds the events for a closed job. It returns nothing when
// the job delivered no merge request. It keeps only the inputs that are
// findings in the tenant World and counts the rest as skipped. The projector
// creates a missing edge target, so an input that names a plan and carries the
// Finding label would become a phantom :Finding node. Nothing is guessed.
func fixedByEvents(c jobnode.ClosedJob, findings func(tenant string) map[string]string) (events []brain.Event, skippedInputs int) {
	var mrKey, mrURL, mrRef string
	for _, d := range c.Deliverables {
		if d.Kind != mergeRequestDeliverable {
			continue
		}
		if key := firstNonEmpty(d.URL, d.Ref); key != "" {
			mrKey, mrURL, mrRef = key, d.URL, d.Ref
			break
		}
	}
	if mrKey == "" {
		return nil, 0
	}

	known := findings(c.TenantID)
	// prealloc: at most one event per input, plus the merge request itself.
	events = make([]brain.Event, 0, len(c.Inputs)+1)
	seen := make(map[string]bool, len(c.Inputs))
	for _, id := range c.Inputs {
		if seen[id] {
			continue
		}
		seen[id] = true
		scope, ok := known[id]
		if !ok {
			skippedInputs++
			continue
		}
		events = append(events, brain.EntityObserved{
			// Key is the World id, the value the projector merges a Finding on
			// (brain_id). Any other key writes a second node.
			Label: labelFinding, Key: id, ScopeID: scope, MissionID: c.MissionRunID,
			Edges: []brain.EntityEdge{{Type: edgeFixedBy, TargetLabel: labelMergeRequest, TargetKey: mrKey}},
		})
	}
	if len(events) == 0 {
		return nil, skippedInputs
	}
	props := map[string]string{"job_id": c.JobID}
	if mrURL != "" {
		props["url"] = mrURL
	}
	if mrRef != "" {
		props["ref"] = mrRef
	}
	mr := brain.EntityObserved{Label: labelMergeRequest, Key: mrKey, MissionID: c.MissionRunID, Props: props}
	return append([]brain.Event{mr}, events...), skippedInputs
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
