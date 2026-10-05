// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
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

// openFindingsResolver answers jobnode's {{findings.open}} from the tenant
// World: the open findings on the target the run is against (gibson#497).
//
// The target is read from the World's own mission record, not from the request,
// for the reason CONTEXT.md gives for ScopeID: a caller that could name the
// scope could point a fix job at findings it was never granted. A Finding's
// ScopeID IS the target UUID (ADR-0102 makes host identity the (ScopeID,
// Address) coordinate), so the match needs no new provenance.
func openFindingsResolver(reg *brain.Registry) jobnode.FindingsResolver {
	return jobnode.FindingsResolverFunc(func(_ context.Context, tenant, missionRunID string) ([]string, error) {
		if missionRunID == "" {
			return nil, errors.New("a job with no mission run has no target, so no findings to fix")
		}
		w := reg.For(tenant)

		var scope string
		for _, m := range w.Missions() {
			if m.ID == missionRunID {
				scope = m.TargetID
				break
			}
		}
		if scope == "" {
			// Not an empty result. A mission the World does not know, or one with
			// no target, cannot have its findings scoped, and answering "none"
			// would read as "nothing to fix" (gibson#497).
			return nil, fmt.Errorf("mission run %q names no target in the tenant World", missionRunID)
		}

		var ids []string
		for _, f := range w.Findings() {
			if f.ScopeID == scope && f.Status == brain.FindingStatusOpen {
				ids = append(ids, f.ID)
			}
		}
		return ids, nil
	})
}
