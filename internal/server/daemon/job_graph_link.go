// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
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
//
// The merge request comes from the deliverable of the job, and so from the
// agent. The daemon later reverts that merge request with its own grant. So
// the link reads the merge request on the Git host first (review B1). It
// links only a merge request that is open, that was opened after the claim
// of the job, and that comes from the job branch. Any other merge request is
// refused: an agent, or a prompt injection, could name a merge request that
// a person merged, and the daemon would then revert the work of that person.
type jobGraphLink struct {
	submit func(tenant string, ev brain.Event)
	// findings returns the scope, the status and the claim of each finding in
	// the tenant World, keyed by finding id.
	findings func(tenant string) map[string]findingRef
	// mergeRequests reads a merge request on the Git host of the tenant.
	mergeRequests mergeRequestReader
	now           func() time.Time
	logger        *slog.Logger
}

// mergeRequestReader reads one merge request through the governed connector
// path. fixloop.ConnectorReader satisfies it.
type mergeRequestReader interface {
	MergeRequest(ctx context.Context, tenant, missionID, key string) (fixloop.MergeFact, error)
}

// findingRef is what the link needs to know about a finding in the World.
type findingRef struct {
	scope     string
	status    string
	claim     string
	claimedAt time.Time
}

var _ jobnode.CloseObserver = (*jobGraphLink)(nil)

func newJobGraphLink(reg *brain.Registry, mrs mergeRequestReader, logger *slog.Logger) *jobGraphLink {
	return &jobGraphLink{
		submit: func(tenant string, ev brain.Event) { reg.For(tenant).Submit(ev) },
		findings: func(tenant string) map[string]findingRef {
			out := map[string]findingRef{}
			for _, f := range reg.For(tenant).Findings() {
				out[f.ID] = findingRef{scope: f.ScopeID, status: f.Status, claim: f.FixClaim, claimedAt: f.FixClaimedAt}
			}
			return out
		},
		mergeRequests: mrs,
		now:           func() time.Time { return time.Now().UTC() },
		logger:        logger,
	}
}

// JobClosed submits the events for one accomplished close.
func (l *jobGraphLink) JobClosed(ctx context.Context, c jobnode.ClosedJob) {
	mrKey, _, _ := deliveredMergeRequest(c)
	if mrKey == "" {
		return
	}
	now := time.Now().UTC()
	if l.now != nil {
		now = l.now()
	}
	known := l.findings(c.TenantID)
	claim := jobnode.ClaimName(c.MissionRunID, c.NodeID)
	held := heldFindings(c, known, claim)
	if len(held) > 0 {
		if reason := l.vet(ctx, c, mrKey, held, known); reason != "" {
			l.refuse(c, mrKey, claim, held, reason, now)
			return
		}
	}
	// Only the findings that this job holds take the link. A finding that no
	// job holds, or that another job holds, keeps what it has.
	events, skipped := fixedByEvents(c, func(string) map[string]findingRef { return onlyHeld(known, held) }, now)
	if skipped > 0 {
		l.logger.Info("job inputs that are not findings of this job were left out of the FIXED_BY link",
			"job_id", c.JobID, "skipped", skipped)
	}
	for _, ev := range events {
		l.submit(c.TenantID, ev)
	}
}

// deliveredMergeRequest returns the key, the URL and the ref of the first merge
// request that the job delivered. The key is empty when it delivered none.
func deliveredMergeRequest(c jobnode.ClosedJob) (key, url, ref string) {
	for _, d := range c.Deliverables {
		if d.Kind != mergeRequestDeliverable {
			continue
		}
		if k := firstNonEmpty(d.URL, d.Ref); k != "" {
			return k, d.URL, d.Ref
		}
	}
	return "", "", ""
}

// heldFindings returns the inputs that are findings that the claim of the job
// holds, in input order and once each.
func heldFindings(c jobnode.ClosedJob, known map[string]findingRef, claim string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range c.Inputs {
		if ref, ok := known[id]; ok && !seen[id] && ref.claim == claim {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func onlyHeld(known map[string]findingRef, held []string) map[string]findingRef {
	out := make(map[string]findingRef, len(held))
	for _, id := range held {
		out[id] = known[id]
	}
	return out
}

// vet reads the merge request on the Git host and returns why the link is
// refused, or "" when the merge request is the work of this job.
func (l *jobGraphLink) vet(ctx context.Context, c jobnode.ClosedJob, mrKey string, held []string, known map[string]findingRef) string {
	if l.mergeRequests == nil {
		return "the daemon has no reader of the Git host, so it cannot check the merge request"
	}
	fact, err := l.mergeRequests.MergeRequest(ctx, c.TenantID, c.MissionRunID, mrKey)
	if err != nil {
		return "the daemon could not read the merge request on the Git host: " + err.Error()
	}
	var claimedAt time.Time
	for _, id := range held {
		if t := known[id].claimedAt; t.After(claimedAt) {
			claimedAt = t
		}
	}
	return mergeRequestRefusal(fact, jobnode.JobBranch(c.JobID), claimedAt)
}

// mergeRequestRefusal returns why a merge request is not the work of a fix job,
// or "" when it is. The job branch and the time of the claim come from the
// daemon. The fact comes from the Git host. Nothing comes from the agent.
func mergeRequestRefusal(fact fixloop.MergeFact, branch string, claimedAt time.Time) string {
	switch {
	case fact.State != fixloop.MROpen:
		return fmt.Sprintf("the merge request is %q on the Git host, not open", fact.State)
	case fact.SourceBranch == "" || fact.CreatedAt.IsZero():
		// The check needs both fields, and an old connector server does not
		// send them (review R2). The daemon keeps the check and names the
		// cause, so the operator updates the connector.
		return errConnectorLacksMergeFields
	case fact.SourceBranch != branch:
		return fmt.Sprintf("the merge request comes from branch %q, not from the job branch %q", fact.SourceBranch, branch)
	case claimedAt.IsZero():
		return "the claim of the job has no time, so the age of the merge request cannot be checked"
	case fact.CreatedAt.IsZero():
		return "the Git host gave no time of creation for the merge request"
	case fact.CreatedAt.Before(claimedAt):
		return fmt.Sprintf("the merge request was opened at %s, before the claim of the job at %s",
			fact.CreatedAt.Format(time.RFC3339), claimedAt.Format(time.RFC3339))
	}
	return ""
}

// errConnectorLacksMergeFields is the refusal when merge_request_state sends
// no source_branch or no created_at.
const errConnectorLacksMergeFields = "the Git host connector sent no source_branch or no created_at in " +
	"merge_request_state, so the daemon cannot check that the merge request is the work of the job: " +
	"update the connector server to a release that sends both fields"

// refuse records the refusal on each finding that the job holds and ends the
// claims. The next job can then work on the findings.
func (l *jobGraphLink) refuse(c jobnode.ClosedJob, mrKey, claim string, held []string, reason string, now time.Time) {
	if reason == errConnectorLacksMergeFields {
		l.logger.Error("the Git host connector is too old for the fix loop",
			"job_id", c.JobID, "merge_request", mrKey, "reason", reason)
	} else {
		l.logger.Warn("the daemon refused the merge request of a fix job",
			"job_id", c.JobID, "merge_request", mrKey, "reason", reason)
	}
	for _, id := range held {
		l.submit(c.TenantID, brain.FixLinkRefused{
			ID: id, MergeRequest: mrKey, JobID: c.JobID, Reason: reason, MissionID: c.MissionRunID, At: now,
		})
		l.submit(c.TenantID, brain.FixClaimReleased{ID: id, Claim: claim, MissionID: c.MissionRunID, At: now})
	}
}

// fixedByEvents builds the events for a closed job. It returns nothing when
// the job delivered no merge request. Each open finding also becomes `fixing`,
// with the merge request recorded on it (gibson#1505). A finding in any other
// status keeps its status. The function keeps only the inputs that are
// findings in the tenant World and counts the rest as skipped. The projector
// creates a missing edge target, so an input that names a plan and carries the
// Finding label would become a phantom :Finding node. Nothing is guessed.
func fixedByEvents(c jobnode.ClosedJob, findings func(tenant string) map[string]findingRef, now time.Time) (events []brain.Event, skippedInputs int) {
	mrKey, mrURL, mrRef := deliveredMergeRequest(c)
	if mrKey == "" {
		return nil, 0
	}

	known := findings(c.TenantID)
	// prealloc: at most one event per input, plus the merge request itself.
	events = make([]brain.Event, 0, 2*len(c.Inputs)+1)
	var fixing []brain.Event
	seen := make(map[string]bool, len(c.Inputs))
	for _, id := range c.Inputs {
		if seen[id] {
			continue
		}
		seen[id] = true
		ref, ok := known[id]
		if !ok {
			skippedInputs++
			continue
		}
		events = append(events, brain.EntityObserved{
			// Key is the World id, the value the projector merges a Finding on
			// (brain_id). Any other key writes a second node.
			Label: labelFinding, Key: id, ScopeID: ref.scope, MissionID: c.MissionRunID,
			Edges: []brain.EntityEdge{{Type: edgeFixedBy, TargetLabel: labelMergeRequest, TargetKey: mrKey}},
		})
		if ref.status == brain.FindingStatusOpen {
			fixing = append(fixing, brain.FindingStatusChanged{
				ID: id, Status: brain.FindingStatusFixing, MissionID: c.MissionRunID, MergeRequest: mrKey, At: now,
			})
		}
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
	return withCountermeasure(c, mrKey, append(append([]brain.Event{mr}, events...), fixing...)), skippedInputs
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
			// A Finding that another fix job holds is not open work.
			if f.ScopeID == scope && f.Status == brain.FindingStatusOpen && f.FixClaim == "" {
				ids = append(ids, f.ID)
			}
		}
		return ids, nil
	})
}

// fixClaims implements jobnode.FixClaims over the tenant World. The World
// decides: the first claim of a Finding wins, and a replay gives the same
// holder (brain.FixClaimed).
type fixClaims struct {
	engine func(tenant string) *brain.Engine
	now    func() time.Time
}

var _ jobnode.FixClaims = fixClaims{}

func newFixClaims(reg *brain.Registry) fixClaims {
	return fixClaims{
		engine: func(tenant string) *brain.Engine { return reg.For(tenant) },
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// findingInputs returns the inputs that are Findings of the World. An input
// that names a plan or a log is no Finding and takes no claim.
func findingInputs(eng *brain.Engine, inputs []string) []string {
	known := map[string]bool{}
	for _, f := range eng.Findings() {
		known[f.ID] = true
	}
	var out []string
	for _, id := range inputs {
		if known[id] {
			out = append(out, id)
		}
	}
	return out
}

// Claim implements jobnode.FixClaims.
func (c fixClaims) Claim(ctx context.Context, tenantID, claim, missionRunID string, inputs []string) error {
	eng := c.engine(tenantID)
	ids := findingInputs(eng, inputs)
	for _, id := range ids {
		ev := brain.FixClaimed{ID: id, Claim: claim, MissionID: missionRunID, At: c.now()}
		if err := eng.SubmitAndWait(ctx, ev); err != nil {
			c.Release(ctx, tenantID, claim, missionRunID, ids)
			return fmt.Errorf("claim finding %s: %w", id, err)
		}
	}
	var held []string
	eng.ReadWorld(func(w *brain.World) {
		for _, id := range ids {
			if holder := w.FixClaimOf(id); holder != claim {
				held = append(held, id+" (held by "+holder+")")
			}
		}
	})
	if len(held) > 0 {
		c.Release(ctx, tenantID, claim, missionRunID, ids)
		return fmt.Errorf("findings %v: %w", held, jobnode.ErrFindingClaimed)
	}
	return nil
}

// Release implements jobnode.FixClaims. The World ends a claim only for its
// holder, so a release of a claim that another job holds changes nothing.
func (c fixClaims) Release(_ context.Context, tenantID, claim, missionRunID string, inputs []string) {
	eng := c.engine(tenantID)
	for _, id := range findingInputs(eng, inputs) {
		eng.Submit(brain.FixClaimReleased{ID: id, Claim: claim, MissionID: missionRunID, At: c.now()})
	}
}
