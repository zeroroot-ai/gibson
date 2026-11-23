// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
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
	// opened returns the head that open_merge_request returned to the tool gate.
	// The link records the head of a fix only when the host head equals it.
	opened openedHeadReader
	now    func() time.Time
	logger *slog.Logger

	// pending holds the closes whose merge request the daemon could not read
	// on the Git host, keyed by job id (gibson#1581). RetryPending reads them
	// again. The close path never waits for a retry.
	mu      sync.Mutex
	pending map[string]*pendingLink
	// running is true while Run loops. A test reads it.
	running atomic.Bool
	// readTimeout bounds one read of a merge request. Zero means
	// pendingReadTimeout. A test sets it.
	readTimeout time.Duration
}

// read bounds one read of a merge request, so a hung connector of one tenant
// stops neither a close nor the links of the other tenants.
func (l *jobGraphLink) read(ctx context.Context, c jobnode.ClosedJob, mrKey string, held []string, known map[string]findingRef) (string, fixloop.MergeFact, error) {
	d := l.readTimeout
	if d == 0 {
		d = pendingReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return l.vet(readCtx, c, mrKey, held, known)
}

// pendingLink is a close that waits for a good read of the merge request.
type pendingLink struct {
	closed  jobnode.ClosedJob
	mrKey   string
	since   time.Time
	lastErr string
}

const (
	// pendingLinkInterval is how often Run reads the pending merge requests.
	pendingLinkInterval = 30 * time.Second
	// pendingReadTimeout bounds one read of a merge request in RetryPending, so
	// a hung connector of one tenant does not stop the links of the others.
	pendingReadTimeout = 20 * time.Second
	// pendingLinkLimit is how long a link stays pending. A link that no read
	// settles in this time is refused, so a claim does not wait for a Git host
	// that stays down.
	pendingLinkLimit = 30 * time.Minute
)

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

func newJobGraphLink(
	reg *brain.Registry, mrs mergeRequestReader, opened openedHeadReader, logger *slog.Logger,
) *jobGraphLink {
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
		opened:        opened,
		now:           func() time.Time { return time.Now().UTC() },
		logger:        logger,
	}
}

// JobClosed submits the events for one accomplished close. It reads the merge
// request on the Git host one time. When the read fails, the link is pending
// and RetryPending reads it again (gibson#1581). The close path does not wait.
func (l *jobGraphLink) JobClosed(ctx context.Context, c jobnode.ClosedJob) {
	mrKey, _, _ := deliveredMergeRequest(c)
	if mrKey == "" {
		return
	}
	known := l.findings(c.TenantID)
	claim := jobnode.ClaimName(c.MissionRunID, c.NodeID)
	held := heldFindings(c, known, claim)
	if len(held) == 0 {
		// A job that delivered a merge request and holds no finding has lost
		// its claims, or names no finding of the World (review r11).
		l.logger.Warn("a fix job closed with a merge request and holds no finding",
			"job_id", c.JobID, "merge_request", mrKey, "claim", claim)
	}
	now := l.clock()
	var fact fixloop.MergeFact
	if len(held) > 0 {
		reason, f, readErr := l.read(ctx, c, mrKey, held, known)
		fact = f
		if readErr != nil {
			l.markPending(c, mrKey, held, readErr, now)
			return
		}
		if reason != "" {
			l.refuse(c, mrKey, claim, held, reason, now)
			return
		}
	}
	l.link(c, known, held, fact, now)
}

func (l *jobGraphLink) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now().UTC()
}

// link submits the FIXED_BY events for the findings that the job holds.
func (l *jobGraphLink) link(c jobnode.ClosedJob, known map[string]findingRef, held []string, fact fixloop.MergeFact, now time.Time) {
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
	// The head and the files come from the read of the host that passed the
	// checks of the caller, never from the deliverable of the agent
	// (gibson#1579).
	mrKey, _, _ := deliveredMergeRequest(c)
	for _, ev := range l.headEvents(c, mrKey, held, fact, now) {
		l.submit(c.TenantID, ev)
	}
}

// fixFileJSON is the shape of one file in FixHeadRecorded.Files.
type fixFileJSON struct {
	Path         string `json:"path"`
	Change       string `json:"change"`
	PreviousPath string `json:"previous_path,omitempty"`
	BlobSHA      string `json:"blob_sha,omitempty"`
	Mode         string `json:"mode,omitempty"`
}

// maxFixFiles is the largest list that the harness read returns (the SDK allows
// 100 files).
const maxFixFiles = 100

var headSHARe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// headEvents builds the events that record the head commit and the changed files
// of the merge request. It builds none when the host gave no valid head or no
// complete list: the fields stay empty, and the log says why. It also builds none
// when the head of the host is not the commit that the fix job made. The tool
// open_merge_request returned that commit to the tool gate, and the job branch
// can hold another commit at the time of the link.
func (l *jobGraphLink) headEvents(c jobnode.ClosedJob, mrKey string, held []string, fact fixloop.MergeFact, now time.Time) []brain.Event {
	if len(held) == 0 {
		return nil
	}
	switch {
	case !headSHARe.MatchString(fact.HeadSHA):
		l.logger.Warn("the host gave no valid head commit for the merge request of a fix job, so the fix has no head",
			"job_id", c.JobID, "merge_request", mrKey)
		return nil
	case fact.ChangedFilesError != "":
		l.logger.Warn("the host gave no list of the files of the merge request of a fix job",
			"job_id", c.JobID, "merge_request", mrKey, "error", fact.ChangedFilesError)
		return nil
	case fact.ChangedFilesTruncated || len(fact.ChangedFiles) == 0 || len(fact.ChangedFiles) > maxFixFiles:
		l.logger.Warn("the list of the files of the merge request of a fix job is not complete or is over the limit",
			"job_id", c.JobID, "merge_request", mrKey, "files", len(fact.ChangedFiles), "truncated", fact.ChangedFilesTruncated)
		return nil
	}
	if reason := l.headMismatch(c, mrKey, fact.HeadSHA); reason != "" {
		l.logger.Warn("the head of the merge request of a fix job is not the commit that the job made, so the fix has no head",
			"job_id", c.JobID, "merge_request", mrKey, "reason", reason)
		return nil
	}
	files := make([]fixFileJSON, 0, len(fact.ChangedFiles))
	for _, f := range fact.ChangedFiles {
		files = append(files, fixFileJSON{Path: f.Path, Change: f.Change, PreviousPath: f.PreviousPath, BlobSHA: f.BlobSHA, Mode: f.Mode})
	}
	enc, err := json.Marshal(files)
	if err != nil {
		l.logger.Warn("the files of a fix could not be encoded", "job_id", c.JobID, "error", err)
		return nil
	}
	out := make([]brain.Event, 0, len(held))
	for _, id := range held {
		out = append(out, brain.FixHeadRecorded{
			ID: id, MergeRequest: mrKey, HeadSHA: fact.HeadSHA, Files: string(enc), MissionID: c.MissionRunID, At: now,
		})
	}
	return out
}

// headMismatch returns why the head of the host is not the commit that the fix
// job made, or "" when it is. The commit that the job made is the head that
// open_merge_request returned for the merge request of this tenant, on the job
// branch.
func (l *jobGraphLink) headMismatch(c jobnode.ClosedJob, mrKey, hostHead string) string {
	if l.opened == nil {
		return "the daemon keeps no record of the heads that open_merge_request returned"
	}
	made, ok := l.opened.OpenedHead(c.TenantID, mrKey)
	switch {
	case !ok:
		return "the daemon saw no result of open_merge_request for this merge request"
	case made.sourceBranch != jobnode.JobBranch(c.JobID):
		return fmt.Sprintf("open_merge_request opened branch %q, not the job branch %q", made.sourceBranch, jobnode.JobBranch(c.JobID))
	case made.sha != hostHead:
		return fmt.Sprintf("open_merge_request returned head %s, and the host holds head %s", made.sha, hostHead)
	}
	return ""
}

// markPending keeps the close for RetryPending and records the wait on each
// finding that the job holds. The claims stay, so no second job takes the
// findings while the link waits.
func (l *jobGraphLink) markPending(c jobnode.ClosedJob, mrKey string, held []string, readErr error, now time.Time) {
	reason := "the daemon could not read the merge request on the Git host: " + readErr.Error()
	_, url, ref := deliveredMergeRequest(c)
	l.logger.Warn("the read of the merge request of a fix job failed, so the link is pending",
		"job_id", c.JobID, "merge_request", mrKey, "error", readErr)
	l.mu.Lock()
	if l.pending == nil {
		l.pending = map[string]*pendingLink{}
	}
	l.pending[c.JobID] = &pendingLink{closed: c, mrKey: mrKey, since: now, lastErr: readErr.Error()}
	l.mu.Unlock()
	for _, id := range held {
		l.submit(c.TenantID, brain.FixLinkPending{
			ID: id, MergeRequest: mrKey, JobID: c.JobID, Reason: reason, MissionID: c.MissionRunID,
			NodeID: c.NodeID, URL: url, Ref: ref, Countermeasure: c.Countermeasure, At: now,
		})
	}
}

// Run reads the pending merge requests again at each pendingLinkInterval, until
// ctx ends.
func (l *jobGraphLink) Run(ctx context.Context) {
	l.running.Store(true)
	defer l.running.Store(false)
	t := time.NewTicker(pendingLinkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.RetryPending(ctx)
		}
	}
}

// RetryPending reads the merge request of each pending link once. A good read
// links the fix or refuses it, as a close does. A failed read keeps the link
// pending until pendingLinkLimit, and then refuses it.
func (l *jobGraphLink) RetryPending(ctx context.Context) {
	l.mu.Lock()
	list := make([]*pendingLink, 0, len(l.pending))
	for _, p := range l.pending {
		list = append(list, p)
	}
	l.mu.Unlock()

	for _, p := range list {
		c := p.closed
		now := l.clock()
		known := l.findings(c.TenantID)
		claim := jobnode.ClaimName(c.MissionRunID, c.NodeID)
		held := heldFindings(c, known, claim)
		if len(held) == 0 {
			// The claims ended, so no finding waits for this link.
			l.dropPending(c.JobID)
			continue
		}
		reason, fact, readErr := l.read(ctx, c, p.mrKey, held, known)
		switch {
		case readErr != nil && now.Sub(p.since) < pendingLinkLimit:
			l.logger.Warn("the read of the merge request of a pending fix link failed again",
				"job_id", c.JobID, "merge_request", p.mrKey, "error", readErr)
			continue
		case readErr != nil:
			l.refuse(c, p.mrKey, claim, held, fmt.Sprintf(
				"the daemon could not read the merge request on the Git host for %s: %s", pendingLinkLimit, readErr), now)
		case reason != "":
			l.refuse(c, p.mrKey, claim, held, reason, now)
		default:
			l.link(c, known, held, fact, now)
		}
		l.dropPending(c.JobID)
	}
}

func (l *jobGraphLink) dropPending(jobID string) {
	l.mu.Lock()
	delete(l.pending, jobID)
	l.mu.Unlock()
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

// vet reads the merge request on the Git host one time. It returns why the
// link is refused, or "" when the merge request is the work of this job. A
// failed read is the error, and no verdict: the link is then pending.
func (l *jobGraphLink) vet(
	ctx context.Context, c jobnode.ClosedJob, mrKey string, held []string, known map[string]findingRef,
) (reason string, fact fixloop.MergeFact, readErr error) {
	if l.mergeRequests == nil {
		return "the daemon has no reader of the Git host, so it cannot check the merge request", fixloop.MergeFact{}, nil
	}
	fact, err := l.mergeRequests.MergeRequest(ctx, c.TenantID, c.MissionRunID, mrKey)
	if err != nil {
		return "", fixloop.MergeFact{}, fmt.Errorf("read merge request %s: %w", mrKey, err)
	}
	var claimedAt time.Time
	for _, id := range held {
		if t := known[id].claimedAt; t.After(claimedAt) {
			claimedAt = t
		}
	}
	return mergeRequestRefusal(fact, jobnode.JobBranch(c.JobID), claimedAt), fact, nil
}

// mergeRequestRefusal returns why a merge request is not the work of a fix job,
// or "" when it is. The job branch and the time of the claim come from the
// daemon. The fact comes from the Git host. Nothing comes from the agent.
func mergeRequestRefusal(fact fixloop.MergeFact, branch string, claimedAt time.Time) string {
	switch {
	case fact.State != fixloop.MROpen:
		return fmt.Sprintf("the merge request is %q on the Git host, not open", fact.State)
	case fact.SourceBranch == "" && fact.SourceBranchReason != "":
		// The host knows the merge request and says why it gives no branch,
		// for example a branch in a fork. That is no work of the job.
		return "the Git host gave no source branch for the merge request: " + fact.SourceBranchReason
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

// Adopt rebuilds the pending links of a tenant after the engine hydrated its
// World. A link that waited for the Git host when the daemon stopped has a
// FixLinkWait on each finding that the job holds, and the claim of the job
// stayed (gibson#1581). The daemon reads the merge request again, so a restart
// does not orphan it.
func (l *jobGraphLink) Adopt(tenant string, findings []brain.FindingSnapshot) {
	jobs := map[string]*pendingLink{}
	for _, f := range findings {
		w := f.FixLinkWait
		if w.JobID == "" || f.Status != brain.FindingStatusOpen || f.FixClaim == "" {
			continue
		}
		p, ok := jobs[w.JobID]
		if !ok {
			p = &pendingLink{mrKey: w.MergeRequest, since: w.Since, lastErr: "the daemon restarted while the link was pending",
				closed: jobnode.ClosedJob{
					TenantID: tenant, MissionRunID: w.MissionRunID, NodeID: w.NodeID, JobID: w.JobID,
					Deliverables:   []job.Deliverable{{Kind: mergeRequestDeliverable, URL: w.URL, Ref: w.Ref}},
					Countermeasure: w.Countermeasure,
				}}
			jobs[w.JobID] = p
		}
		p.closed.Inputs = append(p.closed.Inputs, f.ID)
	}
	if len(jobs) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil {
		l.pending = map[string]*pendingLink{}
	}
	for id, p := range jobs {
		l.pending[id] = p
		l.logger.Info("a pending fix link was rebuilt after the start of the daemon",
			"tenant", tenant, "job_id", id, "merge_request", p.mrKey)
	}
}

// wireFixLink builds the link of closed fix jobs, rebuilds the pending links of
// each tenant when its engine starts, and starts the loop that reads them again.
func (d *daemonImpl) wireJobClosed(ctx context.Context, mrs mergeRequestReader, logger *slog.Logger) {
	d.brainExecutor.jobClosed = wireFixLink(ctx, d.brainRegistry, mrs, d.openedHeadStore(), logger)
}

// wireFixLink is the link that wireJobClosed installs.
func wireFixLink(
	ctx context.Context, reg *brain.Registry, mrs mergeRequestReader, opened openedHeadReader, logger *slog.Logger,
) *jobGraphLink {
	link := newJobGraphLink(reg, mrs, opened, logger)
	reg.OnEngine(func(e *brain.Engine) { link.Adopt(e.World.Tenant, e.Findings()) })
	go link.Run(ctx)
	return link
}
