// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// Watcher reads the facts of the fix loop for the findings of one tenant and
// returns the events to submit. It holds no World. One Watcher serves all
// tenants, and each call names its tenant.
type Watcher struct {
	reader   Reader
	reverter Reverter
	placer   Placer
	policy   PolicySource
	hold     HoldSource
	now      func() time.Time
	logger   *slog.Logger

	mu sync.Mutex
	// refused is the last refusal that the Watcher reported for each merge
	// request, so that one refusal is one Timeline event.
	refused map[string]string
	// released is the time when the Watcher freed the unused slot of a merge
	// request. The Watcher queues the merge request again only after the
	// RequeueBackoff of the policy, so a merge request that no agent merges does
	// not churn the queue (gibson#1609).
	released map[string]time.Time
}

// NewWatcher builds a Watcher. The reader, the reverter and the placer are
// required. A nil policy source means DefaultPolicy.
func NewWatcher(r Reader, rv Reverter, p Placer, policy PolicySource, logger *slog.Logger) (*Watcher, error) {
	if r == nil || rv == nil || p == nil {
		return nil, errors.New("fixloop: a watcher needs a reader, a reverter and a placer")
	}
	if policy == nil {
		policy = func(string) Policy { return DefaultPolicy() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{
		reader: r, reverter: rv, placer: p, policy: policy,
		now: func() time.Time { return time.Now().UTC() }, logger: logger,
		refused: map[string]string{}, released: map[string]time.Time{},
	}, nil
}

// WithHoldSource sets the source of the hold time of the health signal. The
// Watcher asks it one time for each deploy, for the fix mission of the merge
// request, and the deploy event keeps the answer. A mission that
// states no hold time gets the hold time of the policy. Without a source, each
// merge request gets the hold time of the policy.
func (w *Watcher) WithHoldSource(h HoldSource) *Watcher {
	w.hold = h
	return w
}

// Step reads the facts for each finding that has a merge request and returns
// the events to submit, in a stable order. A read that fails is logged and
// skipped, and the next Step tries it again. An error never moves a finding.
func (w *Watcher) Step(ctx context.Context, tenant string, findings []brain.FindingSnapshot, slots []brain.MergeSlot) []brain.Event {
	byMR := map[string][]brain.FindingSnapshot{}
	for _, f := range findings {
		if f.MergeRequest != "" {
			byMR[f.MergeRequest] = append(byMR[f.MergeRequest], f)
		}
	}
	keys := make([]string, 0, len(byMR))
	for k := range byMR {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	slotOf := map[string]brain.MergeSlot{}
	for _, s := range slots {
		slotOf[s.MergeRequest] = s
	}
	var out []brain.Event
	for _, mr := range keys {
		fs := byMR[mr]
		var evs []brain.Event
		var err error
		switch {
		case anyStatus(fs, brain.FindingStatusFixing):
			slot, hasSlot := slotOf[mr]
			evs, err = w.stepFixing(ctx, tenant, mr, fs, slot, hasSlot)
			if err != nil && hasSlot {
				// The daemon cannot read the merge request, so it cannot know if it
				// merged. The slot stays, and the wait is visible (gibson#1609).
				evs = w.beginWait(slot, mr, fs, brain.WaitMergeUnreadable,
					"the daemon cannot read the merge request on the Git host")
			}
		case anyStatus(fs, brain.FindingStatusFixed):
			slot, hasSlot := slotOf[mr]
			evs, err = w.stepFixed(ctx, tenant, mr, fs, slot, hasSlot)
		}
		if err != nil {
			w.logger.Warn("fix loop read failed", "tenant", tenant, "merge_request", mr, "error", err)
		}
		out = append(out, evs...)
	}
	return out
}

// fixMission returns the mission of the fix job of the merge request. Each
// event of the fix loop carries it, so a replay of that mission shows the
// whole loop (gibson#1465).
func fixMission(fs []brain.FindingSnapshot) string {
	for _, f := range fs {
		if f.FixMissionID != "" {
			return f.FixMissionID
		}
	}
	return ""
}

func anyStatus(fs []brain.FindingSnapshot, status string) bool {
	for _, f := range fs {
		if f.Status == status {
			return true
		}
	}
	return false
}

func (w *Watcher) stampOr(t time.Time) time.Time {
	if t.IsZero() {
		return w.now()
	}
	return t.UTC()
}

// stepFixing reads the merge request of a `fixing` finding.
func (w *Watcher) stepFixing(
	ctx context.Context, tenant, mr string, fs []brain.FindingSnapshot, slot brain.MergeSlot, hasSlot bool,
) ([]brain.Event, error) {
	fact, err := w.reader.MergeRequest(ctx, tenant, fixMission(fs), mr)
	if err != nil {
		return nil, fmt.Errorf("read merge request: %w", err)
	}
	// A read that worked ends the wait of an unreadable merge request.
	ended := w.endWait(slot, hasSlot, mr, fs, brain.WaitMergeUnreadable)
	switch fact.State {
	case MRMerged, MRClosed:
		w.forgetRefusal(mr)
		return append(ended, brain.MergeRequestObserved{
			Key: mr, State: fact.State, At: w.stampOr(fact.At), MissionID: fixMission(fs),
		}), nil
	case MRRefused:
		// The host refused the merge and the merge request is still open, for
		// example by a branch protection rule. The slot stays: a person can merge
		// the merge request by hand, and no second fix of the Application may ship
		// before the health verdict of this one. The fix waits on a person, and the
		// refusal and its reason are the record of that wait. The slot leaves only
		// when the host shows the merge request merged or closed (gibson#1609).
		out := ended
		if w.noteRefusal(mr, fact.Reason) || !refusalOpen(fs) {
			out = append(out, brain.MergeRequestObserved{
				Key: mr, State: brain.MergeRequestRefused, Reason: fact.Reason, At: w.stampOr(fact.At), MissionID: fixMission(fs),
			})
		}
		return out, nil
	}
	// The merge request is open and the host does not refuse it. A refusal that
	// an earlier read recorded ends now.
	if refusalOpen(fs) {
		w.forgetRefusal(mr)
		ended = append(ended, brain.MergeRequestObserved{
			Key: mr, State: brain.MergeRequestOpen, At: w.stampOr(fact.At), MissionID: fixMission(fs),
		})
	}
	if hasSlot {
		// No merge used the granted slot within the window, and the host shows the
		// merge request still open. The slot leaves the queue, and the next fix of
		// the Application gets its turn. The host is read first: a merge request
		// that merged is seen above and keeps its slot until its health signal
		// answers (gibson#1609).
		// A merge call that the gate allowed within the call bound may still be on
		// its way to the host. The Watcher frees nothing then, and the next pass
		// reads the host again after the bound.
		if slot.Granted && !slot.GrantedAt.IsZero() && w.now().Sub(slot.GrantedAt) >= w.policy(tenant).grantWindow() &&
			!w.callInFlight(tenant, slot) {
			w.noteRelease(mr)
			return append(ended, brain.MergeSlotExpired{
				MergeRequest: mr, Application: slot.Application, At: w.now(), MissionID: fixMission(fs),
				CallBound: w.policy(tenant).callBound(),
				Reason:    "no merge used the granted slot within the grant window and the merge request is still open",
			}), nil
		}
		return ended, nil
	}
	// A green pipeline asks for the slot of its Application. The queue grants
	// one slot at a time. A slot that the Watcher freed is not asked for again
	// until the backoff has passed.
	if !fact.PipelineGreen || w.inBackoff(tenant, mr) {
		return ended, nil
	}
	if noFixHead(fs) {
		// The link recorded no head for this fix and said why. The fix agent makes no
		// merge call without a head, so a slot would only block the Application for
		// the grant window at each cycle. The finding waits on a person instead.
		w.logger.Warn("fix loop: the fix has no head, so the merge request gets no merge slot",
			"tenant", tenant, "merge_request", mr)
		return ended, nil
	}
	mission := fixMission(fs)
	if mission == "" {
		// A slot binds a mission, and no call of an empty mission merges. A
		// slot with none would only hold the Application.
		w.logger.Warn("fix loop: the merge request names no fix mission, so it gets no merge slot",
			"tenant", tenant, "merge_request", mr)
		return nil, nil
	}
	app, err := w.placer.Application(ctx, tenant, fs[0].ID)
	if err != nil {
		return nil, fmt.Errorf("place finding: %w", err)
	}
	if app == "" {
		return nil, nil
	}
	return []brain.Event{brain.MergeRequestQueued{
		MergeRequest: mr, Application: app, At: w.now(), MissionID: mission,
	}}, nil
}

// noFixHead reports whether a finding of the merge request has no fix head and the
// link recorded the reason (brain.FixHeadMissing).
func noFixHead(fs []brain.FindingSnapshot) bool {
	for _, f := range fs {
		if f.FixHeadSHA == "" && f.FixHeadMissingReason != "" {
			return true
		}
	}
	return false
}

func (w *Watcher) noteRelease(mr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.released[mr] = w.now()
}

// inBackoff reports whether the Watcher freed the slot of the merge request
// less than the RequeueBackoff of the policy ago. A merge request past its backoff is forgotten.
func (w *Watcher) inBackoff(tenant, mr string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	at, ok := w.released[mr]
	if !ok {
		return false
	}
	if w.now().Sub(at) < w.policy(tenant).requeueBackoff() {
		return true
	}
	delete(w.released, mr)
	return false
}

func (w *Watcher) noteRefusal(mr, reason string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if last, ok := w.refused[mr]; ok && last == reason {
		return false
	}
	w.refused[mr] = reason
	return true
}

func (w *Watcher) forgetRefusal(mr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.refused, mr)
}

// callInFlight reports whether the gate allowed a merge call for the slot within
// the call bound of the policy.
func (w *Watcher) callInFlight(tenant string, slot brain.MergeSlot) bool {
	return !slot.LastAllowedAt.IsZero() && w.now().Sub(slot.LastAllowedAt) < w.policy(tenant).callBound()
}

// refusalOpen reports whether the World holds a refusal of the merge request that
// no later report ended.
func refusalOpen(fs []brain.FindingSnapshot) bool {
	for _, f := range fs {
		if f.MergeRequestState == brain.MergeRequestRefused {
			return true
		}
	}
	return false
}

// beginWait records that the fix waits on a person, once for each wait. The open
// waits are on the slot, which the World folds from the Timeline, so a restart of
// the daemon neither repeats a wait nor loses one. A merge request with no slot
// has no wait: the slot is what the wait explains.
func (w *Watcher) beginWait(slot brain.MergeSlot, mr string, fs []brain.FindingSnapshot, kind, reason string) []brain.Event {
	if slot.MergeRequest == "" {
		return nil
	}
	if _, open := slot.Waits[kind]; open {
		return nil
	}
	return []brain.Event{brain.FixWaiting{
		MergeRequest: mr, WaitKind: kind, Reason: reason, Waiting: true, At: w.now(), MissionID: fixMission(fs),
	}}
}

// endWait records that a wait ended. It returns nothing for a wait that the slot
// does not hold.
func (w *Watcher) endWait(slot brain.MergeSlot, hasSlot bool, mr string, fs []brain.FindingSnapshot, kind string) []brain.Event {
	if !hasSlot {
		return nil
	}
	if _, open := slot.Waits[kind]; !open {
		return nil
	}
	return []brain.Event{brain.FixWaiting{MergeRequest: mr, WaitKind: kind, Waiting: false, At: w.now(), MissionID: fixMission(fs)}}
}

// stepFixed reads the deploy, then the health signal, of a merged fix. It
// reverts the merge when the health signal failed. A merged fix that has no
// health verdict after the grant window waits on a person, with no clock to free
// the slot: the hold time of the health signal is gibson#1463 (gibson#1609).
func (w *Watcher) stepFixed(
	ctx context.Context, tenant, mr string, fs []brain.FindingSnapshot, slot brain.MergeSlot, hasSlot bool,
) ([]brain.Event, error) {
	f := firstWithStatus(fs, brain.FindingStatusFixed)
	var wait []brain.Event
	switch {
	case f.Health != "":
		wait = w.endWait(slot, hasSlot, mr, fs, brain.WaitNoHealthVerdict)
	case hasSlot && slot.Granted && !slot.GrantedAt.IsZero() && w.now().Sub(slot.GrantedAt) >= w.policy(tenant).grantWindow():
		wait = w.beginWait(slot, mr, fs, brain.WaitNoHealthVerdict, "no health verdict")
	}
	// The hold wait ends with the health verdict.
	if f.Health != "" {
		wait = append(wait, w.endWait(slot, hasSlot, mr, fs, brain.WaitHoldUnreadable)...)
	}
	evs, err := w.stepFixedFacts(ctx, tenant, mr, f)
	for _, e := range evs {
		if d, ok := e.(brain.DeployObserved); ok && d.HoldUnreadable && hasSlot {
			wait = append(wait, w.beginWait(slot, mr, fs, brain.WaitHoldUnreadable,
				"the hold of the fix mission cannot be read")...)
		}
	}
	if f.Health == brain.HealthFailed && hasSlot {
		wait = append(wait, w.revertWaits(slot, mr, fs, evs, err)...)
	}
	return append(wait, evs...), err
}

// revertWaits makes the wait of a failed health signal visible. The slot stays
// until the revert merges (review M2), so the list of items that wait on a person
// must say why the Application is blocked: the revert merge request is not merged
// yet, or the revert call failed.
func (w *Watcher) revertWaits(slot brain.MergeSlot, mr string, fs []brain.FindingSnapshot, evs []brain.Event, err error) []brain.Event {
	for _, e := range evs {
		if _, reverted := e.(brain.FixReverted); reverted {
			return nil // the revert merged, and the slot leaves with it
		}
	}
	if err != nil {
		out := w.beginWait(slot, mr, fs, brain.WaitRevertFailed, "the revert call failed")
		return append(out, w.endWait(slot, true, mr, fs, brain.WaitRevertPending)...)
	}
	out := w.beginWait(slot, mr, fs, brain.WaitRevertPending, "revert pending: the revert merge request is not merged yet")
	return append(out, w.endWait(slot, true, mr, fs, brain.WaitRevertFailed)...)
}

func (w *Watcher) stepFixedFacts(ctx context.Context, tenant, mr string, f brain.FindingSnapshot) ([]brain.Event, error) {
	switch {
	case f.DeployedAt.IsZero():
		d, err := w.reader.Deploy(ctx, tenant, f.FixMissionID, mr)
		if err != nil {
			return nil, fmt.Errorf("read deploy: %w", err)
		}
		if !d.Deployed || d.At.IsZero() {
			return nil, nil // merged and not deployed yet
		}
		hold, err := w.holdAtDeploy(ctx, tenant, f.FixMissionID)
		if err != nil {
			return nil, err // the deploy is not recorded now, and the next step reads again
		}
		return deployEvents(mr, d, f.FixMissionID, hold), nil
	case f.Health == brain.HealthFailed:
		return w.revert(ctx, tenant, mr, f)
	case f.Health == "":
		return w.readHealth(ctx, tenant, mr, f)
	}
	return nil, nil
}

// The labels and the edge of the deploy link (gibson#1460).
const (
	labelMergeRequest = "MergeRequest"
	labelDeployment   = "Deployment"
	edgeDeployedIn    = "DEPLOYED_IN"
)

// holdRead is the hold time that the Watcher read from the fix mission at the
// deploy. unreadable is true when the record of the mission is gone.
type holdRead struct {
	hold       time.Duration
	unreadable bool
}

// holdAtDeploy reads the hold time of the fix mission one time, when the Watcher
// records the deploy. A mission that states none gives zero, and the default hold
// time applies. A record that is gone gives MaxHold and the mark unreadable, and the
// finding waits visibly with its own reason. Any other error is returned, so the
// Watcher records no deploy in this pass and reads again at the next step.
func (w *Watcher) holdAtDeploy(ctx context.Context, tenant, missionID string) (holdRead, error) {
	if w.hold == nil {
		return holdRead{}, nil
	}
	hold, err := w.hold(ctx, tenant, missionID)
	switch {
	case errors.Is(err, ErrHoldNotFound):
		w.logger.Warn("fix loop: the fix mission record is gone, so the hold is the upper bound",
			"tenant", tenant, "mission_id", missionID, "hold", MaxHold)
		return holdRead{hold: MaxHold, unreadable: true}, nil
	case err != nil:
		return holdRead{}, fmt.Errorf("read hold time: %w", err)
	}
	return holdRead{hold: min(max(hold, 0), MaxHold)}, nil
}

// deployEvents records the deploy of a merged fix. The Timeline event holds
// the time of the deploy. The graph gets the edge from the merge request to
// the Deployment that carries it. A deploy with no deployment key has no node
// to point at, so it gets the event and no edge.
func deployEvents(mr string, d DeployFact, missionID string, hold holdRead) []brain.Event {
	out := make([]brain.Event, 0, 3)
	out = append(out, brain.DeployObserved{
		MergeRequest: mr, DeploymentKey: d.DeploymentKey, ApplicationKey: d.ApplicationKey, At: d.At.UTC(),
		MissionID: missionID, HoldSeconds: int64(hold.hold / time.Second), HoldUnreadable: hold.unreadable,
	})
	if d.DeploymentKey == "" {
		return out
	}
	props := map[string]string{"deployed_at": d.At.UTC().Format(time.RFC3339)}
	if d.ApplicationKey != "" {
		props["application"] = d.ApplicationKey
	}
	return append(out,
		brain.EntityObserved{Label: labelDeployment, Key: d.DeploymentKey, MissionID: missionID, Props: props},
		brain.EntityObserved{
			Label: labelMergeRequest, Key: mr, MissionID: missionID,
			Edges: []brain.EntityEdge{{Type: edgeDeployedIn, TargetLabel: labelDeployment, TargetKey: d.DeploymentKey}},
		},
	)
}

// revert calls the revert tool. The Git host merges the revert only on a green
// pipeline, so one call can leave it open. FixReverted comes only when the
// host says that the revert is merged. Before that, the first call records
// RevertRequested, and the wait for the pipeline is wait time.
func (w *Watcher) revert(ctx context.Context, tenant, mr string, f brain.FindingSnapshot) ([]brain.Event, error) {
	fact, err := w.reverter.Revert(ctx, tenant, mr, f.FixMissionID)
	if err != nil {
		return nil, fmt.Errorf("revert merge request: %w", err)
	}
	if fact.Merged {
		return []brain.Event{brain.FixReverted{MergeRequest: mr, At: w.now(), MissionID: f.FixMissionID}}, nil
	}
	if !f.RevertRequestedAt.IsZero() && (f.RevertMergeRequest != "" || fact.RevertMergeRequest == "") {
		return nil, nil // the revert waits for its pipeline, and nothing is new
	}
	return []brain.Event{brain.RevertRequested{
		MergeRequest: mr, RevertMergeRequest: fact.RevertMergeRequest, At: w.now(), MissionID: f.FixMissionID,
	}}, nil
}

func firstWithStatus(fs []brain.FindingSnapshot, status string) brain.FindingSnapshot {
	for _, f := range fs {
		if f.Status == status {
			return f
		}
	}
	return brain.FindingSnapshot{}
}

// readHealth decides the health event. The hold time starts at the deploy, or
// at the end of the restart that the deploy needed. A restart that runs longer
// than the limit is a failure.
func (w *Watcher) readHealth(ctx context.Context, tenant, mr string, f brain.FindingSnapshot) ([]brain.Event, error) {
	pol := w.policy(tenant)
	// The hold time was read once, at the deploy, and the deploy event holds it.
	// A later read never needs the record of the fix mission.
	if f.HealthHold > 0 {
		pol.HoldTime = f.HealthHold
	}
	d, err := w.reader.Deploy(ctx, tenant, f.FixMissionID, mr)
	if err != nil {
		return nil, fmt.Errorf("read deploy: %w", err)
	}
	since := f.DeployedAt
	if d.Restart.Needed {
		end := d.Restart.Ended
		if end.IsZero() {
			end = w.now()
		}
		if pol.RestartLimit > 0 && end.Sub(d.Restart.Started) > pol.RestartLimit {
			return []brain.Event{brain.HealthObserved{
				MergeRequest: mr, Held: false, At: w.now(), MissionID: f.FixMissionID,
			}}, nil
		}
		if d.Restart.Ended.IsZero() {
			return nil, nil // the restart still runs
		}
		since = d.Restart.Ended
	}
	app := d.ApplicationKey
	if app == "" {
		if app, err = w.placer.Application(ctx, tenant, f.ID); err != nil {
			return nil, fmt.Errorf("place finding: %w", err)
		}
	}
	if app == "" {
		return w.unavailable(mr, f), nil // no place, so no health signal to read
	}
	h, err := w.reader.Health(ctx, tenant, f.FixMissionID, app, since, pol.HoldTime)
	if err != nil {
		return nil, fmt.Errorf("read health: %w", err)
	}
	if !h.Known {
		return w.unavailable(mr, f), nil // no signal keeps the finding `fixed`
	}
	if !h.Done {
		return nil, nil // the hold time still runs
	}
	// A held signal must cover the whole hold time. The daemon checks the
	// time of the answer and does not take the done flag of the connector on
	// trust (review m3). A failure ends the hold early, so it needs no check.
	if h.Held && (h.At.IsZero() || h.At.Before(since.Add(pol.HoldTime))) {
		return nil, nil
	}
	return []brain.Event{brain.HealthObserved{
		MergeRequest: mr, Held: h.Held, At: w.stampOr(h.At), MissionID: f.FixMissionID,
	}}, nil
}

// unavailable returns the one event that records a missing health signal. The
// finding keeps the time of the first report.
func (w *Watcher) unavailable(mr string, f brain.FindingSnapshot) []brain.Event {
	if !f.HealthUnavailableAt.IsZero() {
		return nil
	}
	return []brain.Event{brain.HealthUnavailable{MergeRequest: mr, At: w.now(), MissionID: f.FixMissionID}}
}
