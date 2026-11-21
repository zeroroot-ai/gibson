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
	now      func() time.Time
	logger   *slog.Logger

	mu sync.Mutex
	// refused is the last refusal that the Watcher reported for each merge
	// request, so that one refusal is one Timeline event.
	refused map[string]string
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
		refused: map[string]string{},
	}, nil
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

	slotOf := map[string]bool{}
	for _, s := range slots {
		slotOf[s.MergeRequest] = true
	}
	var out []brain.Event
	for _, mr := range keys {
		fs := byMR[mr]
		var evs []brain.Event
		var err error
		switch {
		case anyStatus(fs, brain.FindingStatusFixing):
			evs, err = w.stepFixing(ctx, tenant, mr, fs, slotOf[mr])
		case anyStatus(fs, brain.FindingStatusFixed):
			evs, err = w.stepFixed(ctx, tenant, mr, fs)
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
func (w *Watcher) stepFixing(ctx context.Context, tenant, mr string, fs []brain.FindingSnapshot, hasSlot bool) ([]brain.Event, error) {
	fact, err := w.reader.MergeRequest(ctx, tenant, fixMission(fs), mr)
	if err != nil {
		return nil, fmt.Errorf("read merge request: %w", err)
	}
	switch fact.State {
	case MRMerged, MRClosed:
		w.forgetRefusal(mr)
		return []brain.Event{brain.MergeRequestObserved{Key: mr, State: fact.State, At: w.stampOr(fact.At), MissionID: fixMission(fs)}}, nil
	case MRRefused:
		if !w.noteRefusal(mr, fact.Reason) {
			return nil, nil
		}
		return []brain.Event{brain.MergeRequestObserved{
			Key: mr, State: brain.MergeRequestRefused, At: w.stampOr(fact.At), MissionID: fixMission(fs),
		}}, nil
	}
	// The merge request is open. A green pipeline asks for the slot of its
	// Application. The queue grants one slot at a time.
	if hasSlot || !fact.PipelineGreen {
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
		MergeRequest: mr, Application: app, At: w.now(), MissionID: fixMission(fs),
	}}, nil
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

// stepFixed reads the deploy, then the health signal, of a merged fix. It
// reverts the merge when the health signal failed.
func (w *Watcher) stepFixed(ctx context.Context, tenant, mr string, fs []brain.FindingSnapshot) ([]brain.Event, error) {
	f := firstWithStatus(fs, brain.FindingStatusFixed)
	switch {
	case f.DeployedAt.IsZero():
		d, err := w.reader.Deploy(ctx, tenant, f.FixMissionID, mr)
		if err != nil {
			return nil, fmt.Errorf("read deploy: %w", err)
		}
		if !d.Deployed || d.At.IsZero() {
			return nil, nil // merged and not deployed yet
		}
		return deployEvents(mr, d, f.FixMissionID), nil
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

// deployEvents records the deploy of a merged fix. The Timeline event holds
// the time of the deploy. The graph gets the edge from the merge request to
// the Deployment that carries it. A deploy with no deployment key has no node
// to point at, so it gets the event and no edge.
func deployEvents(mr string, d DeployFact, missionID string) []brain.Event {
	out := make([]brain.Event, 0, 3)
	out = append(out, brain.DeployObserved{
		MergeRequest: mr, DeploymentKey: d.DeploymentKey, ApplicationKey: d.ApplicationKey, At: d.At.UTC(),
		MissionID: missionID,
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
