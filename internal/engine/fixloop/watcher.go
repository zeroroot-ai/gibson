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

// NewWatcher builds a Watcher. A nil policy source means DefaultPolicy.
func NewWatcher(r Reader, rv Reverter, p Placer, policy PolicySource, logger *slog.Logger) *Watcher {
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
	}
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
	fact, err := w.reader.MergeRequest(ctx, tenant, mr)
	if err != nil {
		return nil, fmt.Errorf("read merge request: %w", err)
	}
	switch fact.State {
	case MRMerged, MRClosed:
		w.forgetRefusal(mr)
		return []brain.Event{brain.MergeRequestObserved{Key: mr, State: fact.State, At: w.stampOr(fact.At)}}, nil
	case MRRefused:
		if !w.noteRefusal(mr, fact.Reason) {
			return nil, nil
		}
		return []brain.Event{brain.MergeRequestObserved{Key: mr, State: brain.MergeRequestRefused, At: w.stampOr(fact.At)}}, nil
	}
	// The merge request is open. A green pipeline asks for the slot of its
	// Application. The queue grants one slot at a time.
	if hasSlot || !fact.PipelineGreen || w.placer == nil {
		return nil, nil
	}
	app, err := w.placer.Application(ctx, tenant, fs[0].ID)
	if err != nil {
		return nil, fmt.Errorf("place finding: %w", err)
	}
	if app == "" {
		return nil, nil
	}
	return []brain.Event{brain.MergeRequestQueued{MergeRequest: mr, Application: app, At: w.now()}}, nil
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
		d, err := w.reader.Deploy(ctx, tenant, mr)
		if err != nil {
			return nil, fmt.Errorf("read deploy: %w", err)
		}
		if !d.Deployed || d.At.IsZero() {
			return nil, nil // merged and not deployed yet
		}
		return []brain.Event{brain.DeployObserved{
			MergeRequest: mr, DeploymentKey: d.DeploymentKey, ApplicationKey: d.ApplicationKey, At: d.At.UTC(),
		}}, nil
	case f.Health == brain.HealthFailed:
		if w.reverter == nil {
			return nil, errors.New("no reverter is wired")
		}
		if err := w.reverter.Revert(ctx, tenant, mr); err != nil {
			return nil, fmt.Errorf("revert merge request: %w", err)
		}
		return []brain.Event{brain.FixReverted{MergeRequest: mr, At: w.now()}}, nil
	case f.Health == "":
		return w.readHealth(ctx, tenant, mr, f)
	}
	return nil, nil
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
	d, err := w.reader.Deploy(ctx, tenant, mr)
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
			return []brain.Event{brain.HealthObserved{MergeRequest: mr, Held: false, At: w.now()}}, nil
		}
		if d.Restart.Ended.IsZero() {
			return nil, nil // the restart still runs
		}
		since = d.Restart.Ended
	}
	app := d.ApplicationKey
	if app == "" && w.placer != nil {
		if app, err = w.placer.Application(ctx, tenant, f.ID); err != nil {
			return nil, fmt.Errorf("place finding: %w", err)
		}
	}
	if app == "" {
		return nil, nil // no place, so no health signal to read
	}
	h, err := w.reader.Health(ctx, tenant, app, since, pol.HoldTime)
	if err != nil {
		return nil, fmt.Errorf("read health: %w", err)
	}
	if !h.Known || !h.Done {
		return nil, nil // no signal keeps the finding `fixed`. A running hold waits.
	}
	return []brain.Event{brain.HealthObserved{MergeRequest: mr, Held: h.Held, At: w.stampOr(h.At)}}, nil
}
