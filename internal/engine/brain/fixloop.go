// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"time"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// fixloop.go holds the events and the System that carry a Finding from `fixed`
// to `verified` or back to `open` (gibson#1460, #1464, #1465, #1463).
//
// A Finding is `verified` when two proofs exist (ADR-0178, ADR-0179):
//
//  1. The check that raised it ran again on evidence newer than the deploy and
//     no longer found the flaw. A stronger check can verify and a weaker check
//     cannot.
//  2. The health signal of the deploy held.
//
// A check that finds the flaw again, on evidence newer than the deploy, sets the
// Finding to `open`. Each fact below is an event that carries its own time.
// VerificationSystem turns the facts into one FindingStatusChanged, so each
// change is a Timeline event and a replay gives the same statuses.
//
// The producers of these events are outside this package. The Git host and the
// observability tool of the buyer reach Gibson through a Connector, and an agent
// reports what it read.

// DeployObserved records that the merge request was deployed. A merge request
// that is merged and not deployed has no DeployObserved event.
type DeployObserved struct {
	MergeRequest  string
	DeploymentKey string
	// ApplicationKey is the Application that the Deployment belongs to.
	ApplicationKey string
	At             time.Time
	MissionID      string
}

// Kind identifies the deploy.observed brain event.
func (DeployObserved) Kind() string { return "deploy.observed" }

// applyDeployObserved records the deploy on each Finding that the merge request
// carries. A new deploy forgets the health signal of the one before.
func applyDeployObserved(w *World, e DeployObserved) {
	if e.MergeRequest == "" || e.At.IsZero() {
		return
	}
	forEachFindingOfMR(w, e.MergeRequest, func(f *Finding) {
		f.DeployedAt = e.At
		f.DeploymentKey = e.DeploymentKey
		f.Health = ""
		f.HealthUnavailableAt = time.Time{}
	})
}

// HealthObserved records what the health signal of the service said after the
// deploy of the merge request. Held is true when the signal held.
type HealthObserved struct {
	MergeRequest string
	Held         bool
	At           time.Time
	MissionID    string
}

// Kind identifies the health.observed brain event.
func (HealthObserved) Kind() string { return "health.observed" }

// applyHealthObserved records the answer on each Finding of the merge request.
func applyHealthObserved(w *World, e HealthObserved) {
	if e.MergeRequest == "" {
		return
	}
	health := HealthFailed
	if e.Held {
		health = HealthHeld
	}
	forEachFindingOfMR(w, e.MergeRequest, func(f *Finding) {
		f.Health = health
		f.HealthUnavailableAt = time.Time{}
	})
	releaseMergeSlot(w, e.MergeRequest)
}

// HealthUnavailable records that the service of the merge request has no health
// signal to read. A fix of such a service stays `fixed`, because `verified`
// needs a held signal. The fix waits on a person, who must add the signal
// (gibson#1500).
type HealthUnavailable struct {
	MergeRequest string
	At           time.Time
	MissionID    string
}

// Kind identifies the health.unavailable brain event.
func (HealthUnavailable) Kind() string { return "health.unavailable" }

// applyHealthUnavailable marks each Finding of the merge request. The first
// report keeps its time, so a repeated report does not restart the wait.
func applyHealthUnavailable(w *World, e HealthUnavailable) {
	if e.MergeRequest == "" || e.At.IsZero() {
		return
	}
	forEachFindingOfMR(w, e.MergeRequest, func(f *Finding) {
		if f.HealthUnavailableAt.IsZero() {
			f.HealthUnavailableAt = e.At
		}
	})
}

// FixReverted records that an agent reverted its own merge because the health
// signal failed. Each Finding of the merge request is `open` again.
type FixReverted struct {
	MergeRequest string
	At           time.Time
	MissionID    string
}

// Kind identifies the fix.reverted brain event.
func (FixReverted) Kind() string { return "fix.reverted" }

// applyFixReverted sets each Finding of the merge request to open and forgets
// the fix. It is the one event that moves a `verified` Finding back to `open`
// without a rerun, because the revert undoes the fix.
func applyFixReverted(w *World, e FixReverted) {
	if e.MergeRequest == "" {
		return
	}
	forEachFindingOfMR(w, e.MergeRequest, func(f *Finding) {
		f.Status = FindingStatusOpen
		resetFix(f)
	})
	releaseMergeSlot(w, e.MergeRequest)
}

// CheckRerun records that a check ran again on one Finding. Found is true when
// the check found the flaw again. EvidenceAt is the time of the evidence that the
// check read. The check of a scan mission and an attack predicate that settled
// both produce it.
type CheckRerun struct {
	ID         string
	CheckKind  string
	Found      bool
	EvidenceAt time.Time
	MissionID  string
}

// Kind identifies the check.rerun brain event.
func (CheckRerun) Kind() string { return "check.rerun" }

// applyCheckRerun keeps the newest rerun of the Finding. An invalid kind or a
// time that is not newer changes nothing.
func applyCheckRerun(w *World, e CheckRerun) {
	if !finding.CheckKind(e.CheckKind).IsValid() || e.EvidenceAt.IsZero() {
		return
	}
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.ID != e.ID {
			continue
		}
		if e.EvidenceAt.After(f.RerunAt) {
			f.RerunKind, f.RerunFound, f.RerunAt = e.CheckKind, e.Found, e.EvidenceAt
		}
		q.Close()
		return
	}
}

// forEachFindingOfMR calls fn on each Finding that the merge request carries.
func forEachFindingOfMR(w *World, key string, fn func(*Finding)) {
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		if f := q.Get(); f.MergeRequest == key {
			fn(f)
		}
	}
}

// effectiveCheck is the check of a Finding for the order of strength. A Finding
// with no recorded check counts as the weakest, so any check can verify it.
func effectiveCheck(f FindingSnapshot) finding.Check {
	if f.CheckKind == "" {
		return finding.Check{Kind: finding.CheckTool}
	}
	return finding.Check{Kind: finding.CheckKind(f.CheckKind)}
}

// VerificationSystem decides the fate of each `fixed` Finding that has a
// deploy and a rerun on newer evidence:
//
//	the check found the flaw again                 → open
//	the check found nothing, and it is strong
//	enough, and the health signal held            → verified
//
// A rerun on evidence that is not newer than the deploy decides nothing. A clean
// rerun of a check that is weaker than the check that raised the Finding decides
// nothing. A clean rerun with no "held" health signal decides nothing, so no
// Finding is `verified` while the health signal has no "held" event.
//
// The System is quiescent: after the change the Finding is no longer `fixed`.
func VerificationSystem(w *World) []Event {
	now := w.Now()
	var out []Event
	for _, f := range w.FindingSnapshot() {
		if f.Status != FindingStatusFixed || f.DeployedAt.IsZero() {
			continue
		}
		if f.RerunAt.IsZero() || !f.RerunAt.After(f.DeployedAt) {
			continue // the evidence is not newer than the deploy
		}
		if f.RerunFound {
			out = append(out, FindingStatusChanged{ID: f.ID, Status: FindingStatusOpen, At: now})
			continue
		}
		rerun := finding.Check{Kind: finding.CheckKind(f.RerunKind)}
		if !rerun.CanVerify(effectiveCheck(f)) || f.Health != HealthHeld {
			continue
		}
		out = append(out, FindingStatusChanged{ID: f.ID, Status: FindingStatusVerified, At: now})
	}
	return out
}
