// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "github.com/mlange-42/ark/ecs"

// rescan.go reconciles what a scan did NOT see (gibson#1686).
//
// Every other Finding transition is driven by an observation: something looked,
// found a weakness, and said so. `fixed` → `verified` is the one transition
// with no observation behind it. Nothing emits "I did not see this". A scan
// reports what it found, and the absence of a Finding from that report is only
// meaningful once the whole scan has finished looking.
//
// That is why this is a System over a completed mission rather than anything a
// branch can do. The Scan mission joins its three branches at `report` so there
// is exactly one completion to hang this off. A per-branch reconciliation would
// verify a runtime Finding because the IMAGE branch finished without seeing it —
// each branch is blind to the other two by design.
//
// # Scope
//
// The rule is: a scan reconciles only the Findings that a scan of the same
// target has raised before.
//
// A Finding records the scan responsible for it (Finding.ScanScope, the scan
// mission's TargetID) and the scan that last saw it (Finding.LastScan). After a
// scan completes, those two divide its scope in two, and nothing else is in it.
//
// Both ways of getting this wrong are silent, which is why the rule is narrow
// rather than convenient:
//
//   - Too wide — scoping by Application, or by "every Finding in the tenant" —
//     verifies a Finding no scan was ever responsible for. A pentest finding, a
//     hand-filed one, or one raised by a different mission type would be closed
//     out because an unrelated scan happened to finish without seeing it. The
//     Finding's ScanScope is empty in every one of those cases, so it is never
//     in scope here.
//
//   - Too narrow — requiring the scan to positively re-observe absence — never
//     verifies anything, and the demo's time-to-fix number never closes.
//
// # Failure
//
// A scan that did not finish reconciles nothing. An unfinished look is not
// evidence of absence, and a scan that could not run produces exactly the same
// report as a scan that found everything clean: an empty one. Only
// MissionCompleted reconciles; MissionFailed is marked reconciled so the System
// stays quiescent, and emits no status change at all.

// ScanMissionName is the name of the Scan mission definition
// (internal/platform/missioncatalog/missions/scan.cue). A mission is a scan —
// and so reconciles — when its Name matches.
const ScanMissionName = "scan"

// ScanReconciled records that a terminal scan's reconciliation has run.
//
// It exists because reconciliation is a one-shot at the terminal transition,
// not a standing property of a completed mission. Without it, a completed scan
// stays completed forever, so an agent that marks a Finding `fixed` an hour
// later would have it verified on the very next tick by a scan that finished
// before the fix existed. The marker makes the scan's judgement about what it
// saw expire with the scan.
type ScanReconciled struct {
	MissionID string
}

// Kind identifies the scan.reconciled brain event.
func (ScanReconciled) Kind() string { return "scan.reconciled" }

// applyScanReconciled marks the mission reconciled. An unknown mission changes
// nothing: the event is in the Timeline either way.
func applyScanReconciled(w *World, e ScanReconciled) {
	q := ecs.NewFilter1[Mission](w.ecs).Query()
	for q.Next() {
		m := q.Get()
		if m.ID == e.MissionID {
			m.Reconciled = true
			q.Close()
			return
		}
	}
}

// RescanReconciliationSystem moves the Findings a completed scan did not see.
//
// For each terminal, not-yet-reconciled scan mission it emits ScanReconciled,
// and — only when the scan actually completed — one FindingStatusChanged per
// Finding in its scope whose status is `fixed`:
//
//	seen again by this scan  → open      (the fix did not hold)
//	not seen by this scan    → verified  (the fix held)
//
// Nothing else moves. An `open` Finding the scan did not see stays `open`: a
// scan not seeing something it never fixed is not evidence, and silently
// closing it would lose a real weakness. The same goes for `fixing` — a merge
// request is in flight and the scan's silence says nothing about it.
//
// The instant of the transition is recorded by the projector, which stamps
// verified_at the first time a Finding reaches verified (gibson#1679).
func RescanReconciliationSystem(w *World) []Event {
	missions := w.MissionSnapshot()
	scans := make([]MissionSnapshot, 0, len(missions))
	for _, m := range missions {
		if m.Name != ScanMissionName || m.Reconciled {
			continue
		}
		if m.Status != MissionCompleted && m.Status != MissionFailed {
			continue // still running: it has not finished looking
		}
		scans = append(scans, m)
	}
	if len(scans) == 0 {
		return nil
	}

	findings := w.FindingSnapshot()

	// One ScanReconciled per scan, plus at most one status change per Finding
	// in its scope.
	out := make([]Event, 0, len(scans)+len(findings))
	for _, m := range scans {
		out = append(out, ScanReconciled{MissionID: m.ID})
		if m.Status != MissionCompleted {
			// An unfinished look is not evidence of absence.
			continue
		}
		for _, f := range findings {
			if f.ScanScope == "" || f.ScanScope != m.TargetID {
				continue // not this recurring scan's responsibility
			}
			if f.Status != FindingStatusFixed {
				continue // only a fix is waiting on a rescan's verdict
			}
			status := FindingStatusVerified
			if f.LastScan == m.ID {
				status = FindingStatusOpen // the scan saw it again
			}
			out = append(out, FindingStatusChanged{
				ID: f.ID, Status: status, MissionID: m.ID,
			})
		}
	}
	return out
}
