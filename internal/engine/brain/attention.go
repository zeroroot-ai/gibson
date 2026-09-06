// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"fmt"
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// surpriseBoost is added to an entity's attention when it carries a Surprise, so
// the off-path/anomalous thing is surfaced even when its belief is low (ADR-0005/
// 0006: attention has two inputs — the goal-directed belief field AND surprise).
const surpriseBoost = 1.0

// attentionScore combines the two attention inputs: the belief field (goal-directed)
// and the surprise signal (off-path anomaly). Derived at read time — not stored —
// so it never needs an entity key and always reflects current belief + surprise.
func attentionScore(juicy float64, surprised bool) float64 {
	a := juicy
	if surprised {
		a += surpriseBoost
	}
	return a
}

// Finding is a confirmed, reportable security result (ADR-0006). A surprise that
// is investigated and confirmed is promoted to a Finding; an unconfirmed surprise
// is just an attention boost. Findings are the output; "anomaly" is not a separate
// entity.
type Finding struct {
	ID          string
	Title       string
	Description string
	ScopeID     string
	Address     string
	Severity    string

	// Status is the Finding's lifecycle: open, fixing, fixed, verified
	// (gibson#1656). It lives here and only here; a Vulnerability never carries
	// one. A Finding is verified only by a rescan, never by a merge.
	Status string

	// VulnerabilityID is the identity of the weakness this Finding is an
	// occurrence of (a CVE, a GHSA, a CWE, or a platform id). Empty when the
	// Finding has no shared identity. The projector links INSTANCE_OF to the
	// one Vulnerability node per id per tenant.
	VulnerabilityID string

	// ScanScope and LastScan are the Finding's rescan provenance (gibson#1686):
	// which recurring scan is RESPONSIBLE for it, and when that scan last saw it.
	//
	// ScanScope is the TargetID of the scan mission that first raised it — the
	// stable identity of the recurring scan, since one Application's scan is
	// bound to one target. It is the scoping rule for reconciliation, and it is
	// what keeps "absent" from meaning "absent from a scan that was never
	// looking": a Finding a scan never raised has an empty ScanScope and is
	// never reconciled, so a pentest finding or a hand-filed one is not verified
	// because an unrelated scan finished without seeing it.
	//
	// LastScan is the mission id of the most recent scan that raised it. A
	// rescan re-raises what it still sees, so after a scan completes LastScan
	// divides the scope in two: equal to that scan means seen again, anything
	// else means this scan looked and did not find it.
	ScanScope string
	LastScan  string
}

// Finding statuses (gibson#1656). FindingStatusOpen is the default for a raised
// Finding; the others are set by FindingStatusChanged.
const (
	FindingStatusOpen     = "open"
	FindingStatusFixing   = "fixing"
	FindingStatusFixed    = "fixed"
	FindingStatusVerified = "verified"
)

// ValidFindingStatus reports whether s is one of the four Finding statuses.
func ValidFindingStatus(s string) bool {
	switch s {
	case FindingStatusOpen, FindingStatusFixing, FindingStatusFixed, FindingStatusVerified:
		return true
	}
	return false
}

// FindingRaised promotes an observation/surprise into a confirmed Finding. The
// trigger is an investigator (the Decider / an agent); this is the mechanism.
type FindingRaised struct {
	ID          string
	Title       string
	Description string
	ScopeID     string
	Address     string
	Severity    string
	// MissionID links the finding to the mission whose work raised it — the
	// mission-evidence edge (gibson#1075). Carried from the mission-event ingest
	// context for agent/decider findings, and inherited from the source host for a
	// surprise→Finding promotion. Empty when no mission linkage is available (e.g. a
	// finding submitted over the component path, which carries no mission context —
	// follow-up gibson#1078); such findings stay tenant-ambient.
	MissionID string

	// Status is the initial lifecycle status. Empty or invalid means open.
	Status string

	// VulnerabilityID is the shared identity of the weakness, when known.
	VulnerabilityID string
}

func (FindingRaised) Kind() string { return "finding.raised" }

func applyFindingRaised(w *World, e FindingRaised) {
	scope, scan := scanProvenance(w, e.MissionID)

	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.ID != e.ID { // idempotent by ID
			continue
		}
		// A re-raise is a fresh SIGHTING, not a new Finding: everything the
		// Finding already holds stays (an agent's status, its priority), and
		// only the rescan provenance moves. That is what makes "this scan saw
		// it again" expressible at all — without it, the second scan of an
		// unchanged Application would be indistinguishable from no scan.
		if scan != "" {
			f.LastScan = scan
			if f.ScanScope == "" {
				f.ScanScope = scope
			}
		}
		q.Close()
		return
	}
	status := e.Status
	if !ValidFindingStatus(status) {
		status = FindingStatusOpen
	}
	w.findings.NewEntity(&Finding{
		ID: e.ID, Title: e.Title, Description: e.Description, ScopeID: e.ScopeID,
		Address: e.Address, Severity: e.Severity, Status: status, VulnerabilityID: e.VulnerabilityID,
		ScanScope: scope, LastScan: scan,
	})
}

// scanProvenance resolves the rescan scope and the scan id for a Finding raised
// by missionID. A mission that is not a scan — or no mission at all, which is
// how a component-path finding arrives — yields empty strings, so the Finding
// stays outside every scan's scope and no rescan ever reconciles it.
func scanProvenance(w *World, missionID string) (scope, scan string) {
	if missionID == "" {
		return "", ""
	}
	for _, m := range w.MissionSnapshot() {
		if m.ID == missionID && m.Name == ScanMissionName {
			return m.TargetID, m.ID
		}
	}
	return "", ""
}

// FindingStatusChanged moves one Finding through its lifecycle (gibson#1656).
// The trigger is the always-on agent (open -> fixing when its merge request
// opens, fixing -> fixed when GitLab merges it) or a rescan (fixed -> verified
// when the Finding is absent, fixed -> open when it is present again).
type FindingStatusChanged struct {
	ID        string
	Status    string
	MissionID string
}

// Kind identifies the finding.status_changed brain event.
func (FindingStatusChanged) Kind() string { return "finding.status_changed" }

// applyFindingStatusChanged updates the Finding in place. An unknown Finding
// or an invalid status changes nothing: the event is recorded in the Timeline
// either way, but the World never holds a status outside the four.
func applyFindingStatusChanged(w *World, e FindingStatusChanged) {
	if !ValidFindingStatus(e.Status) {
		return
	}
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.ID == e.ID {
			f.Status = e.Status
			q.Close()
			return
		}
	}
}

// FindingSnapshot is a stable, comparable view of a Finding.
type FindingSnapshot struct {
	ID              string
	Title           string
	Description     string
	ScopeID         string
	Address         string
	Severity        string
	Status          string
	VulnerabilityID string
	// ScanScope and LastScan are the rescan provenance (gibson#1686): the
	// recurring scan responsible for this Finding, and the scan that last saw it.
	ScanScope string
	LastScan  string
}

// surpriseFindingID is the stable finding id for a host's identity anomaly, so the
// surprise→Finding promotion is idempotent (one anomaly finding per surprised host).
func surpriseFindingID(hostID uint64) string {
	return fmt.Sprintf("anomaly-host-%d", hostID)
}

// SurpriseFindingSystem promotes a host's Surprise — an identity-contradiction
// anomaly from scope-relative resolution (ADR-0002/0006) — into a Finding. This is
// the surprise→Finding pipeline: a strong-signal contradiction (an address reused
// by a different host) is a real security signal, so it surfaces as a reportable
// Finding, not just an attention boost. Idempotent + quiescent: one finding per
// surprised host, keyed by surpriseFindingID.
func SurpriseFindingSystem(w *World) []Event {
	existing := map[string]bool{}
	for _, f := range w.FindingSnapshot() {
		existing[f.ID] = true
	}
	var out []Event
	for _, h := range w.Snapshot() {
		if h.Surprise == "" {
			continue
		}
		fid := surpriseFindingID(h.ID)
		if existing[fid] {
			continue
		}
		out = append(out, FindingRaised{
			ID:          fid,
			Title:       "Identity anomaly at " + h.Address,
			Description: h.Surprise,
			ScopeID:     h.ScopeID,
			Address:     h.Address,
			Severity:    "medium",
			MissionID:   h.MissionID, // inherit the source host's mission attribution
		})
	}
	return out
}

// FindingSnapshot returns the current findings in deterministic (ID) order.
func (w *World) FindingSnapshot() []FindingSnapshot {
	var out []FindingSnapshot
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		out = append(out, FindingSnapshot{
			ID: f.ID, Title: f.Title, Description: f.Description, ScopeID: f.ScopeID,
			Address: f.Address, Severity: f.Severity, Status: f.Status, VulnerabilityID: f.VulnerabilityID,
			ScanScope: f.ScanScope, LastScan: f.LastScan,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
