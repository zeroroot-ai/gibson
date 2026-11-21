// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"fmt"
	"sort"
	"time"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// surpriseBoost is added to an entity's attention when it carries a Surprise, so
// the off-path/anomalous thing is surfaced even when its belief is low (ADR-0129/
// 0006: attention has two inputs — the goal-directed belief field AND surprise).
const surpriseBoost = 1.0

// attentionScore combines the attention inputs: the belief field (goal-directed)
// and the surprise signal (off-path anomaly). The belief field contributes both
// how valuable a host is (juicy) and how attackable it is (exploitable,
// gibson#478) — a host a scan has proved exploitable must rank above an equally
// juicy host that is not, so the Decider spends its context budget on the hosts an
// attack can actually land on. Derived at read time — not stored — so it never
// needs an entity key and always reflects current belief + surprise.
func attentionScore(juicy, exploitable float64, surprised bool) float64 {
	a := juicy + exploitable
	if surprised {
		a += surpriseBoost
	}
	return a
}

// Finding is a confirmed, reportable security result (ADR-0106). A surprise that
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
	// LastScan is the run ID of the most recent scan run that raised it. The
	// mission ID is the same for every run of a recurring scan, so only the
	// run tells one scan from the next (gibson#1217). A
	// rescan re-raises what it still sees, so after a scan completes LastScan
	// divides the scope in two: equal to that scan means seen again, anything
	// else means this scan looked and did not find it.
	ScanScope string
	LastScan  string

	// MergeRequest is the key of the merge request that carries the fix
	// (gibson#1505). MergeRequestState is what the Git host last reported for
	// it: empty while it is open, then merged or closed.
	MergeRequest      string
	MergeRequestState string

	// Priority, PriorityRule and PriorityReason are what the last triage pass
	// decided (gibson#1522). Priority is P1 to P4 and is empty until a pass
	// decides. Empty is a fact about the Finding and never a default.
	Priority       string
	PriorityRule   string
	PriorityReason string

	// FixFacts are the facts of the fix loop (gibson#1457, #1460, #1464).
	FixFacts

	// RefusedMoves counts the status changes that the lifecycle refused, and
	// LastRefusedMove names the last one, as "from -> to" (review M4).
	RefusedMoves    int
	LastRefusedMove string

	// SubmittedBy, AgentName and EnrolledBy are the verified submitter
	// (gibson#208). See FindingRaised.
	SubmittedBy string
	AgentName   string
	EnrolledBy  string
}

// FixFacts are what the fix loop records about one Finding. Each time comes
// from an event, never from the clock during Reduce, so a replay gives the same
// World.
type FixFacts struct {
	// CheckKind and CheckRef name the check that raised the Finding (ADR-0178):
	// predicate, scan or tool. Empty means that the producer recorded none. An
	// empty kind counts as the weakest check, so any check can verify it.
	CheckKind string
	CheckRef  string
	// FirstSeenAt is when the check first saw the flaw. RaisedAt is when Gibson
	// read it. For a Finding from a tool of the buyer the two differ.
	FirstSeenAt time.Time
	RaisedAt    time.Time
	// DeployedAt and DeploymentKey record the deploy of the merged fix. They are
	// zero for a fix that is not deployed.
	DeployedAt    time.Time
	DeploymentKey string
	// Health is what the health signal said after the deploy: empty, held or
	// failed.
	Health string
	// HealthUnavailableAt is when the daemon found that the service has no
	// health signal. It is zero when a signal exists or the daemon did not look.
	HealthUnavailableAt time.Time
	// RerunKind, RerunFound and RerunAt are the latest rerun of a check on the
	// Finding. RerunAt is the time of the evidence.
	RerunKind  string
	RerunFound bool
	RerunAt    time.Time
	// FixMissionID is the mission of the job that opened the merge request of
	// the fix (gibson#1465). The daemon writes each later event of the fix loop
	// with it, so a replay of that mission shows the merge, the deploy, the
	// health signal and the revert.
	FixMissionID string
	// RevertRequestedAt is when the daemon first asked the Git host to revert
	// the fix, and RevertMergeRequest is the merge request of the revert. Both
	// are zero until a failed health signal asks for a revert.
	RevertRequestedAt  time.Time
	RevertMergeRequest string
	// FixClaim names the fix job that works on the Finding now: the mission
	// run and the node of the job. Empty means that no job holds it.
	// FixClaimedAt is the time of the claim. A merge request that the job
	// delivers must be newer than it (review B1).
	FixClaim     string
	FixClaimedAt time.Time
	// VerifiedAt is the time of the change to `verified`. A bounded reader
	// of the history reads it to leave out an old fix (review M6).
	VerifiedAt time.Time
}

// Health values of FixFacts.
const (
	HealthHeld   = "held"
	HealthFailed = "failed"
)

// Finding statuses (gibson#1656). FindingStatusOpen is the default for a raised
// Finding; the others are set by FindingStatusChanged.
//
// The values come from package finding, the one definition of the four
// statuses (gibson#1518). The World stores a status as a plain string.
const (
	FindingStatusOpen     = string(finding.StatusOpen)
	FindingStatusFixing   = string(finding.StatusFixing)
	FindingStatusFixed    = string(finding.StatusFixed)
	FindingStatusVerified = string(finding.StatusVerified)
)

// ValidFindingStatus reports whether s is one of the four Finding statuses.
func ValidFindingStatus(s string) bool {
	return finding.FindingStatus(s).IsValid()
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
	// MissionRunID is the run of the mission that produced this evidence. The
	// reducer drops the event when the mission has moved on to another run, so
	// late evidence of run 1 cannot count for run 2 (gibson#1217). Empty means
	// the event is not run-scoped.
	MissionRunID string

	// Status is the initial lifecycle status. Empty or invalid means open.
	Status string

	// VulnerabilityID is the shared identity of the weakness, when known.
	VulnerabilityID string

	// SubmittedBy, AgentName and EnrolledBy are the verified submitter
	// (gibson#208): the FGA principal that submitted the finding, the name the
	// agent registered under, and the subject of the person who enrolled it.
	// Empty on paths that carry no submitter identity.
	SubmittedBy string
	AgentName   string
	EnrolledBy  string

	// CheckKind and CheckRef name the check that raised the Finding (ADR-0178).
	CheckKind string
	CheckRef  string
	// At is when Gibson read the evidence. FirstSeenAt is when the check first
	// saw the flaw, when that is earlier. A producer sets both. Reduce never
	// reads the clock.
	At          time.Time
	FirstSeenAt time.Time
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
		if f.RaisedAt.IsZero() {
			f.RaisedAt = e.At
		}
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
		FixFacts: FixFacts{
			CheckKind: e.CheckKind, CheckRef: e.CheckRef,
			RaisedAt: e.At, FirstSeenAt: firstSeen(e),
		},
		SubmittedBy: e.SubmittedBy, AgentName: e.AgentName, EnrolledBy: e.EnrolledBy,
	})
}

// firstSeen is the time a check first saw the flaw. A producer that has no
// earlier time gives none, and the time of the read stands.
func firstSeen(e FindingRaised) time.Time {
	if !e.FirstSeenAt.IsZero() {
		return e.FirstSeenAt
	}
	return e.At
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
		if m.ID == missionID && m.Name == ScanMissionName && m.RunID != "" {
			return m.TargetID, m.RunID
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
	// MergeRequest is the key of the merge request behind the change
	// (gibson#1505). When it is set, the Finding records it and forgets the
	// state of any earlier merge request.
	MergeRequest string
	// At is the time of the change. A reader of the Timeline uses it.
	At time.Time
}

// Kind identifies the finding.status_changed brain event.
func (FindingStatusChanged) Kind() string { return "finding.status_changed" }

// allowedStatusMoves are the moves of the lifecycle of a Finding (ADR-0178,
// review M4). FixReverted is the one other event that sets a status: it
// opens a Finding again because the revert undoes the fix.
var allowedStatusMoves = map[[2]string]bool{
	{FindingStatusOpen, FindingStatusFixing}:    true, // a fix job opened a merge request
	{FindingStatusFixing, FindingStatusFixed}:   true, // the merge request merged
	{FindingStatusFixing, FindingStatusOpen}:    true, // the merge request closed
	{FindingStatusFixed, FindingStatusVerified}: true, // the check and the health signal proved the fix
	{FindingStatusFixed, FindingStatusOpen}:     true, // the check found the flaw again
	{FindingStatusVerified, FindingStatusOpen}:  true, // the check found the flaw again after the verification (review r8)
}

// AllowedStatusMove reports whether a Finding may move from one status to the
// other with a FindingStatusChanged event.
func AllowedStatusMove(from, to string) bool { return allowedStatusMoves[[2]string{from, to}] }

// applyFindingStatusChanged updates the Finding in place. An unknown Finding
// or an invalid status changes nothing: the event is recorded in the Timeline
// either way, but the World never holds a status outside the four. A move
// that the lifecycle does not allow changes nothing, and the Finding records
// the refusal (review M4).
func applyFindingStatusChanged(w *World, e FindingStatusChanged) {
	if !ValidFindingStatus(e.Status) {
		return
	}
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.ID == e.ID {
			if !AllowedStatusMove(f.Status, e.Status) {
				f.RefusedMoves++
				f.LastRefusedMove = f.Status + " -> " + e.Status
				q.Close()
				return
			}
			f.Status = e.Status
			if e.MergeRequest != "" {
				f.MergeRequest = e.MergeRequest
				f.MergeRequestState = ""
				f.FixMissionID = e.MissionID
			}
			if e.Status == FindingStatusOpen {
				resetFix(f)
			}
			if e.Status == FindingStatusVerified {
				f.VerifiedAt = e.At
			}
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
	// MergeRequest and MergeRequestState: see Finding (gibson#1505).
	MergeRequest      string
	MergeRequestState string
	// Priority, PriorityRule and PriorityReason: see Finding (gibson#1522).
	Priority       string
	PriorityRule   string
	PriorityReason string
	// FixFacts: see Finding.
	FixFacts
	// RefusedMoves and LastRefusedMove: see Finding.
	RefusedMoves    int
	LastRefusedMove string
	// SubmittedBy, AgentName and EnrolledBy are the verified submitter
	// (gibson#208). See FindingRaised.
	SubmittedBy string
	AgentName   string
	EnrolledBy  string
}

// surpriseFindingID is the stable finding id for a host's identity anomaly, so the
// surprise→Finding promotion is idempotent (one anomaly finding per surprised host).
func surpriseFindingID(hostID uint64) string {
	return fmt.Sprintf("anomaly-host-%d", hostID)
}

// SurpriseFindingSystem promotes a host's Surprise — an identity-contradiction
// anomaly from scope-relative resolution (ADR-0102/0106) — into a Finding. This is
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
			CheckKind:   string(finding.CheckScan),
			CheckRef:    h.MissionID,
			At:          w.Now(),
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
			MergeRequest: f.MergeRequest, MergeRequestState: f.MergeRequestState,
			Priority: f.Priority, PriorityRule: f.PriorityRule, PriorityReason: f.PriorityReason,
			FixFacts:     f.FixFacts,
			RefusedMoves: f.RefusedMoves, LastRefusedMove: f.LastRefusedMove,
			SubmittedBy: f.SubmittedBy, AgentName: f.AgentName, EnrolledBy: f.EnrolledBy,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// resetFix forgets the fix of a Finding that is open again. The next fix starts
// from nothing: a new merge request, a new deploy and a new health signal.
func resetFix(f *Finding) {
	f.MergeRequest = ""
	f.MergeRequestState = ""
	f.DeployedAt = time.Time{}
	f.DeploymentKey = ""
	f.Health = ""
	f.HealthUnavailableAt = time.Time{}
	f.RerunKind, f.RerunFound, f.RerunAt = "", false, time.Time{}
	f.FixMissionID = ""
	f.RevertRequestedAt, f.RevertMergeRequest = time.Time{}, ""
	f.FixClaim, f.FixClaimedAt = "", time.Time{}
	f.VerifiedAt = time.Time{}
}
