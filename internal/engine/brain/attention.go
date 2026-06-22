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
}

func (FindingRaised) Kind() string { return "finding.raised" }

func applyFindingRaised(w *World, e FindingRaised) {
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		if q.Get().ID == e.ID { // idempotent by ID
			q.Close()
			return
		}
	}
	w.findings.NewEntity(&Finding{ID: e.ID, Title: e.Title, Description: e.Description, ScopeID: e.ScopeID, Address: e.Address, Severity: e.Severity})
}

// FindingSnapshot is a stable, comparable view of a Finding.
type FindingSnapshot struct {
	ID          string
	Title       string
	Description string
	ScopeID     string
	Address     string
	Severity    string
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
		out = append(out, FindingSnapshot{ID: f.ID, Title: f.Title, Description: f.Description, ScopeID: f.ScopeID, Address: f.Address, Severity: f.Severity})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
