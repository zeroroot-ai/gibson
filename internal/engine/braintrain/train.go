// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package braintrain joins the belief training lane to the brain: it derives
// the training rows of a tenant from its folded World (train.go), and it gives
// the runtime its view of a fitted edge posterior artifact
// (edge_posterior.go). The fitting itself is package fit, which the belief
// trainer imports without the brain.
package braintrain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
)

// RowsFromWorld derives the training rows for the belief-CPT model from a
// folded World (gibson#613). The Timeline is snapshot-trimmed (engine.go
// TrimTo), so the World, which the snapshot carries whole, is the only input
// that cannot lose a row.
//
// Each host with an outcome becomes a row. The evidence variables of a row
// are the belief evidence of the host (World.BeliefEvidenceByHost), the same
// evidence that inference scores:
//   - reachable                 <- host has any open port
//   - port_<n>, svc_<name>      <- port n open, a service of that name seen
//   - finding_critical/_high    <- a confirmed, active finding at that severity
//   - exploit_demonstrated      <- a bet settled TRUE on the host
//
// The outcome variables come from the fold itself, as ADR-0106 describes: the
// log already records them, so most labels are automatic, and HITL labels
// override them:
//   - exploitable <- AUTO: a Finding was raised for the host; a HITL
//     true_positive forces true, false_positive or dismiss forces false
//   - juicy       <- the HITL verdict (true_positive => true, otherwise
//     false); an absent label falls back to the AUTO exploitable signal
//
// A row names each variable it saw as true or false. A port or a service that
// the host did not show is absent, and fit.Fit reads an absent variable as
// false.
func RowsFromWorld(w *brain.World) []fit.Row {
	labels := map[string]brain.LabelSnapshot{}
	for _, l := range w.LabelSnapshot() {
		labels[l.TargetID] = l
	}
	findings := w.FindingSnapshot()
	evidence := w.BeliefEvidenceByHost()

	var rows []fit.Row
	for _, h := range w.Snapshot() {
		auto, hasAuto := autoOutcomeForHost(findings, h)
		lbl, hasLabel := labelForHost(h, labels)
		if !hasAuto && !hasLabel {
			continue // nothing to learn from this host
		}

		ev := evidence[h.ID]
		row := fit.Row{
			"reachable":            ev.Reachable,
			"finding_critical":     ev.FindingCritical,
			"finding_high":         ev.FindingHigh,
			"exploit_demonstrated": ev.ExploitDemonstrated,
		}
		for _, p := range ev.OpenPorts {
			row[fmt.Sprintf("port_%d", p)] = true
		}
		for _, svc := range ev.Services {
			if _, name, ok := strings.Cut(svc, "/"); ok && name != "" {
				row["svc_"+name] = true
			}
		}

		// exploitable: AUTO finding OR explicit HITL true-positive.
		exploitable := auto
		if hasLabel {
			switch lbl.Verdict {
			case brain.VerdictTruePositive:
				exploitable = true
			case brain.VerdictFalsePositive, brain.VerdictDismiss:
				exploitable = false
			}
		}
		row["exploitable"] = exploitable

		// juicy: HITL verdict if present, else the AUTO outcome.
		juicy := auto
		if hasLabel {
			juicy = lbl.Verdict == brain.VerdictTruePositive
		}
		row["juicy"] = juicy

		rows = append(rows, row)
	}

	// Deterministic order so re-training the same World yields a byte-stable artifact.
	sort.SliceStable(rows, func(i, j int) bool { return rowKey(rows[i]) < rowKey(rows[j]) })
	return rows
}

// autoOutcomeForHost reports whether the fold raised a Finding against this
// host (the AUTO positive outcome). A host with a Finding at its address is a
// confirmed positive; a scanned host with none is a (weak) negative example;
// an unscanned host (no ports) teaches nothing.
func autoOutcomeForHost(findings []brain.FindingSnapshot, h brain.HostSnapshot) (outcome, known bool) {
	for _, f := range findings {
		if f.Address == h.Address && f.ScopeID == h.ScopeID {
			return true, true
		}
	}
	if len(h.OpenPorts) > 0 {
		return false, true
	}
	return false, false
}

// labelForHost finds a HITL label targeting this host, by its anomaly-finding
// id or its raw-surprise id.
func labelForHost(h brain.HostSnapshot, labels map[string]brain.LabelSnapshot) (brain.LabelSnapshot, bool) {
	for _, tid := range []string{
		fmt.Sprintf("anomaly-host-%d", h.ID),
		fmt.Sprintf("surprise-host-%d", h.ID),
	} {
		if l, ok := labels[tid]; ok {
			return l, true
		}
	}
	return brain.LabelSnapshot{}, false
}

// rowKey is a canonical string form of a row, for a stable sort.
func rowKey(r fit.Row) string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		if r[k] {
			b.WriteString("=1;")
		} else {
			b.WriteString("=0;")
		}
	}
	return b.String()
}
