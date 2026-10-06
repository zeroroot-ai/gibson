// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package braintrain holds the belief-training surface: the per-tenant
// edge-posterior artifact the runtime loads (edge_posterior.go) and the
// training-row derivation from a folded World (train.go). The fitting half
// returns with gibson#614.
package braintrain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// Row is one training example: a full assignment of every network variable
// to a binary state (true/false) for a single observed host. Fitting is plain
// (Laplace-smoothed) conditional counting over these rows.
type Row map[string]bool

// RowsFromWorld derives the training rows for the belief-CPT model from a
// folded World (gibson#613, child A of gibson#590). It replaces the deleted
// RowsFromTimeline: the Timeline is snapshot-trimmed (engine.go TrimTo), so
// the World, which the snapshot carries whole, is the only input that cannot
// lose a row.
//
// Every host with an outcome becomes a row. Outcomes come from the fold
// itself: the log already records them, so most
// labels are automatic; HITL labels override or augment them.
//
// Variables follow the belief model's evidence conventions:
//   - reachable   <- host has any open port
//   - svc_<name>  <- a service of that name observed
//   - port_<n>    <- port n open
//   - exploitable <- AUTO: a Finding was raised for the host; a HITL
//     true_positive forces true, false_positive or dismiss forces false
//   - juicy       <- the HITL verdict (true_positive => true, otherwise
//     false); an absent label falls back to the AUTO exploitable signal
//
// known restricts the variables emitted to those the base network declares,
// so a row only sets columns the model can use. nil means every variable.
func RowsFromWorld(w *brain.World, known map[string]bool) []Row {
	// Index labels by their target id (Finding id or surprise host id).
	labels := map[string]brain.LabelSnapshot{}
	for _, l := range w.LabelSnapshot() {
		labels[l.TargetID] = l
	}
	findings := w.FindingSnapshot()

	var rows []Row
	for _, h := range w.Snapshot() {
		auto, hasAuto := autoOutcomeForHost(findings, h)
		lbl, hasLabel := labelForHost(h, labels)
		if !hasAuto && !hasLabel {
			continue // nothing to learn from this host
		}

		row := Row{}
		setIf(row, known, "reachable", len(h.OpenPorts) > 0)
		for _, p := range h.OpenPorts {
			setIf(row, known, fmt.Sprintf("port_%d", p), true)
		}
		for _, svc := range serviceNames(h) {
			setIf(row, known, "svc_"+svc, true)
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
		setIf(row, known, "exploitable", exploitable)

		// juicy: HITL verdict if present, else the AUTO outcome.
		juicy := auto
		if hasLabel {
			juicy = lbl.Verdict == brain.VerdictTruePositive
		}
		setIf(row, known, "juicy", juicy)

		rows = append(rows, row)
	}

	// Deterministic order so re-training the same World yields a byte-stable artifact.
	sort.SliceStable(rows, func(i, j int) bool { return rowKey(rows[i]) < rowKey(rows[j]) })
	return rows
}

func setIf(r Row, known map[string]bool, k string, v bool) {
	if known == nil || known[k] {
		r[k] = v
	}
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

func serviceNames(h brain.HostSnapshot) []string {
	var out []string
	for _, svc := range h.Services {
		if svc.Name != "" {
			out = append(out, svc.Name)
		}
	}
	sort.Strings(out)
	return out
}

// rowKey is a canonical string form of a row, for a stable sort.
func rowKey(r Row) string {
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
