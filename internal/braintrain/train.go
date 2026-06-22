package braintrain

import (
	"fmt"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/brain"
)

// Row is one training example: a full assignment of every network variable to a
// binary state (true/false) for a single observed host. Fitting is then plain
// (Laplace-smoothed) conditional counting over these rows.
type Row map[string]bool

// laplaceAlpha is the additive-smoothing pseudocount. It keeps every CPT entry
// strictly in (0,1) even with sparse tenant data — pgmpy's check_model rejects a
// degenerate 0/1 column, and a hard 0 would make a single mislabel unrecoverable.
const laplaceAlpha = 1.0

// Fit rewrites a base artifact's CPT values from training rows and stamps a new
// per-tenant version, returning the trained artifact (ADR-0006). The base
// supplies STRUCTURE (variables + edges) only; every CPT is refit from data with
// Laplace smoothing. Variables absent from the rows fall back to the smoothing
// prior (a uniform-ish table), so a partially-observed network still validates.
//
// version is the full artifact version string the caller assigns (e.g.
// "tenant-acme-v3"); it is what a mission pins and what replay re-loads.
func Fit(base *Artifact, rows []Row, version string) (*Artifact, error) {
	if base == nil {
		return nil, fmt.Errorf("braintrain: nil base artifact")
	}
	if version == "" {
		return nil, fmt.Errorf("braintrain: empty version")
	}

	parents := base.parents()
	trained := &Artifact{
		Version:     version,
		Description: fmt.Sprintf("Per-tenant belief model trained offline from %d outcome+label rows (gibson#753, ADR-0006). Structure from %q; CPTs refit by Laplace-smoothed counting. Never derived from cross-tenant data.", len(rows), base.Version),
		Variables:   append([]string(nil), base.Variables...),
		Edges:       cloneEdges(base.Edges),
		CPDs:        map[string]*CPD{},
	}

	for _, v := range base.Variables {
		ps := parents[v]
		trained.CPDs[v] = fitCPD(v, ps, rows)
	}
	if err := trained.validate(); err != nil {
		return nil, err
	}
	return trained, nil
}

// fitCPD counts P(v=true | parents) over the rows with additive smoothing,
// returning a CPD in the sidecar's [state][parent-assignment] column layout. Rows
// missing v (or any parent) are skipped for that variable — partial observation
// degrades gracefully to the smoothing prior, it does not corrupt the table.
func fitCPD(v string, ps []string, rows []Row) *CPD {
	ncols := 1 << len(ps) // 2^|parents| parent assignments
	// trueCount/total per parent-assignment column.
	trueCount := make([]float64, ncols)
	total := make([]float64, ncols)

	for _, r := range rows {
		if _, ok := r[v]; !ok {
			continue
		}
		col, ok := parentColumn(r, ps)
		if !ok {
			continue // a parent value is missing in this row
		}
		total[col]++
		if r[v] {
			trueCount[col]++
		}
	}

	falseRow := make([]float64, ncols)
	trueRow := make([]float64, ncols)
	for c := 0; c < ncols; c++ {
		// Laplace smoothing over 2 states.
		pTrue := (trueCount[c] + laplaceAlpha) / (total[c] + 2*laplaceAlpha)
		trueRow[c] = round(pTrue)
		falseRow[c] = round(1 - pTrue)
	}

	cpd := &CPD{Values: [][]float64{falseRow, trueRow}}
	if len(ps) > 0 {
		cpd.Evidence = append([]string(nil), ps...)
		cpd.EvidenceCard = make([]int, len(ps))
		for i := range ps {
			cpd.EvidenceCard[i] = 2
		}
	}
	return cpd
}

// parentColumn maps a row's parent-state assignment to a column index in the
// big-endian order pgmpy uses (first parent most significant). Returns false if
// any parent's value is absent from the row.
func parentColumn(r Row, ps []string) (int, bool) {
	col := 0
	for _, p := range ps {
		val, ok := r[p]
		if !ok {
			return 0, false
		}
		col <<= 1
		// pgmpy column order: state index 0 ("false") is the LOW end of each
		// parent's stride, so true contributes the high bit.
		if val {
			col |= 1
		}
	}
	return col, true
}

func cloneEdges(in [][]string) [][]string {
	out := make([][]string, len(in))
	for i, e := range in {
		out[i] = append([]string(nil), e...)
	}
	return out
}

// round clamps to 4 decimal places — enough precision for a CPT, keeps artifacts
// compact and byte-stable across re-runs on the same data.
func round(f float64) float64 {
	return float64(int64(f*1e4+0.5)) / 1e4
}

// RowsFromTimeline derives training rows from a tenant's brain Timeline (ADR-0006).
// It folds the events into a World, then for every host that carries either an
// AUTO outcome (a Finding raised against it) or a HITL label, emits one Row of
// (evidence → outcome). This is the (evidence → outcome) training signal ADR-0005
// §4 describes: the log already records outcomes, so most labels are automatic;
// HITL labels override/augment them.
//
// Variables follow the sidecar's evidence conventions (sidecar/belief/model.py):
//   - reachable   ← host has any open port
//   - svc_<name>  ← a service of that name observed
//   - port_<n>    ← port n open
//   - exploitable ← AUTO: a Finding was raised for the host; HITL true_positive ⇒ true
//   - juicy       ← HITL verdict (true_positive ⇒ true, false_positive/dismiss ⇒ false);
//     absent label falls back to the AUTO exploitable signal.
//
// known restricts the variables emitted to those the base network declares, so a
// row only sets columns the model can use.
func RowsFromTimeline(events []brain.Event, known map[string]bool) []Row {
	tl := &brain.Timeline{}
	tenant := ""
	for _, ev := range events {
		tl.Append(ev)
	}
	w := brain.Replay(tenant, tl)

	// Index labels by their target id (Finding id or surprise host id).
	labels := map[string]brain.LabelSnapshot{}
	for _, l := range w.LabelSnapshot() {
		labels[l.TargetID] = l
	}

	var rows []Row
	for _, h := range w.Snapshot() {
		auto, hasAuto := autoOutcomeForHost(w, h)
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

	// Deterministic order so re-training the same log yields a byte-stable artifact.
	sort.SliceStable(rows, func(i, j int) bool { return rowKey(rows[i]) < rowKey(rows[j]) })
	return rows
}

func setIf(r Row, known map[string]bool, k string, v bool) {
	if known == nil || known[k] {
		r[k] = v
	}
}

// autoOutcomeForHost reports whether the log raised a Finding against this host
// (the AUTO positive outcome). A host with an anomaly Finding at its address is a
// confirmed positive; absence is a negative example.
func autoOutcomeForHost(w *brain.World, h brain.HostSnapshot) (bool, bool) {
	for _, f := range w.FindingSnapshot() {
		if f.Address == h.Address && f.ScopeID == h.ScopeID {
			return true, true
		}
	}
	// No finding for this host — a (weak) negative AUTO example only if the host
	// was actually scanned (has ports); an empty host teaches nothing.
	if len(h.OpenPorts) > 0 {
		return false, true
	}
	return false, false
}

// labelForHost finds a HITL label targeting this host, by its anomaly-finding id
// or its raw-surprise id.
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

func rowKey(r Row) string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		if r[k] {
			s += k + "=1;"
		} else {
			s += k + "=0;"
		}
	}
	return s
}
