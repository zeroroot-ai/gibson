package brain

import (
	"sort"
	"strconv"

	"github.com/mlange-42/ark/ecs"
)

// LabelVerdict is the human judgement applied to a surfaced surprise or Finding
// (ADR-0006: the HITL label source). It is the gold-signal companion to the
// free-but-noisy AUTO outcomes the trainer also consumes.
type LabelVerdict string

const (
	// VerdictTruePositive — a real, confirmed security signal.
	VerdictTruePositive LabelVerdict = "true_positive"
	// VerdictFalsePositive — surfaced but not a real signal.
	VerdictFalsePositive LabelVerdict = "false_positive"
	// VerdictDismiss — not actionable / noise; decays the surprise, trains the model down.
	VerdictDismiss LabelVerdict = "dismiss"
)

// validVerdicts gates SubmitLabel — an unknown verdict is rejected fail-closed so
// the training signal never carries a typo'd label.
var validVerdicts = map[LabelVerdict]bool{
	VerdictTruePositive:  true,
	VerdictFalsePositive: true,
	VerdictDismiss:       true,
}

// ValidVerdict reports whether v is a known label verdict.
func ValidVerdict(v LabelVerdict) bool { return validVerdicts[v] }

// Label is a human review judgement on a surfaced item (a Finding or a
// surprised host), recorded in the per-tenant World (ADR-0006).
//
// Tenant isolation is structural, not a field check: a Label only ever exists in
// one tenant's World/Timeline (one World per tenant — ADR-0001), so labels
// **never** cross tenants and never feed the curated base model. WITHIN a tenant
// they pool across all that tenant's users — UserID is provenance only, NOT a
// partition key; the trainer reads every label in the tenant's log regardless of
// which user applied it (ADR-0006 §6).
type Label struct {
	TargetID string       // the labelled item: a Finding id, or a surprise host id
	Verdict  LabelVerdict // true_positive / false_positive / dismiss
	Severity string       // corrected severity (optional; "" = leave as-is)
	Category string       // free-form taxonomy tag (optional)
	UserID   string       // who applied it — provenance only; labels pool tenant-wide
}

// LabelSnapshot is a stable, comparable view of a Label.
type LabelSnapshot struct {
	TargetID string
	Verdict  LabelVerdict
	Severity string
	Category string
	UserID   string
}

// LabelApplied records a human review judgement as a Timeline event. Like every
// brain write it flows through an event so it is logged, tenant-scoped, and
// replay-reproducible. Applying a label is **never** a runtime gate: the event is
// appended asynchronously and the mission never waits on it (ADR-0006 §2).
type LabelApplied struct {
	TargetID string
	Verdict  LabelVerdict
	Severity string
	Category string
	UserID   string
}

func (LabelApplied) Kind() string { return "label.applied" }

// applyLabelApplied folds a label into the World. Latest-write-wins per target:
// re-labelling the same item replaces the prior judgement (one current label per
// target), so the trainer reads the tenant's settled opinion, not a history of
// edits. The label pool is shared across the tenant's users by construction.
func applyLabelApplied(w *World, e LabelApplied) {
	q := ecs.NewFilter1[Label](w.ecs).Query()
	for q.Next() {
		l := q.Get()
		if l.TargetID == e.TargetID {
			l.Verdict = e.Verdict
			l.Severity = e.Severity
			l.Category = e.Category
			l.UserID = e.UserID
			q.Close()
			return
		}
	}
	w.labels.NewEntity(&Label{
		TargetID: e.TargetID,
		Verdict:  e.Verdict,
		Severity: e.Severity,
		Category: e.Category,
		UserID:   e.UserID,
	})
}

// LabelSnapshot returns the tenant's current labels in deterministic (target id)
// order — the pooled, tenant-wide label set the offline trainer consumes.
func (w *World) LabelSnapshot() []LabelSnapshot {
	var out []LabelSnapshot
	q := ecs.NewFilter1[Label](w.ecs).Query()
	for q.Next() {
		l := q.Get()
		out = append(out, LabelSnapshot{
			TargetID: l.TargetID,
			Verdict:  l.Verdict,
			Severity: l.Severity,
			Category: l.Category,
			UserID:   l.UserID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out
}

// ReviewItem is one entry in the HITL review queue: a surfaced surprise or a
// Finding awaiting (or carrying) a human label. The queue is a read-only
// projection — it never blocks a mission (ADR-0006 §2).
type ReviewItem struct {
	TargetID string // Finding id or surprise host id (the label target)
	Kind     string // "finding" or "surprise"
	Title    string
	ScopeID  string
	Address  string
	Severity string
	// Labelled carries the current label if one has been applied (else zero).
	Labelled bool
	Label    LabelSnapshot
}

// surpriseReviewID is the stable review-queue / label target id for a surprised
// host, distinct from its anomaly Finding id so a raw surprise can be labelled
// before it is promoted.
func surpriseReviewID(hostID uint64) string {
	return "surprise-host-" + strconv.FormatUint(hostID, 10)
}

// ReviewQueue projects the tenant's surfaced surprises + Findings into a review
// queue, attaching any label already applied. Deterministic order (Findings by
// id, then surprises by host). Read-only over snapshots — building the queue
// never mutates the World and never gates execution.
func (w *World) ReviewQueue() []ReviewItem {
	labels := map[string]LabelSnapshot{}
	for _, l := range w.LabelSnapshot() {
		labels[l.TargetID] = l
	}

	var out []ReviewItem
	for _, f := range w.FindingSnapshot() {
		item := ReviewItem{
			TargetID: f.ID,
			Kind:     "finding",
			Title:    f.Title,
			ScopeID:  f.ScopeID,
			Address:  f.Address,
			Severity: f.Severity,
		}
		if l, ok := labels[f.ID]; ok {
			item.Labelled = true
			item.Label = l
		}
		out = append(out, item)
	}

	for _, h := range w.Snapshot() {
		if h.Surprise == "" {
			continue
		}
		tid := surpriseReviewID(h.ID)
		// A surprise already promoted to a Finding is reviewed as that Finding;
		// skip the raw-surprise duplicate.
		if _, promoted := labels[surpriseFindingID(h.ID)]; promoted {
			continue
		}
		item := ReviewItem{
			TargetID: tid,
			Kind:     "surprise",
			Title:    "Surprise at " + h.Address,
			ScopeID:  h.ScopeID,
			Address:  h.Address,
			Severity: "medium",
		}
		if l, ok := labels[tid]; ok {
			item.Labelled = true
			item.Label = l
		}
		out = append(out, item)
	}
	return out
}
