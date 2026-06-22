package brain

import "testing"

// A label applied to a Finding is folded into the World and surfaces in the
// pooled label set (ADR-0006).
func TestLabelApplied_FoldsIntoWorld(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictTruePositive, Severity: "high", Category: "rce", UserID: "alice"})
	e.Tick()

	ls := e.Labels()
	if len(ls) != 1 {
		t.Fatalf("want 1 label, got %d (%+v)", len(ls), ls)
	}
	if ls[0].TargetID != "finding-1" || ls[0].Verdict != VerdictTruePositive || ls[0].UserID != "alice" {
		t.Errorf("label wrong: %+v", ls[0])
	}
}

// Re-labelling the same target replaces the prior judgement (latest-write-wins,
// one current label per target) — the trainer reads the tenant's settled opinion.
func TestLabelApplied_LatestWriteWins(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictTruePositive, UserID: "alice"})
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictFalsePositive, UserID: "bob"})
	e.Tick()

	ls := e.Labels()
	if len(ls) != 1 {
		t.Fatalf("re-label should not add a row; want 1, got %d", len(ls))
	}
	if ls[0].Verdict != VerdictFalsePositive || ls[0].UserID != "bob" {
		t.Errorf("latest write should win: %+v", ls[0])
	}
}

// Labels pool ACROSS USERS within a tenant: two users labelling two items both
// land in the one tenant-wide pool (ADR-0006 §6 — UserID is provenance, not a
// partition key).
func TestLabels_PoolAcrossUsersWithinTenant(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictTruePositive, UserID: "alice"})
	e.Submit(LabelApplied{TargetID: "finding-2", Verdict: VerdictDismiss, UserID: "bob"})
	e.Tick()

	ls := e.Labels()
	if len(ls) != 2 {
		t.Fatalf("both users' labels should pool tenant-wide; want 2, got %d (%+v)", len(ls), ls)
	}
	// Deterministic (target-id) order.
	if ls[0].TargetID != "finding-1" || ls[1].TargetID != "finding-2" {
		t.Errorf("labels not in deterministic order: %+v", ls)
	}
}

// Labels NEVER cross tenants: a label in t1's World is invisible in t2's World
// (structural isolation — one World per tenant, ADR-0001).
func TestLabels_NeverCrossTenant(t *testing.T) {
	t1 := NewEngine("t1")
	t2 := NewEngine("t2")
	t1.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictTruePositive, UserID: "alice"})
	t1.Tick()
	t2.Tick()

	if n := len(t1.Labels()); n != 1 {
		t.Fatalf("t1 should hold its label; got %d", n)
	}
	if n := len(t2.Labels()); n != 0 {
		t.Fatalf("t2 must NOT see t1's label; got %d", n)
	}
}

// Labelling is replay-reproducible: folding the Timeline into a fresh World
// reproduces the label set exactly (labels are events — ADR-0006 §3).
func TestLabelApplied_ReplayReproduces(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictTruePositive, UserID: "alice"})
	e.Submit(LabelApplied{TargetID: "finding-1", Verdict: VerdictFalsePositive, UserID: "bob"})
	e.Tick()

	tl := &Timeline{}
	for _, ev := range e.Events() {
		tl.Append(ev)
	}
	w := Replay("t1", tl)
	ls := w.LabelSnapshot()
	if len(ls) != 1 || ls[0].Verdict != VerdictFalsePositive {
		t.Fatalf("replay did not reproduce label set: %+v", ls)
	}
}

// The review queue projects Findings (and surfaced surprises), attaching any
// applied label — and never mutates the World (read-only; non-blocking).
func TestReviewQueue_ProjectsFindingsWithLabels(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SurpriseFindingSystem)
	// Raise a Finding via an identity contradiction.
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB"})
	e.Tick()

	fs := e.Findings()
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	// Label that finding.
	e.Submit(LabelApplied{TargetID: fs[0].ID, Verdict: VerdictTruePositive, UserID: "alice"})
	e.Tick()

	q := e.ReviewQueue()
	var labelled *ReviewItem
	for i := range q {
		if q[i].TargetID == fs[0].ID {
			labelled = &q[i]
		}
	}
	if labelled == nil {
		t.Fatalf("finding not in review queue: %+v", q)
	}
	if !labelled.Labelled || labelled.Label.Verdict != VerdictTruePositive {
		t.Errorf("review item should carry its label: %+v", labelled)
	}
	// Building the queue must be quiescent (no events emitted).
	if applied := e.Tick(); applied != 0 {
		t.Errorf("review queue is read-only; extra tick applied %d events", applied)
	}
}

func TestValidVerdict(t *testing.T) {
	for _, v := range []LabelVerdict{VerdictTruePositive, VerdictFalsePositive, VerdictDismiss} {
		if !ValidVerdict(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	if ValidVerdict("bogus") {
		t.Error("unknown verdict must be rejected fail-closed")
	}
}
