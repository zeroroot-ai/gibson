package brain

import "testing"

// The place wait ends with the fix: a verified finding and a finding that is open
// again hold no place block. A finding has no false_positive status (a verdict is
// a label), so those two moves are the ones that end a fix.
func TestPlaceBlock_EndsWithTheFix(t *testing.T) {
	block := func(w *World) {
		Reduce(w, FindingPlaceBlocked{ID: "f1", Reason: "waiting on a person: x"})
	}
	get := func(w *World) string { return w.FindingSnapshot()[0].PlaceBlock }

	w := NewWorld("t")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1"})
	block(w)
	if get(w) == "" {
		t.Fatal("the block was not set")
	}
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusVerified})
	if got := get(w); got != "" {
		t.Errorf("a verified finding keeps the block %q", got)
	}

	w = NewWorld("t")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1"})
	block(w)
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusOpen})
	if got := get(w); got != "" {
		t.Errorf("a finding that is open again keeps the block %q", got)
	}
}
