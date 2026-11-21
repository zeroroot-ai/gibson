// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

func TestFindingPrioritized_OnlyP1ToP4Lands(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, FindingPrioritized{ID: "f1", Priority: "P2", Rule: "kev"})
	Reduce(w, FindingPrioritized{ID: "f1", Priority: "P9", Reason: "because"})
	f := findingByID(t, w, "f1")
	if f.Priority != "P2" || f.PriorityRule != "kev" || f.PriorityReason != "because" {
		t.Fatalf("finding = %+v, want P2, kev and the reason, with P9 dropped", f)
	}
}

func TestFindingPrioritized_UnrankedFindingHasNoDefault(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1"})
	if p := findingByID(t, w, "f1").Priority; p != "" {
		t.Fatalf("priority = %q, want empty", p)
	}
}

// An agent that writes a Finding entity with priority properties reaches the
// typed field, and the free property does not stay on the entity.
func TestEntityObserved_FindingPriorityIsFoldedAndStripped(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, EntityObserved{
		Label: "Finding", Key: "f1",
		Props: map[string]string{"priority": "P1", "priority_rule": "r", "priority_reason": "why", "note": "n"},
	})
	f := findingByID(t, w, "f1")
	if f.Priority != "P1" || f.PriorityRule != "r" || f.PriorityReason != "why" {
		t.Fatalf("finding = %+v", f)
	}
	for _, e := range w.EntitySnapshot() {
		if e.Label == "Finding" {
			if _, ok := e.Props["priority"]; ok {
				t.Fatalf("priority stayed a free property: %v", e.Props)
			}
			if e.Props["note"] != "n" {
				t.Fatalf("other properties must stay: %v", e.Props)
			}
		}
	}
}

func TestEntityObserved_InvalidPriorityIsDropped(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, EntityObserved{Label: "Finding", Key: "f1", Props: map[string]string{"priority": "urgent"}})
	if p := findingByID(t, w, "f1").Priority; p != "" {
		t.Fatalf("priority = %q, want empty", p)
	}
}
