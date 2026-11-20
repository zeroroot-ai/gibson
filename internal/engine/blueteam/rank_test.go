// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

func f(id, prio, sev, status, addr string) brain.FindingSnapshot {
	return brain.FindingSnapshot{ID: id, Priority: prio, Severity: sev, Status: status, Address: addr, ScopeID: "s"}
}

func host(addr string, juicy float64) brain.HostSnapshot {
	return brain.HostSnapshot{ScopeID: "s", Address: addr, Belief: brain.Belief{Juicy: juicy}}
}

func order(rs []Ranked) []string {
	sort.Slice(rs, func(i, j int) bool { return Key(rs[i]) < Key(rs[j]) })
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID)
	}
	return ids
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOpenRanked_P1BeforeP2(t *testing.T) {
	got := order(OpenRanked([]brain.FindingSnapshot{
		f("a", "P2", "critical", "open", "h1"), f("b", "P1", "low", "open", "h1"),
	}, nil))
	if want := []string{"b", "a"}; !equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOpenRanked_SamePriorityByBeliefOfTarget(t *testing.T) {
	got := order(OpenRanked([]brain.FindingSnapshot{
		f("a", "P1", "high", "open", "cold"), f("b", "P1", "high", "open", "hot"),
	}, []brain.HostSnapshot{host("cold", 0.1), host("hot", 0.9)}))
	if want := []string{"b", "a"}; !equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOpenRanked_NoPriorityRanksBySeverity(t *testing.T) {
	got := order(OpenRanked([]brain.FindingSnapshot{
		f("low", "", "low", "open", "h"), f("crit", "", "critical", "open", "h"), f("p3", "P3", "critical", "open", "h"),
	}, nil))
	// A critical finding with no priority ranks as P1. A low one ranks as P4.
	if want := []string{"crit", "p3", "low"}; !equal(got, want) {
		t.Fatalf("order = %v", got)
	}
}

func TestOpenRanked_LeavesOutVerified(t *testing.T) {
	got := OpenRanked([]brain.FindingSnapshot{
		f("a", "P1", "high", "verified", "h"), f("b", "P1", "high", "fixed", "h"),
	}, nil)
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %v", got)
	}
}
