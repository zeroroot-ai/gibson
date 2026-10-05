// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestRowsFromWorld_LabelledFindingBecomesARow mirrors the end-to-end case
// the deleted RowsFromTimeline test drove: a host with an identity
// contradiction raises a Finding, a reviewer labels it true_positive, and the
// World yields one row with the evidence variables and both outcomes true.
func TestRowsFromWorld_LabelledFindingBecomesARow(t *testing.T) {
	e := brain.NewEngine("acme")
	e.AddSystem(brain.SurpriseFindingSystem)
	e.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA", OpenPorts: []int{22},
		Services: map[int]brain.ServiceInfo{22: {Name: "ssh"}}})
	e.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB", OpenPorts: []int{22}})
	e.Tick()
	fs := e.Findings()
	if len(fs) == 0 {
		t.Fatal("expected a finding")
	}
	e.Submit(brain.LabelApplied{TargetID: fs[0].ID, Verdict: brain.VerdictTruePositive, UserID: "alice"})
	e.Tick()

	// The contradiction splits identity into two hosts at one address; both
	// carry the Finding, so both are positive rows.
	rows := RowsFromWorld(e.World, nil)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(rows), rows)
	}
	withService := 0
	for _, r := range rows {
		for _, k := range []string{"reachable", "port_22", "exploitable", "juicy"} {
			if !r[k] {
				t.Errorf("%s must be true in %+v", k, r)
			}
		}
		if r["svc_ssh"] {
			withService++
		}
	}
	if withService != 1 {
		t.Errorf("exactly one host observed the ssh service, got %d rows with svc_ssh", withService)
	}
}

// TestRowsFromWorld_KnownRestrictsColumnsAndUnscannedHostsTeachNothing
// proves known filters the emitted variables and a host with no ports and no
// label yields no row.
func TestRowsFromWorld_KnownRestrictsColumnsAndUnscannedHostsTeachNothing(t *testing.T) {
	w := brain.NewWorld("acme")
	brain.Reduce(w, brain.HostObserved{ScopeID: "s1", Address: "10.0.0.1", OpenPorts: []int{80, 443}})
	brain.Reduce(w, brain.HostObserved{ScopeID: "s1", Address: "10.0.0.2"})

	rows := RowsFromWorld(w, map[string]bool{"reachable": true, "exploitable": true})
	if len(rows) != 1 {
		t.Fatalf("want 1 row (the scanned host only), got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if len(r) != 2 || !r["reachable"] || r["exploitable"] {
		t.Fatalf("known must restrict the row to reachable=true, exploitable=false: %+v", r)
	}
}

// TestRowsFromWorld_HITLVerdictOverridesTheAutoOutcome proves a
// false_positive label on a host's surprise flips exploitable and juicy off,
// and that the sort is stable across two identical runs.
func TestRowsFromWorld_HITLVerdictOverridesTheAutoOutcome(t *testing.T) {
	w := brain.NewWorld("acme")
	brain.Reduce(w, brain.HostObserved{ScopeID: "s1", Address: "10.0.0.9", OpenPorts: []int{22}})
	hosts := w.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(hosts))
	}
	brain.Reduce(w, brain.LabelApplied{TargetID: fmt.Sprintf("surprise-host-%d", hosts[0].ID), Verdict: brain.VerdictFalsePositive, UserID: "bob"})

	rows := RowsFromWorld(w, nil)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0]["exploitable"] || rows[0]["juicy"] {
		t.Fatalf("a false_positive label must force exploitable and juicy false: %+v", rows[0])
	}
	again := RowsFromWorld(w, nil)
	if rowKey(again[0]) != rowKey(rows[0]) {
		t.Fatal("the same World must yield the same rows")
	}
}
