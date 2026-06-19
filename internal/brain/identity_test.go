package brain

import (
	"reflect"
	"testing"
)

// TestResolve_ProgressiveIdentity: a host seen at a new address but with the same
// strong signal (ssh host key) resolves to the SAME entity (one host, not two).
func TestResolve_ProgressiveIdentity(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.5", SSHHostKey: "KEY-A", OpenPorts: []int{22}})
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.9", SSHHostKey: "KEY-A", OpenPorts: []int{22}}) // same key, new address

	snap := w.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d hosts, want 1 (strong-signal match across addresses): %+v", len(snap), snap)
	}
	if snap[0].SSHHostKey != "KEY-A" {
		t.Fatalf("host key = %q, want KEY-A", snap[0].SSHHostKey)
	}
}

// TestResolve_CoordinateUpdate: repeated observations at the same (scope,address)
// with no strong signal update the same entity (no duplicate); ports accumulate.
func TestResolve_CoordinateUpdate(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})

	snap := w.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d hosts, want 1", len(snap))
	}
	if !reflect.DeepEqual(snap[0].OpenPorts, []int{22, 80}) {
		t.Fatalf("open ports = %v, want [22 80]", snap[0].OpenPorts)
	}
}

// TestResolve_PortClose: a port no longer observed is closed, not deleted — it
// drops out of the open set but the host is unchanged in identity.
func TestResolve_PortClose(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}}) // 80 no longer seen

	snap := w.Snapshot()
	if len(snap) != 1 || !reflect.DeepEqual(snap[0].OpenPorts, []int{22}) {
		t.Fatalf("after close: %+v, want one host with open [22]", snap)
	}
}

// TestResolve_Contradiction: the same (scope,address) answered by a different
// strong signal is a DIFFERENT host (two entities) and the newcomer carries a
// Surprise (the anomaly signal). Replay reproduces it.
func TestResolve_Contradiction(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(HostObserved{ScopeID: "s", Address: "10.0.0.5", SSHHostKey: "KEY-A", OpenPorts: []int{22}})
	apply(HostObserved{ScopeID: "s", Address: "10.0.0.5", SSHHostKey: "KEY-B", OpenPorts: []int{22}}) // different key, same coord

	snap := w.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("got %d hosts, want 2 (contradiction = distinct host): %+v", len(snap), snap)
	}
	var surprises int
	for _, h := range snap {
		if h.Surprise != "" {
			surprises++
		}
	}
	if surprises != 1 {
		t.Fatalf("got %d surprised hosts, want 1: %+v", surprises, snap)
	}

	if replayed := Replay("t", tl); !reflect.DeepEqual(replayed.Snapshot(), snap) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", replayed.Snapshot(), snap)
	}
}
