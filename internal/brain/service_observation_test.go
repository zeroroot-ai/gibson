package brain

import (
	"reflect"
	"testing"
)

// TestServiceObservation_FoldEnrichReplay proves that per-port service detail
// (ADR-0007 observation vocabulary) folds into the host as port sub-state, is
// enriched progressively across observations (never erased by a barer scan), and
// survives replay — World == fold(Timeline).
func TestServiceObservation_FoldEnrichReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	// 1. First scan: ports 22 + 80, with partial service detail on 22.
	apply(HostObserved{
		ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80},
		Services: map[int]ServiceInfo{
			22: {Protocol: "tcp", Name: "ssh"},
		},
	})
	// 2. Deeper scan: enriches 22 (product+version), adds detail to 80.
	apply(HostObserved{
		ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80},
		Services: map[int]ServiceInfo{
			22: {Product: "OpenSSH", Version: "8.9p1"},
			80: {Protocol: "tcp", Name: "http", Product: "nginx"},
		},
	})
	// 3. Bare re-scan (no service detail): must NOT erase prior enrichment.
	apply(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})

	want := []HostSnapshot{{
		ID:        1,
		ScopeID:   "s",
		Address:   "10.0.0.5",
		OpenPorts: []int{22, 80},
		Services: map[int]ServiceInfo{
			22: {Protocol: "tcp", Name: "ssh", Product: "OpenSSH", Version: "8.9p1"},
			80: {Protocol: "tcp", Name: "http", Product: "nginx"},
		},
	}}
	got := w.Snapshot()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot:\n got %+v\nwant %+v", got, want)
	}

	// Replay reproduces the enriched World from the Timeline alone.
	if replayed := Replay("tenant-1", tl).Snapshot(); !reflect.DeepEqual(replayed, got) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", replayed, got)
	}
}

// TestServiceObservation_EndpointTechCert folds endpoint/technology/certificate
// sub-state (ADR-0007) and proves progressive enrichment (union, never erased).
func TestServiceObservation_EndpointTechCert(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HostObserved{
		ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{443},
		Endpoints:    map[int][]EndpointInfo{443: {{Path: "/login", Status: 200}}},
		Technologies: map[int][]TechnologyInfo{443: {{Name: "nginx"}}},
		Certificates: map[int]CertificateInfo{443: {Fingerprint: "ab12", Subject: "CN=example"}},
	})
	// Second scan: new endpoint + version on tech; bare cert obs must not erase.
	Reduce(w, HostObserved{
		ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{443},
		Endpoints:    map[int][]EndpointInfo{443: {{Path: "/api"}}},
		Technologies: map[int][]TechnologyInfo{443: {{Name: "nginx", Version: "1.25"}}},
	})

	snap := w.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 host, got %d", len(snap))
	}
	eps := snap[0].Endpoints[443]
	if len(eps) != 2 {
		t.Fatalf("endpoints not unioned: %+v", eps)
	}
	techs := snap[0].Technologies[443]
	if len(techs) != 1 || techs[0].Version != "1.25" {
		t.Fatalf("technology not enriched: %+v", techs)
	}
	if c := snap[0].Certificates[443]; c.Fingerprint != "ab12" || c.Subject != "CN=example" {
		t.Fatalf("certificate not retained: %+v", c)
	}
}

// TestServiceObservation_ClosedPortKeepsService proves a port that goes closed
// retains its service sub-state (ADR-0002: associations are time-bounded, kept not
// deleted) — so the closed port carries no service in the open-only snapshot but is
// not lost from the entity.
func TestServiceObservation_ClosedPortKeepsService(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HostObserved{
		ScopeID: "s", Address: "10.0.0.9", OpenPorts: []int{22, 8080},
		Services: map[int]ServiceInfo{8080: {Name: "http", Product: "tomcat"}},
	})
	// Re-scan: 8080 no longer open.
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.9", OpenPorts: []int{22}})

	got := w.Snapshot()
	if len(got) != 1 || !reflect.DeepEqual(got[0].OpenPorts, []int{22}) {
		t.Fatalf("expected only port 22 open, got %+v", got)
	}
	// 8080's service is gone from the open-port view (it is closed) but the record
	// is retained on the entity — re-observing it open restores the service detail.
	Reduce(w, HostObserved{ScopeID: "s", Address: "10.0.0.9", OpenPorts: []int{22, 8080}})
	got = w.Snapshot()
	if svc := got[0].Services[8080]; svc.Product != "tomcat" {
		t.Fatalf("expected retained service detail on reopened port 8080, got %+v", got[0].Services)
	}
}
