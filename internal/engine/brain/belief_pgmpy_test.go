package brain

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// fakeSidecar is an httptest stand-in for the pgmpy sidecar: it records the last
// request and returns a scripted response, so the Go provider is tested without a
// live Python process.
type fakeSidecar struct {
	lastReq scoreRequest
	resp    scoreResponse
	status  int
	calls   int
}

func (f *fakeSidecar) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.calls++
		_ = json.NewDecoder(r.Body).Decode(&f.lastReq)
		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.resp)
	}
}

// TestPgmpyBelief_ScoresFromSidecar proves the provider derives deterministic
// evidence from a Host, calls the sidecar, and records the returned posteriors +
// model version on the Belief.
func TestPgmpyBelief_ScoresFromSidecar(t *testing.T) {
	fake := &fakeSidecar{resp: scoreResponse{Version: "base-v1", Juicy: 0.7, Exploitable: 0.8, Reachable: 1.0}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p := PgmpyBeliefProvider(srv.URL, "base-v1", nil)
	h := Host{
		ID:      1,
		ScopeID: "s",
		Address: "10.0.0.5",
		Ports: []PortObservation{
			{Number: 443, Open: true, Service: ServiceInfo{Name: "https"}},
			{Number: 22, Open: true, Service: ServiceInfo{Name: "ssh"}},
			{Number: 8080, Open: false}, // closed -> excluded from evidence
		},
	}

	got := p.Score(h)
	want := Belief{Juicy: 0.7, Exploitable: 0.8, Reachable: 1.0, Model: "base-v1"}
	if got != want {
		t.Fatalf("belief = %+v, want %+v", got, want)
	}

	// Evidence is derived deterministically: only open ports, services sorted.
	wantEv := beliefEvidence{
		OpenPorts: []int{22, 443},
		Services:  []string{"22/ssh", "443/https"},
		Reachable: true,
	}
	if !reflect.DeepEqual(fake.lastReq.Evidence, wantEv) {
		t.Fatalf("evidence = %+v, want %+v", fake.lastReq.Evidence, wantEv)
	}
	if fake.lastReq.Version != "base-v1" {
		t.Fatalf("request did not pin version: %q", fake.lastReq.Version)
	}
}

// TestPgmpyBelief_FailQuiet proves a sidecar error yields a zero Belief (no
// score) rather than a bogus one — so the field stays quiescent and the System
// retries on the next evidence change.
func TestPgmpyBelief_FailQuiet(t *testing.T) {
	fake := &fakeSidecar{status: http.StatusInternalServerError}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p := PgmpyBeliefProvider(srv.URL, "", nil)
	if got := p.Score(Host{ID: 1, Ports: []PortObservation{{Number: 22, Open: true}}}); got != (Belief{}) {
		t.Fatalf("expected zero Belief on sidecar error, got %+v", got)
	}
}

// stubPrior is a deterministic PriorProvider for the novel-node path.
type stubPrior struct{ called int }

func (s *stubPrior) PriorFor(NovelNode) NodePrior {
	s.called++
	return NodePrior{Juicy: 0.9, Exploitable: 0.9, Reachable: 1.0}
}

// TestPgmpyBelief_NovelNodeFeedsPrior proves that when the sidecar reports a
// novel node (no CPT), the provider asks the PriorProvider (the LLM seam) and
// re-scores once with the injected priors (ADR-0005 §6).
func TestPgmpyBelief_NovelNodeFeedsPrior(t *testing.T) {
	fake := &fakeSidecar{}
	// First call: novel node reported. Second call: clean score.
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.calls++
		_ = json.NewDecoder(r.Body).Decode(&fake.lastReq)
		w.Header().Set("Content-Type", "application/json")
		if first {
			first = false
			_ = json.NewEncoder(w).Encode(scoreResponse{Version: "base-v1", Novel: []NovelNode{{HostID: 1, Address: "10.0.0.5", Reason: "unknown variable: svc_weird"}}})
			return
		}
		_ = json.NewEncoder(w).Encode(scoreResponse{Version: "base-v1", Juicy: 0.9, Exploitable: 0.9, Reachable: 1.0})
	}))
	defer srv.Close()

	prior := &stubPrior{}
	p := PgmpyBeliefProvider(srv.URL, "base-v1", prior)
	got := p.Score(Host{ID: 1, Address: "10.0.0.5", Ports: []PortObservation{{Number: 9999, Open: true}}})

	if prior.called != 1 {
		t.Fatalf("PriorProvider called %d times, want 1", prior.called)
	}
	if fake.calls != 2 {
		t.Fatalf("sidecar called %d times, want 2 (initial + re-score with priors)", fake.calls)
	}
	if got.Juicy != 0.9 || got.Model != "base-v1" {
		t.Fatalf("belief after prior injection = %+v, want juicy 0.9 / model base-v1", got)
	}
	// The re-score carried the injected prior keyed by the node address.
	if pr, ok := fake.lastReq.Priors["10.0.0.5"]; !ok || pr.Juicy != 0.9 {
		t.Fatalf("re-score did not carry the injected prior: %+v", fake.lastReq.Priors)
	}
}

// TestPgmpyBelief_IntegratesAsSystem proves the pgmpy provider drops into the
// existing BeliefSystem seam: scored on evidence, quiescent once current, and
// replay-reproducible (the BeliefScored event carries the version).
func TestPgmpyBelief_IntegratesAsSystem(t *testing.T) {
	fake := &fakeSidecar{resp: scoreResponse{Version: "base-v1", Juicy: 0.7, Exploitable: 0.8, Reachable: 1.0}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	e := NewEngine("t")
	e.AddSystem(BeliefSystem(PgmpyBeliefProvider(srv.URL, "base-v1", nil)))
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 443}})
	e.Tick()

	snap := e.World.Snapshot()
	if len(snap) != 1 || snap[0].Belief.Model != "base-v1" || snap[0].Belief.Juicy != 0.7 {
		t.Fatalf("belief not scored from sidecar: %+v", snap)
	}
	// Quiescent: same evidence -> same score -> no new event.
	if n := e.Tick(); n != 0 {
		t.Fatalf("belief not quiescent: extra tick applied %d events", n)
	}
	// Replay reproduces (BeliefScored logged with the pinned version).
	if r := Replay("t", e.Timeline); !reflect.DeepEqual(r.Snapshot(), e.World.Snapshot()) {
		t.Fatalf("replay diverged")
	}
}
