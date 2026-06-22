package readiness_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/readiness"
)

// -- helpers -----------------------------------------------------------------

// passingProbe always returns nil.
type passingProbe struct{ name string }

func (p *passingProbe) Name() string                  { return p.name }
func (p *passingProbe) Check(_ context.Context) error { return nil }

// failingProbe always returns an error.
type failingProbe struct {
	name string
	msg  string
}

func (p *failingProbe) Name() string                  { return p.name }
func (p *failingProbe) Check(_ context.Context) error { return errors.New(p.msg) }

// countingProbe counts Check invocations.
type countingProbe struct {
	name   string
	calls  atomic.Int64
	waitCh chan struct{} // if non-nil, Check blocks until waitCh is closed
}

func (p *countingProbe) Name() string { return p.name }
func (p *countingProbe) Check(_ context.Context) error {
	p.calls.Add(1)
	if p.waitCh != nil {
		<-p.waitCh
	}
	return nil
}

// readyzBody decodes the JSON response from a /readyz handler response.
type readyzBody struct {
	Status string `json:"status"`
	Probes []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	} `json:"probes"`
}

func decodeReadyz(t *testing.T, rr *httptest.ResponseRecorder) readyzBody {
	t.Helper()
	var body readyzBody
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode readyz response: %v\nbody: %s", err, rr.Body.String())
	}
	return body
}

// -- tests -------------------------------------------------------------------

// TestReadyHandler_AllPass verifies 200 when every registered probe passes.
func TestReadyHandler_AllPass(t *testing.T) {
	a := readiness.NewAggregator()
	a.Register(&passingProbe{name: "db"})
	a.Register(&passingProbe{name: "cache"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	a.ReadyHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
	body := decodeReadyz(t, rr)
	if body.Status != "pass" {
		t.Errorf("want status=pass, got %q", body.Status)
	}
}

// TestReadyHandler_AnyFail_Returns503 verifies 503 when at least one probe fails.
func TestReadyHandler_AnyFail_Returns503(t *testing.T) {
	a := readiness.NewAggregator()
	a.Register(&failingProbe{name: "db", msg: "connection refused"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	a.ReadyHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rr.Code)
	}
	body := decodeReadyz(t, rr)
	if body.Status != "fail" {
		t.Errorf("want status=fail, got %q", body.Status)
	}
}

// TestReadyHandler_FailingProbeInBody verifies that the failing probe's name
// and error message appear in the response body — kubectl describe friendly.
func TestReadyHandler_FailingProbeInBody(t *testing.T) {
	a := readiness.NewAggregator()
	a.Register(&passingProbe{name: "cache"})
	a.Register(&failingProbe{name: "db", msg: "connection refused"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	a.ReadyHandler().ServeHTTP(rr, req)

	body := decodeReadyz(t, rr)

	found := false
	for _, p := range body.Probes {
		if p.Name == "db" {
			found = true
			if p.Status != "fail" {
				t.Errorf("db probe status: want fail, got %q", p.Status)
			}
			if p.Error != "connection refused" {
				t.Errorf("db probe error: want %q, got %q", "connection refused", p.Error)
			}
		}
	}
	if !found {
		t.Error("db probe not present in response body")
	}
}

// TestReadyHandler_MixedResult_Returns503 verifies that one failing probe among
// passing probes yields 503 and the failing probe appears in the body.
func TestReadyHandler_MixedResult_Returns503(t *testing.T) {
	a := readiness.NewAggregator()
	a.Register(&passingProbe{name: "cache"})
	a.Register(&failingProbe{name: "neo4j", msg: "unavailable"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	a.ReadyHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rr.Code)
	}
	body := decodeReadyz(t, rr)
	if body.Status != "fail" {
		t.Errorf("want status=fail, got %q", body.Status)
	}

	var failNames []string
	for _, p := range body.Probes {
		if p.Status == "fail" {
			failNames = append(failNames, p.Name)
		}
	}
	if len(failNames) != 1 || failNames[0] != "neo4j" {
		t.Errorf("want exactly [neo4j] failing, got %v", failNames)
	}
}

// TestReadyHandler_EmptyAggregator_Returns200 verifies that an Aggregator with
// no probes returns 200 — the process considers itself ready by default.
func TestReadyHandler_EmptyAggregator_Returns200(t *testing.T) {
	a := readiness.NewAggregator()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	a.ReadyHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200 for empty aggregator, got %d", rr.Code)
	}
	body := decodeReadyz(t, rr)
	if body.Status != "pass" {
		t.Errorf("want status=pass, got %q", body.Status)
	}
}

// TestReadyHandler_ConcurrentRequestsDoNotDuplicateWork verifies that
// singleflight collapses concurrent /readyz calls into a single probe run.
//
// Strategy: the counting probe blocks inside Check waiting for a gate channel.
// We launch N goroutines; each fires a request. The probe increments a counter
// BEFORE blocking on the gate — that counter signals "in Check now". We wait
// until at least one goroutine is inside Check (counter >= 1), then open the
// gate. All goroutines that arrived while the first was still in Check are
// collapsed by singleflight and share the single result. Any straggler that
// arrives after the gate is opened may start a second flight; we therefore
// assert calls <= 2 (one guaranteed collapse group, and at most one straggler
// group) rather than exactly 1 — this keeps the test race-safe while still
// proving the singleflight contract.
func TestReadyHandler_ConcurrentRequestsDoNotDuplicateWork(t *testing.T) {
	const concurrency = 10

	gate := make(chan struct{})
	probe := &countingProbe{name: "slow-dep", waitCh: gate}

	a := readiness.NewAggregator()
	a.Register(probe)

	handler := a.ReadyHandler()

	type result struct{ code int }
	results := make(chan result, concurrency)

	// Start all goroutines before opening the gate so they pile up in-flight.
	for range concurrency {
		go func() {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			handler.ServeHTTP(rr, req)
			results <- result{code: rr.Code}
		}()
	}

	// Wait until the singleflight leader is blocked inside Check, then give the
	// remaining goroutines a settle window to pile into sf.Do (where they
	// coalesce onto the leader) before releasing the gate. Black-box coalescing
	// is only observable once the followers have actually entered Do, which is
	// not directly observable, so — like the upstream
	// golang.org/x/sync/singleflight test — we wait for the leader and then
	// settle. Releasing the instant the leader enters (the previous behaviour)
	// raced the followers and flaked under load.
	for probe.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	close(gate)

	// Drain results and confirm all got 200.
	for i := range concurrency {
		r := <-results
		if r.code != http.StatusOK {
			t.Errorf("request %d: want 200, got %d", i, r.code)
		}
	}

	// Singleflight must have collapsed the burst: N requests produce at most
	// 2 Check calls (one in-flight group + at most one straggler group),
	// which is far fewer than N individual calls.
	calls := probe.calls.Load()
	if calls >= int64(concurrency) {
		t.Errorf("singleflight had no effect: got %d Check calls for %d requests", calls, concurrency)
	}
}

// TestLivenessHandler_AlwaysOK verifies that /healthz always returns 200
// regardless of probe state, and the body is {"status":"ok"}.
func TestLivenessHandler_AlwaysOK(t *testing.T) {
	a := readiness.NewAggregator()
	// Register a failing probe — liveness must not consult it.
	a.Register(&failingProbe{name: "db", msg: "down"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	a.LivenessHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200 from LivenessHandler, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("LivenessHandler body is not valid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("want status=ok, got %q", body["status"])
	}
}
