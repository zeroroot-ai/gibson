// Package readiness provides an HTTP readiness/liveness probe aggregator for
// platform services. It is NOT customer-facing; do not import it from any
// package under opensource/.
package readiness

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"golang.org/x/sync/singleflight"
)

// Probe is implemented by any dependency that can report its own health.
// Name must be stable across calls and unique within an Aggregator.
// Check returns nil when the dependency is ready, or a descriptive error
// when it is not.
type Probe interface {
	Name() string
	Check(ctx context.Context) error
}

// probeResult is the per-probe outcome included in the /readyz JSON body.
type probeResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// readyzResponse is the top-level JSON body returned by ReadyHandler.
type readyzResponse struct {
	Status string        `json:"status"`
	Probes []probeResult `json:"probes"`
}

// Aggregator collects Probes and exposes /readyz and /healthz HTTP handlers.
// The zero value is not usable; construct with NewAggregator.
type Aggregator struct {
	mu     sync.RWMutex
	probes []Probe
	sf     singleflight.Group
}

// NewAggregator returns an initialised, empty Aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// Register adds p to the set of probes evaluated on every /readyz request.
// Register is safe for concurrent use but should typically be called during
// service initialisation, before the HTTP server starts accepting traffic.
func (a *Aggregator) Register(p Probe) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.probes = append(a.probes, p)
}

// ReadyHandler returns an http.Handler that evaluates all registered probes
// concurrently on each request. Concurrent requests are collapsed via
// singleflight so probe work is never duplicated under burst traffic.
//
// Response codes:
//   - 200 OK    — all probes passed (or no probes are registered).
//   - 503 Service Unavailable — one or more probes failed.
//
// The JSON body always lists every probe with its name, status ("pass"/"fail"),
// and the error message for failing probes.
func (a *Aggregator) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Collapse concurrent requests into a single probe run.
		v, _, _ := a.sf.Do("readyz", func() (any, error) { //nolint:contextcheck // singleflight.Group.Do has a fixed func() signature; context is captured from the handler closure
			return a.runProbes(r.Context()), nil
		})
		resp := v.(readyzResponse)

		w.Header().Set("Content-Type", "application/json")
		if resp.Status != "pass" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// LivenessHandler returns an http.Handler that always responds 200 OK with
// {"status":"ok"}. It signals that the process is alive and the runtime is
// not deadlocked; it does NOT check dependency health.
func (a *Aggregator) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
}

// runProbes executes all registered probes concurrently and aggregates results.
// It returns as soon as every probe has reported; the context passed to each
// probe is the one that arrived with the HTTP request.
func (a *Aggregator) runProbes(ctx context.Context) readyzResponse {
	a.mu.RLock()
	probes := make([]Probe, len(a.probes))
	copy(probes, a.probes)
	a.mu.RUnlock()

	if len(probes) == 0 {
		return readyzResponse{
			Status: "pass",
			Probes: []probeResult{},
		}
	}

	results := make([]probeResult, len(probes))
	var wg sync.WaitGroup
	wg.Add(len(probes))

	for i, p := range probes {
		go func() {
			defer wg.Done()
			err := p.Check(ctx)
			pr := probeResult{Name: p.Name(), Status: "pass"}
			if err != nil {
				pr.Status = "fail"
				pr.Error = err.Error()
			}
			results[i] = pr
		}()
	}

	wg.Wait()

	overall := "pass"
	for _, r := range results {
		if r.Status == "fail" {
			overall = "fail"
			break
		}
	}

	return readyzResponse{
		Status: overall,
		Probes: results,
	}
}
