// Package contract — benchmark.go
//
// RunBenchmarks drives sustained and burst Get load against any SecretsBroker
// implementation, records per-call latencies, and writes a JSON result file.
// It is the canonical performance harness for the secrets-broker spec
// (Requirement 9 / NFR Performance).
//
// Usage in a provider _test.go:
//
//	func BenchmarkProvider(b *testing.B) {
//	    broker := newMyProvider(b) // real or emulated backend
//	    contract.RunBenchmarks(b, broker)
//	}
//
// The harness writes JSON results to the path given by the environment variable
// GIBSON_BENCH_OUTPUT when set, so CI scripts can ingest the numbers. When the
// env var is absent the results are only printed to b.Log.
//
// Spec: secrets-broker Requirements 9.1–9.4, NFR Performance.
package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// benchTenant is the tenant used across all benchmark calls. Using a fixed
// tenant avoids per-call allocation overhead interfering with measurements.
var benchTenant = auth.MustNewTenantID("bench-tenant")

// benchSecretName is the name of the pre-seeded secret read during benchmarks.
// It is written once in the setup phase before any timing window opens.
const benchSecretName = "bench-secret-value"

// BenchmarkResult holds the p50/p95/p99 latency histograms for one benchmark
// phase (sustained or burst) and the observed RPS.
type BenchmarkResult struct {
	// Phase is "sustained_100rps" or "burst_1000rps".
	Phase string `json:"phase"`
	// DurationSeconds is the wall-clock length of the measurement window.
	DurationSeconds float64 `json:"duration_seconds"`
	// RequestCount is the total number of Get calls dispatched.
	RequestCount int64 `json:"request_count"`
	// ErrorCount is the number of calls that returned a non-nil error.
	ErrorCount int64 `json:"error_count"`
	// ObservedRPS is RequestCount / DurationSeconds.
	ObservedRPS float64 `json:"observed_rps"`
	// P50Ms, P95Ms, P99Ms are per-call Get latencies in milliseconds.
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
}

// BenchmarkReport is the full JSON output written to GIBSON_BENCH_OUTPUT.
type BenchmarkReport struct {
	// Timestamp is the UTC time the report was produced.
	Timestamp string `json:"timestamp"`
	// Provider is the optional human-readable provider name, set via
	// GIBSON_BENCH_PROVIDER env var.
	Provider string `json:"provider,omitempty"`
	// Results contains one entry per phase.
	Results []BenchmarkResult `json:"results"`
}

// RunBenchmarks executes two load phases against b (the provided broker):
//
//  1. Sustained: 100 RPS Get for 60 seconds.
//  2. Burst:    1000 RPS Get for 60 seconds.
//
// It requires the broker to support Put (CanPut == true) so it can seed the
// test secret before measurements begin. When CanPut is false, the function
// skips seeding and attempts Get unconditionally — the caller is responsible
// for ensuring the named secret already exists.
//
// When the env var GIBSON_BENCH_OUTPUT is set to a non-empty path, the results
// are written as JSON to that file. Benchmark failures (e.g. the broker being
// unreachable) call b.Fatal.
func RunBenchmarks(b *testing.B, broker secrets.Broker) {
	b.Helper()

	// Seed the test secret once before any timing window.
	setupBenchSecret(b, broker)

	const (
		sustainedRPS = 100
		burstRPS     = 1000
		duration     = 60 * time.Second
	)

	results := make([]BenchmarkResult, 0, 2)

	r1 := runPhase(b, broker, "sustained_100rps", sustainedRPS, duration)
	results = append(results, r1)

	r2 := runPhase(b, broker, "burst_1000rps", burstRPS, duration)
	results = append(results, r2)

	report := BenchmarkReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Provider:  os.Getenv("GIBSON_BENCH_PROVIDER"),
		Results:   results,
	}

	reportJSON(b, report)
}

// setupBenchSecret puts the bench secret if the broker supports Put. On
// failure the benchmark is skipped because there is nothing to Get.
func setupBenchSecret(b *testing.B, broker secrets.Broker) {
	b.Helper()
	caps := broker.Capabilities()
	if !caps.CanPut {
		b.Log("RunBenchmarks: CanPut=false; skipping seed — secret must pre-exist")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := broker.Put(ctx, benchTenant, benchSecretName, []byte("bench-value-payload")); err != nil {
		b.Fatalf("RunBenchmarks: seed Put failed: %v", err)
	}
}

// runPhase runs a single load phase: targetRPS requests per second for the
// given duration. It uses a time.Ticker to pace calls across worker goroutines
// and collects per-call latency samples. The number of workers equals
// targetRPS so each worker fires at most once per second, avoiding per-worker
// coordination overhead while still achieving the aggregate target rate.
//
// For very high targetRPS (1000), each worker fires once per second in an
// N-worker pool. The ticker interval is set to 1s / targetRPS when targetRPS
// fits within a single worker rate, or to 1s with targetRPS workers each
// firing once per tick.
func runPhase(b *testing.B, broker secrets.Broker, phase string, targetRPS int, duration time.Duration) BenchmarkResult {
	b.Helper()
	b.Logf("RunBenchmarks: starting phase %s (%d RPS for %s)", phase, targetRPS, duration)

	// We model the rate as: targetRPS workers, each firing once per second,
	// paced by a shared ticker at interval = 1s. The ticker has a buffer of
	// targetRPS so no ticks are dropped at burst time.
	tickInterval := time.Second
	workers := targetRPS

	var (
		mu        sync.Mutex
		latencies []time.Duration
		errCount  int64
	)

	ctx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
	defer cancel()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	start := time.Now()
	deadline := start.Add(duration)

	var wg sync.WaitGroup

	// Semaphore limits concurrent in-flight calls to workers.
	sem := make(chan struct{}, workers)

	for !time.Now().After(deadline) {
		select {
		case <-ticker.C:
			// Dispatch `workers` concurrent Get calls on every tick.
			for range workers {
				if time.Now().After(deadline) {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
					defer callCancel()
					t0 := time.Now()
					_, err := broker.Get(callCtx, benchTenant, benchSecretName)
					lat := time.Since(t0)
					mu.Lock()
					latencies = append(latencies, lat)
					if err != nil {
						errCount++
					}
					mu.Unlock()
				}()
			}
		case <-ctx.Done():
			goto done
		}
	}
done:
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := int64(len(latencies))

	p50 := percentileMs(latencies, 0.50)
	p95 := percentileMs(latencies, 0.95)
	p99 := percentileMs(latencies, 0.99)

	rps := 0.0
	if elapsed.Seconds() > 0 {
		rps = float64(n) / elapsed.Seconds()
	}

	b.Logf("RunBenchmarks [%s]: requests=%d errors=%d p50=%.2fms p95=%.2fms p99=%.2fms rps=%.1f",
		phase, n, errCount, p50, p95, p99, rps)

	return BenchmarkResult{
		Phase:           phase,
		DurationSeconds: elapsed.Seconds(),
		RequestCount:    n,
		ErrorCount:      errCount,
		ObservedRPS:     rps,
		P50Ms:           p50,
		P95Ms:           p95,
		P99Ms:           p99,
	}
}

// percentileMs returns the p-th percentile (0.0–1.0) of latencies as
// milliseconds. latencies must be sorted ascending. Returns 0 when empty.
func percentileMs(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	// Nearest-rank: index = ceil(p * N) - 1, clamped.
	idx := int(p*float64(len(sorted)+1)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return float64(sorted[idx].Nanoseconds()) / 1e6
}

// reportJSON writes the BenchmarkReport as pretty-printed JSON. When
// GIBSON_BENCH_OUTPUT is set the JSON is also written to that file.
func reportJSON(b *testing.B, report BenchmarkReport) {
	b.Helper()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		b.Logf("RunBenchmarks: JSON marshal failed: %v", err)
		return
	}

	b.Logf("RunBenchmarks JSON report:\n%s", string(data))

	outPath := os.Getenv("GIBSON_BENCH_OUTPUT")
	if outPath == "" {
		return
	}
	if werr := os.WriteFile(outPath, data, 0o600); werr != nil {
		b.Logf("RunBenchmarks: write to GIBSON_BENCH_OUTPUT=%q failed: %v", outPath, werr)
		return
	}
	b.Logf("RunBenchmarks: results written to %s", outPath)
}

// RunBenchmarksWithDuration is like RunBenchmarks but accepts an explicit
// duration, enabling callers to run shorter warm-up phases or override the
// default 60-second window (e.g. for quick CI smoke runs via
// GIBSON_BENCH_DURATION). Provider benchmark test files should call this
// helper rather than duplicating the phase loop.
func RunBenchmarksWithDuration(b *testing.B, broker secrets.Broker, duration time.Duration) {
	b.Helper()
	setupBenchSecret(b, broker)

	results := make([]BenchmarkResult, 0, 2)
	results = append(results, runPhase(b, broker, "sustained_100rps", 100, duration))
	results = append(results, runPhase(b, broker, "burst_1000rps", 1000, duration))

	report := BenchmarkReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Provider:  os.Getenv("GIBSON_BENCH_PROVIDER"),
		Results:   results,
	}
	reportJSON(b, report)
}

// parseDurationEnv reads a Go duration string from the named env var and
// returns it. When the env var is unset or unparseable, def is returned.
func parseDurationEnv(env string, def time.Duration) time.Duration {
	v := os.Getenv(env)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parseDurationEnv: bad %s=%q: %v; using default %s\n", env, v, err, def)
		return def
	}
	return d
}
