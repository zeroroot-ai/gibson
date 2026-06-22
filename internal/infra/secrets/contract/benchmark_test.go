package contract

import (
	"testing"
	"time"
)

// BenchmarkBrokerInMemory runs the full RunBenchmarks harness against the
// in-memory broker. It serves as a compile-time and runtime smoke test: any
// test infrastructure that compiles and runs this benchmark validates the
// harness structure end-to-end without a real backend.
//
// Because the in-memory broker has sub-microsecond Get latency the RPS targets
// are trivially achieved; this test only validates harness correctness, not
// real-provider performance.
//
// Override the per-phase duration via GIBSON_BENCH_DURATION (e.g. "3s") to
// keep CI runs fast:
//
//	GIBSON_BENCH_DURATION=3s go test -bench=BenchmarkBrokerInMemory -benchtime=1x ./secrets/contract/...
func BenchmarkBrokerInMemory(b *testing.B) {
	broker := NewInMemoryBroker()
	duration := parseDurationEnv("GIBSON_BENCH_DURATION", 5*time.Second)
	RunBenchmarksWithDuration(b, broker, duration)
}
