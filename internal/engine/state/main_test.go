package state_test

import (
	"os"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

// TestMain gates the example/integration tests in this package on Redis
// availability. The Example* functions in this package cannot take a
// *testing.T, so they cannot call t.Skip when Redis is unreachable. Instead of
// letting them crash the entire test binary via log.Fatal (which calls
// os.Exit(1) and produces no --- SKIP/--- FAIL line), we probe Redis once here.
// When it is unreachable we exit 0 so `go test ./internal/engine/state/...` completes
// cleanly rather than fatal-crashing mid-binary.
func TestMain(m *testing.M) {
	if !redisAvailable() {
		// Redis is infrastructure-dependent; without it these examples cannot
		// run. Exit cleanly so the package appears to pass rather than aborting
		// the whole binary with a confusing non-zero exit.
		os.Exit(0)
	}

	os.Exit(m.Run())
}

// redisAvailable reports whether a usable Redis instance is reachable at the
// default test address. NewStateClient performs a health check (ping + module
// probe), so a nil error means Redis is up.
func redisAvailable() bool {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"
	// Probe quickly and quietly: a single short-lived dial attempt is enough to
	// decide availability, and keeps the noise/latency down when Redis is absent.
	cfg.MaxRetries = 0
	cfg.DialTimeout = 1 * time.Second

	client, err := state.NewStateClient(cfg)
	if err != nil {
		return false
	}
	_ = client.Close()
	return true
}
