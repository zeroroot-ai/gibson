//go:build integration_spire

package jwtsource

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSPIREJWTSource_Integration exercises NewSPIREJWTSource against a
// real SPIRE Workload API socket. Excluded from `make test-race` by the
// integration_spire build tag — operators run it ad-hoc to verify the
// path against a live cluster, e.g. after a kind bringup or a chart
// change.
//
// Run with:
//
//	go test -tags=integration_spire -run TestSPIREJWTSource_Integration \
//	    ./internal/platform/secrets/jwtsource/...
//
// The test reads the socket path from GIBSON_DAEMON_SPIRE_SOCKET (same
// env var the daemon honours in main.go); if unset, it falls back to
// DefaultSPIRESocketPath. The audience defaults to "platform-vault"
// (the GIBSON_DAEMON_VAULT_JWT_AUDIENCE value used in dev clusters);
// override via GIBSON_DAEMON_VAULT_JWT_AUDIENCE.
//
// The test fails-skip when no socket is reachable so it can also be
// invoked from a workstation with no SPIRE.
func TestSPIREJWTSource_Integration(t *testing.T) {
	socket := os.Getenv("GIBSON_DAEMON_SPIRE_SOCKET")
	if socket == "" {
		socket = DefaultSPIRESocketPath
	}
	audience := os.Getenv("GIBSON_DAEMON_VAULT_JWT_AUDIENCE")
	if audience == "" {
		audience = "platform-vault"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	src, err := NewSPIREJWTSource(ctx, socket)
	if err != nil {
		t.Skipf("NewSPIREJWTSource(%s): %v — re-run inside a pod with the spire-agent socket mounted", socket, err)
	}
	t.Cleanup(func() { _ = src.Close() })

	tok, err := src.Token(ctx, audience)
	if err != nil {
		t.Fatalf("Token(%q): %v", audience, err)
	}
	if tok == "" {
		t.Fatal("Token returned empty string with nil error")
	}
	// Sanity: a real JWT-SVID has at least two dots.
	dots := 0
	for _, r := range tok {
		if r == '.' {
			dots++
		}
	}
	if dots < 2 {
		t.Errorf("token does not look like a JWT (dots=%d): %q (length %d)", dots, tok[:min(16, len(tok))], len(tok))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
