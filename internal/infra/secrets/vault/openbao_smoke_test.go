//go:build openbao_smoke
// +build openbao_smoke

// Package vault — openbao_smoke_test.go
//
// Slice 2 of the OpenBao migration (PRD deploy#431, ADR-0024).
//
// This is the minimal CI primitive that proves OpenBao 2.5.x can be
// stood up as a test service. It does NOT exercise the SDK's provider
// surface — that's slice 3's job (openbao_integration_test.go).
//
// The smoke test:
//   - Starts an openbao/openbao container in dev mode via testcontainers-go.
//   - Waits for the server's "==> OpenBao server started!" log line and
//     for the listening port to be reachable.
//   - Hits /v1/sys/health and asserts a 200-class response with a
//     "version" field that matches the pinned OpenBao image tag.
//
// Run locally with:
//
//	go test -tags openbao_smoke ./secrets/providers/vault/...
//
// CI: gated by the `openbao-smoke` job in .github/workflows/ci.yaml.
//
// Skipped gracefully when Docker is unavailable, matching the existing
// integration_test.go pattern.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Constants moved to openbao_testconsts_test.go so they're shared
// between this smoke suite (slice 2) and the openbao_integration
// compat suite (slice 3 / sdk#90).

// TestOpenBaoSmoke_Health stands up an OpenBao dev-mode container and
// verifies the basic API surface is reachable. This is the CI primitive
// that slice 3's compat suite (and slice 5's operator integration test)
// will reuse.
//
// On failure modes worth a clear diagnostic:
//
//   - Docker unavailable → t.Skip (matches existing integration_test.go).
//   - Image pull failure → testcontainers surfaces the error verbatim;
//     usually means CI runner has no network egress to ghcr.io or the
//     image tag was retracted.
//   - Container starts but log line never appears within
//     wait-for-log timeout → likely upstream behavior change in
//     OpenBao's startup banner. Update the wait condition AND the
//     openbaoImage pin together.
//   - /v1/sys/health returns non-2xx OR version field mismatch → the
//     pinned image isn't what we asserted; bump openbaoExpectedVersion
//     intentionally rather than relaxing the assertion.
func TestOpenBaoSmoke_Health(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping OpenBao smoke test: %v", err)
		return
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping OpenBao smoke test: %v", healthErr)
		return
	}

	req := testcontainers.ContainerRequest{
		Image: openbaoImage,
		Env: map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID":  openbaoDevRootToken,
			"BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
			"SKIP_SETCAP":            "true",
			"BAO_LOG_LEVEL":          "info",
		},
		ExposedPorts: []string{"8200/tcp"},
		Cmd:          []string{"server", "-dev"},
		WaitingFor: wait.ForAll(
			wait.ForLog("==> OpenBao server started!").WithStartupTimeout(60*time.Second),
			wait.ForListeningPort("8200/tcp").WithStartupTimeout(60*time.Second),
		),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start OpenBao container")

	t.Cleanup(func() {
		if termErr := c.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate OpenBao container: %v", termErr)
		}
	})

	host, err := c.Host(ctx)
	require.NoError(t, err, "resolve OpenBao container host")
	mappedPort, err := c.MappedPort(ctx, "8200")
	require.NoError(t, err, "resolve OpenBao container mapped port")

	addr := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	// Give the server a moment to fully initialise after TCP is up.
	time.Sleep(500 * time.Millisecond)

	healthURL := addr + "/v1/sys/health"
	httpClient := &http.Client{Timeout: 10 * time.Second}

	resp, err := httpClient.Get(healthURL)
	require.NoError(t, err, "GET %s", healthURL)
	defer func() { _ = resp.Body.Close() }()

	// OpenBao returns 200 for an initialized, unsealed, active node;
	// dev mode satisfies all three. Treat any 2xx as success; emit a
	// clear diagnostic for 5xx (server error) or anything else.
	require.GreaterOrEqual(t, resp.StatusCode, 200, "/v1/sys/health status code")
	require.Less(t, resp.StatusCode, 300, "/v1/sys/health status code (got %d)", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read /v1/sys/health body")

	var health struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Standby     bool   `json:"standby"`
		Version     string `json:"version"`
	}
	require.NoError(t, json.Unmarshal(body, &health), "parse /v1/sys/health JSON: %s", string(body))

	require.True(t, health.Initialized, "OpenBao reports not initialized")
	require.False(t, health.Sealed, "OpenBao reports sealed")
	require.False(t, health.Standby, "OpenBao reports standby (dev mode should be active)")
	require.True(t,
		strings.HasPrefix(health.Version, openbaoExpectedVersion),
		"OpenBao version: got %q, want prefix %q (image pin: %s)",
		health.Version, openbaoExpectedVersion, openbaoImage,
	)
}
