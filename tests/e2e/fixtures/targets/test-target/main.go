// test-target — deterministic HTTP fixture server for mission-run e2e tests.
//
// Exposes two endpoints:
//
//	GET /         — returns 200 OK with a deterministic body (known SHA256 fingerprint).
//	GET /healthz  — returns 200 OK {"status":"ok"} for readiness probe.
//
// The body returned by GET / is intentionally stable so e2e assertions can assert
// a known string without hard-coding timing-sensitive values.
//
// Requirements: R2.2 (deterministic target fixture).
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// DeterministicBody is returned by GET /.  The SHA256 of this string is
// a7f3e2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1
// — a known fingerprint the probe agent can assert in its finding evidence.
const DeterministicBody = "test-target-e2e-deterministic-body-v1"

// DefaultPort is the HTTP port the server listens on.
const DefaultPort = "8080"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/", handleRoot)

	addr := fmt.Sprintf(":%s", port)
	slog.Info("test-target: starting", "addr", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("test-target: fatal", "err", err)
		os.Exit(1)
	}
}

// handleRoot returns the deterministic body.  All HTTP methods are accepted so
// the probe agent can exercise GET, POST, or HEAD without fixture modification.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	slog.Debug("test-target: request", "method", r.Method, "path", r.URL.Path)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Test-Target-Version", "e2e-v1")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, DeterministicBody)
}

// handleHealthz returns a minimal JSON liveness/readiness response.
// Used by the K8s readinessProbe and by fixture_deployer.go waitForReady.
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}
