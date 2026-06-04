package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/observability"
)

// gibson#623 — unauthenticated CLI bootstrap endpoint.
//
// `gibson login` needs three values before it can run a device-authorization
// grant: the OIDC issuer, the public client id minted for the CLI app, and the
// scopes to request. None of these are secret, and the CLI has no credentials
// yet, so the endpoint is deliberately unauthenticated. Envoy publishes it on a
// public route and ext-authz allowlists it (no JWT requirement).
//
// It cannot be served by the SDK health server (not extensible) nor by an Envoy
// direct_response (the cli_client_id is minted at runtime into the
// gibson-cli-oidc secret and mounted as an env var — Envoy can't read it). So
// the daemon owns a tiny dedicated HTTP listener for it.
const (
	// envBootstrapPort overrides the listener port; default below.
	envBootstrapPort = "GIBSON_BOOTSTRAP_PORT"
	// envCLIOIDCClientID is the public OIDC client id minted for the gibson-cli
	// device-grant app, mounted from the gibson-cli-oidc secret.
	envCLIOIDCClientID = "GIBSON_CLI_OIDC_CLIENT_ID"
	// envCLIOIDCScopes optionally overrides the space-separated scope list.
	envCLIOIDCScopes = "GIBSON_CLI_OIDC_SCOPES"

	defaultBootstrapPort   = "8085"
	defaultCLIOIDCScopes   = "openid profile email offline_access"
	bootstrapWellKnownPath = "/.well-known/gibson-cli"
)

// bootstrapConfig is the static configuration the CLI bootstrap endpoint serves.
type bootstrapConfig struct {
	Port        string
	Issuer      string
	CLIClientID string
	Scopes      []string
}

// bootstrapConfigFromEnv assembles the bootstrap config from the daemon's
// environment. Issuer reuses the daemon's configured IdP issuer so the CLI and
// the daemon agree on the authority.
func bootstrapConfigFromEnv() bootstrapConfig {
	port := os.Getenv(envBootstrapPort)
	if port == "" {
		port = defaultBootstrapPort
	}
	scopesRaw := os.Getenv(envCLIOIDCScopes)
	if scopesRaw == "" {
		scopesRaw = defaultCLIOIDCScopes
	}
	return bootstrapConfig{
		Port:        port,
		Issuer:      os.Getenv(envIDPAdminIssuer),
		CLIClientID: os.Getenv(envCLIOIDCClientID),
		Scopes:      strings.Fields(scopesRaw),
	}
}

// bootstrapResponse is the JSON body returned to the CLI.
type bootstrapResponse struct {
	Issuer      string   `json:"issuer"`
	CLIClientID string   `json:"cli_client_id"`
	Scopes      []string `json:"scopes"`
}

// bootstrapHandler returns the HTTP handler for the well-known endpoint. It is
// split from the listener so it can be tested with httptest directly.
func bootstrapHandler(cfg bootstrapConfig) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(bootstrapWellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A bootstrap config missing the issuer or client id is useless to the
		// CLI; fail loud so misconfiguration is obvious rather than handing back
		// an unusable empty document.
		if cfg.Issuer == "" || cfg.CLIClientID == "" {
			http.Error(w, "cli bootstrap not configured", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(bootstrapResponse{
			Issuer:      cfg.Issuer,
			CLIClientID: cfg.CLIClientID,
			Scopes:      cfg.Scopes,
		})
	})
	return mux
}

// bootstrapSubsystem owns the lifecycle of the unauthenticated CLI bootstrap
// HTTP listener. Its Serve(ctx) signature matches the other daemon subsystems
// for uniform goroutine launch.
type bootstrapSubsystem struct {
	srv    *http.Server
	logger *observability.Logger
}

// newBootstrapSubsystem builds the subsystem from the given config.
func newBootstrapSubsystem(cfg bootstrapConfig, logger *observability.Logger) *bootstrapSubsystem {
	return &bootstrapSubsystem{
		srv: &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           bootstrapHandler(cfg),
			ReadHeaderTimeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// Serve starts the listener and blocks until ctx is cancelled, then performs a
// graceful stop. Failure is non-fatal (logged), mirroring the health subsystem:
// the CLI bootstrap endpoint being down must never take the daemon down.
func (b *bootstrapSubsystem) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := b.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	b.logger.Info(ctx, "cli bootstrap server started", "addr", b.srv.Addr, "path", bootstrapWellKnownPath)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		b.logger.Warn(ctx, "cli bootstrap server failed (non-fatal)", "error", err)
		return nil
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.srv.Shutdown(stopCtx); err != nil {
		b.logger.Warn(ctx, "error stopping cli bootstrap server", "error", err)
	}
	return nil
}
