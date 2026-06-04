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

// gibson#623 — unauthenticated native-login bootstrap endpoint.
//
// Interactive end-user login from a public/native client (`gibson login`, and
// any future desktop/TUI/IDE client) runs an OAuth2 device-authorization grant.
// Before it can do that it needs three non-secret values: the OIDC issuer, the
// public client id registered for native login, and the scopes to request. The
// client has no credentials yet, so the endpoint is deliberately
// unauthenticated. Envoy publishes it on a public route and ext-authz
// allowlists it (no JWT requirement).
//
// It cannot be served by the SDK health server (not extensible) nor by an Envoy
// direct_response (the client id is minted at runtime into the
// gibson-native-login-oidc secret and mounted as an env var — Envoy can't read
// it). So the daemon owns a tiny dedicated HTTP listener for it.
const (
	// envNativeLoginPort overrides the listener port; default below.
	envNativeLoginPort = "GIBSON_NATIVE_LOGIN_PORT"
	// envNativeLoginClientID is the public OIDC client id registered for the
	// native-login device-grant app, mounted from the gibson-native-login-oidc
	// secret.
	envNativeLoginClientID = "GIBSON_NATIVE_LOGIN_CLIENT_ID"
	// envNativeLoginScopes optionally overrides the space-separated scope list.
	envNativeLoginScopes = "GIBSON_NATIVE_LOGIN_SCOPES"

	defaultNativeLoginPort   = "8085"
	defaultNativeLoginScopes = "openid profile email offline_access"
	nativeLoginWellKnownPath = "/.well-known/gibson-login"
)

// nativeLoginConfig is the static configuration the bootstrap endpoint serves.
type nativeLoginConfig struct {
	Port     string
	Issuer   string
	ClientID string
	Scopes   []string
	// PublicURL is the daemon's public base URL (GIBSON_PUBLIC_URL). It is the
	// base for the Capability-Grant discovery document's absolute endpoint URLs
	// (gibson#648), also served on this pre-auth listener.
	PublicURL string
}

// nativeLoginConfigFromEnv assembles the config from the daemon's environment.
// Issuer reuses the daemon's configured IdP issuer so the client and the daemon
// agree on the authority.
func nativeLoginConfigFromEnv() nativeLoginConfig {
	port := os.Getenv(envNativeLoginPort)
	if port == "" {
		port = defaultNativeLoginPort
	}
	scopesRaw := os.Getenv(envNativeLoginScopes)
	if scopesRaw == "" {
		scopesRaw = defaultNativeLoginScopes
	}
	return nativeLoginConfig{
		Port:      port,
		Issuer:    os.Getenv(envIDPAdminIssuer),
		ClientID:  os.Getenv(envNativeLoginClientID),
		Scopes:    strings.Fields(scopesRaw),
		PublicURL: os.Getenv("GIBSON_PUBLIC_URL"),
	}
}

// nativeLoginResponse is the JSON body returned to the client.
type nativeLoginResponse struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// nativeLoginHandler returns the HTTP handler for the well-known endpoint. It is
// split from the listener so it can be tested with httptest directly.
func nativeLoginHandler(cfg nativeLoginConfig) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(nativeLoginWellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A bootstrap config missing the issuer or client id is useless to the
		// client; fail loud so misconfiguration is obvious rather than handing
		// back an unusable empty document.
		if cfg.Issuer == "" || cfg.ClientID == "" {
			http.Error(w, "native login not configured", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(nativeLoginResponse{
			Issuer:   cfg.Issuer,
			ClientID: cfg.ClientID,
			Scopes:   cfg.Scopes,
		})
	})
	// Capability-Grant registration discovery (gibson#648) — served on the same
	// pre-auth listener; a component holds no Capability Grant yet at discovery
	// time. Envoy publishes it on an allow_missing route alongside gibson-login.
	mux.HandleFunc(agentConfigWellKnownPath, agentConfigHandler(cfg.PublicURL))
	return mux
}

// nativeLoginSubsystem owns the lifecycle of the unauthenticated native-login
// bootstrap HTTP listener. Its Serve(ctx) signature matches the other daemon
// subsystems for uniform goroutine launch.
type nativeLoginSubsystem struct {
	srv    *http.Server
	logger *observability.Logger
}

// newNativeLoginSubsystem builds the subsystem from the given config.
func newNativeLoginSubsystem(cfg nativeLoginConfig, logger *observability.Logger) *nativeLoginSubsystem {
	return &nativeLoginSubsystem{
		srv: &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           nativeLoginHandler(cfg),
			ReadHeaderTimeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// Serve starts the listener and blocks until ctx is cancelled, then performs a
// graceful stop. Failure is non-fatal (logged), mirroring the health subsystem:
// the bootstrap endpoint being down must never take the daemon down.
func (b *nativeLoginSubsystem) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := b.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	b.logger.Info(ctx, "native-login bootstrap server started", "addr", b.srv.Addr, "path", nativeLoginWellKnownPath)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		b.logger.Warn(ctx, "native-login bootstrap server failed (non-fatal)", "error", err)
		return nil
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.srv.Shutdown(stopCtx); err != nil {
		b.logger.Warn(ctx, "error stopping native-login bootstrap server", "error", err)
	}
	return nil
}
