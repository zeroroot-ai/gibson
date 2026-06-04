package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBootstrapHandler_OK(t *testing.T) {
	h := bootstrapHandler(bootstrapConfig{
		Issuer:      "https://idp.example.com",
		CLIClientID: "cli-123",
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bootstrapWellKnownPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var got bootstrapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Issuer != "https://idp.example.com" || got.CLIClientID != "cli-123" {
		t.Errorf("body = %+v, want issuer+client id echoed", got)
	}
	if len(got.Scopes) != 4 || got.Scopes[0] != "openid" {
		t.Errorf("scopes = %v, want the four configured scopes", got.Scopes)
	}
}

func TestBootstrapHandler_Unconfigured503(t *testing.T) {
	// Missing client id → 503, not an unusable empty document.
	h := bootstrapHandler(bootstrapConfig{Issuer: "https://idp.example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bootstrapWellKnownPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when unconfigured", rec.Code)
	}
}

func TestBootstrapHandler_MethodNotAllowed(t *testing.T) {
	h := bootstrapHandler(bootstrapConfig{Issuer: "https://i", CLIClientID: "c"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, bootstrapWellKnownPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 on POST", rec.Code)
	}
	if a := rec.Header().Get("Allow"); a != http.MethodGet {
		t.Errorf("Allow = %q, want GET", a)
	}
}

func TestBootstrapConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv(envBootstrapPort, "")
	t.Setenv(envCLIOIDCScopes, "")
	t.Setenv(envIDPAdminIssuer, "https://idp.example.com")
	t.Setenv(envCLIOIDCClientID, "cli-xyz")

	cfg := bootstrapConfigFromEnv()
	if cfg.Port != defaultBootstrapPort {
		t.Errorf("port = %q, want default %q", cfg.Port, defaultBootstrapPort)
	}
	if cfg.Issuer != "https://idp.example.com" || cfg.CLIClientID != "cli-xyz" {
		t.Errorf("cfg = %+v, want issuer+client id from env", cfg)
	}
	if len(cfg.Scopes) != 4 {
		t.Errorf("scopes = %v, want 4 default scopes", cfg.Scopes)
	}
}
