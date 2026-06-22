package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeLoginHandler_OK(t *testing.T) {
	h := nativeLoginHandler(nativeLoginConfig{
		Issuer:   "https://idp.example.com",
		ClientID: "cli-123",
		Scopes:   []string{"openid", "profile", "email", "offline_access"},
	}, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var got nativeLoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Issuer != "https://idp.example.com" || got.ClientID != "cli-123" {
		t.Errorf("body = %+v, want issuer+client id echoed", got)
	}
	if len(got.Scopes) != 4 || got.Scopes[0] != "openid" {
		t.Errorf("scopes = %v, want the four configured scopes", got.Scopes)
	}
}

func TestNativeLoginHandler_Unconfigured503(t *testing.T) {
	// Missing client id → 503, not an unusable empty document.
	h := nativeLoginHandler(nativeLoginConfig{Issuer: "https://idp.example.com"}, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when unconfigured", rec.Code)
	}
}

func TestNativeLoginHandler_MethodNotAllowed(t *testing.T) {
	h := nativeLoginHandler(nativeLoginConfig{Issuer: "https://i", ClientID: "c"}, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, nativeLoginWellKnownPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 on POST", rec.Code)
	}
	if a := rec.Header().Get("Allow"); a != http.MethodGet {
		t.Errorf("Allow = %q, want GET", a)
	}
}

func TestNativeLoginConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv(envNativeLoginPort, "")
	t.Setenv(envNativeLoginScopes, "")
	t.Setenv(envIDPAdminIssuer, "https://idp.example.com")
	t.Setenv(envNativeLoginClientID, "cli-xyz")

	cfg := nativeLoginConfigFromEnv()
	if cfg.Port != defaultNativeLoginPort {
		t.Errorf("port = %q, want default %q", cfg.Port, defaultNativeLoginPort)
	}
	if cfg.Issuer != "https://idp.example.com" || cfg.ClientID != "cli-xyz" {
		t.Errorf("cfg = %+v, want issuer+client id from env", cfg)
	}
	if len(cfg.Scopes) != 4 {
		t.Errorf("scopes = %v, want 4 default scopes", cfg.Scopes)
	}
}
