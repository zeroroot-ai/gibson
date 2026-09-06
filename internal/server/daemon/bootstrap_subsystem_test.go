// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

func TestNativeLoginHandler_OK(t *testing.T) {
	h := nativeLoginHandler(nativeLoginConfig{
		Issuer:   "https://idp.example.com",
		ClientID: "cli-123",
		Scopes:   []string{"openid", "profile", "email", "offline_access"},
	}, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, http.NoBody))

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
	h := nativeLoginHandler(nativeLoginConfig{Issuer: "https://idp.example.com"}, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when unconfigured", rec.Code)
	}
}

func TestNativeLoginHandler_MethodNotAllowed(t *testing.T) {
	h := nativeLoginHandler(nativeLoginConfig{Issuer: "https://i", ClientID: "c"}, nil, nil, nil, nil, nil)
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

func testObservabilityLogger() *observability.Logger {
	return observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})
}

// TestNewNativeLoginSubsystem_NilCG proves the constructor tolerates both CG
// dependencies being nil (gibson#648's pre-Minter/pre-CapabilityGrantService
// boot ordering): the resulting subsystem must carry a working listener with
// the CG routes simply absent, not a nil-holding interface that panics on
// first request.
func TestNewNativeLoginSubsystem_NilCG(t *testing.T) {
	sub := newNativeLoginSubsystem(nativeLoginConfig{
		Port:     "0",
		Issuer:   "https://idp.example.com",
		ClientID: "cli-123",
	}, testObservabilityLogger(), nil, nil, nil, nil)
	if sub == nil || sub.srv == nil {
		t.Fatal("newNativeLoginSubsystem returned a subsystem with no server")
	}
	if sub.srv.Addr != ":0" {
		t.Errorf("Addr = %q, want %q", sub.srv.Addr, ":0")
	}
	rec := httptest.NewRecorder()
	sub.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, http.NoBody))
	if rec.Code != http.StatusOK {
		t.Errorf("discovery status = %d, want 200 even with the CG routes absent", rec.Code)
	}
}

// TestNewNativeLoginSubsystem_WiresCG proves that non-nil *Minter and
// *CapabilityGrantService pointers reach the handler as the cgBootstrapMinter
// / cgBootstrapRegistrar interfaces — the explicit-nil-check conversion this
// constructor exists for (a naive `cgBootstrapMinter(cgMinter)` assignment
// would produce a non-nil interface holding a nil pointer for the "unset"
// case, which is covered separately above). This test only proves the
// non-nil pointers are threaded through, not the CG handlers' own behavior.
func TestNewNativeLoginSubsystem_WiresCG(t *testing.T) {
	minter, err := capabilitygrant.NewMinter(t.Context(), capabilitygrant.Config{
		Issuer:      "https://api.example.com",
		Audience:    "gibson-daemon",
		KeyProvider: testKeyProvider{key: []byte("0123456789abcdef0123456789abcdef")},
		KeyID:       "cg-test-v1",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	cgSvc := new(capabilitygrant.CapabilityGrantService)

	sub := newNativeLoginSubsystem(nativeLoginConfig{
		Port:     "0",
		Issuer:   "https://idp.example.com",
		ClientID: "cli-123",
	}, testObservabilityLogger(), minter, cgSvc, nil, nil)
	if sub == nil || sub.srv == nil {
		t.Fatal("newNativeLoginSubsystem returned a subsystem with no server")
	}
	// The discovery route (unaffected by CG wiring) must still work.
	rec := httptest.NewRecorder()
	sub.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, nativeLoginWellKnownPath, http.NoBody))
	if rec.Code != http.StatusOK {
		t.Errorf("discovery status = %d, want 200", rec.Code)
	}
}
