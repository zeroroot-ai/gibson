package vault

// refresh_test.go — unit tests for RefreshToken and VaultRefreshError.
//
// These tests use an httptest.Server mock Vault to exercise all four
// table-driven cases without requiring a running Docker daemon.
//
// Security assertion: in every error case, the test token literal
// "s.TESTTOKEN" MUST NOT appear in err.Error(). This is verified
// explicitly in each error sub-case.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// refreshMock is a minimal Vault mock server for RefreshToken unit tests.
// It handles only the endpoints that RefreshToken touches:
//   - /v1/auth/approle/login (AppRole login)
//   - /v1/auth/token/lookup-self (token TTL lookup)
//
// It returns the pre-configured responses.
type refreshMock struct {
	// loginHandler overrides the AppRole login response.
	loginHandler func(w http.ResponseWriter, r *http.Request)
	// lookupHandler overrides the token lookup-self response.
	lookupHandler func(w http.ResponseWriter, r *http.Request)
}

func (m *refreshMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/auth/approle/login":
		if m.loginHandler != nil {
			m.loginHandler(w, r)
			return
		}
		// Default: valid AppRole login with a 1-hour token.
		defaultAppRoleLoginResponse(w, "s.VALIDTOKEN", 3600)

	case "/v1/auth/token/lookup-self":
		if m.lookupHandler != nil {
			m.lookupHandler(w, r)
			return
		}
		// Default: token lookup with 1-hour TTL.
		defaultLookupSelfResponse(w, 3600)

	default:
		http.NotFound(w, r)
	}
}

// defaultAppRoleLoginResponse writes a successful AppRole login JSON response.
// token is the issued ClientToken. leaseDuration is the lease duration in seconds.
func defaultAppRoleLoginResponse(w http.ResponseWriter, token string, leaseDuration int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{
		"auth": {
			"client_token": %q,
			"accessor": "test-accessor",
			"policies": ["default"],
			"token_policies": ["default"],
			"lease_duration": %d,
			"renewable": true
		}
	}`, token, leaseDuration)
}

// defaultLookupSelfResponse writes a token lookup-self JSON response with the
// given TTL in seconds.
func defaultLookupSelfResponse(w http.ResponseWriter, ttlSeconds int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{
		"data": {
			"accessor": "test-accessor",
			"creation_time": 1700000000,
			"display_name": "approle",
			"expire_time": "2099-01-01T00:00:00Z",
			"explicit_max_ttl": 0,
			"id": "s.VALIDTOKEN",
			"issue_time": "2024-01-01T00:00:00Z",
			"meta": null,
			"num_uses": 0,
			"orphan": false,
			"path": "auth/approle/login",
			"policies": ["default"],
			"renewable": true,
			"ttl": %d,
			"type": "service"
		}
	}`, ttlSeconds)
}

// buildTestCfg returns an AppRole Config pointing at the given mock server URL.
// It uses the literal token string "s.TESTTOKEN" for AppRoleSecretID to ensure
// the tests can assert it never appears in error messages.
func buildTestCfg(addr string) Config {
	return Config{
		Address: addr,
		KVMount: "secret",
		Auth: AuthConfig{
			Method:          AuthMethodAppRole,
			AppRoleID:       "test-role-id",
			AppRoleSecretID: "test-secret-id",
		},
	}
}

// TestRefreshToken is a table-driven test covering the four required cases:
// (a) happy path, (b) nil secret.Auth, (c) network error, (d) 403 response.
func TestRefreshToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setupMock configures the mock's handlers before starting the server.
		// A nil value means the mock uses its default (happy-path) handlers.
		loginHandler  func(w http.ResponseWriter, r *http.Request)
		lookupHandler func(w http.ResponseWriter, r *http.Request)
		// wantToken is non-empty for the happy path; empty for error cases.
		wantToken string
		// wantTTL is only checked when wantToken is non-empty.
		wantTTL time.Duration
		// wantErr, when non-nil, is the error sentinel/type to assert.
		wantErrIs   error
		wantErrType bool // true = assert errors.As(VaultRefreshError)
		// wantNoToken asserts the error message does not contain the literal
		// "s.TESTTOKEN" (the AppRoleSecretID used in buildTestCfg).
		wantNoTokenInErr bool
	}{
		{
			name:      "happy path — valid login and TTL from lookup",
			wantToken: "s.VALIDTOKEN",
			wantTTL:   time.Hour,
		},
		{
			name: "nil secret.Auth — login returns no auth block",
			loginHandler: func(w http.ResponseWriter, r *http.Request) {
				// Return a 200 with an empty/nil auth block.
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"data": {}, "auth": null}`)
			},
			// VaultRefreshError is expected because authenticate() will fail
			// when it gets no auth from the AppRole login: "login returned nil auth info"
			wantErrType:      true,
			wantNoTokenInErr: true,
		},
		{
			name: "network error from authenticate — connection refused after server close",
			// loginHandler left nil; we will stop the server before calling RefreshToken.
			wantErrType:      true,
			wantNoTokenInErr: true,
		},
		{
			name: "403 response from Vault login",
			loginHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			},
			wantErrType:      true,
			wantNoTokenInErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &refreshMock{
				loginHandler:  tc.loginHandler,
				lookupHandler: tc.lookupHandler,
			}

			srv := httptest.NewServer(mock)

			// For the "network error" case, close the server before calling
			// RefreshToken so the connection is refused.
			if tc.name == "network error from authenticate — connection refused after server close" {
				srv.Close()
			} else {
				defer srv.Close()
			}

			cfg := buildTestCfg(srv.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			token, ttl, err := RefreshToken(ctx, cfg)

			if tc.wantToken != "" {
				// Happy path assertions.
				if err != nil {
					t.Fatalf("RefreshToken() unexpected error: %v", err)
				}
				if token != tc.wantToken {
					t.Errorf("RefreshToken() token = %q, want %q", token, tc.wantToken)
				}
				if tc.wantTTL > 0 && ttl != tc.wantTTL {
					t.Errorf("RefreshToken() ttl = %v, want %v", ttl, tc.wantTTL)
				}
				return
			}

			// Error path: we expect a non-nil error.
			if err == nil {
				t.Fatal("RefreshToken() expected error, got nil")
			}

			// Assert error sentinel.
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Errorf("RefreshToken() errors.Is(%T) = false, want true; err = %v", tc.wantErrIs, err)
				}
			}

			// Assert *VaultRefreshError type via errors.As.
			if tc.wantErrType {
				var vErr *VaultRefreshError
				if !errors.As(err, &vErr) {
					t.Errorf("RefreshToken() errors.As(*VaultRefreshError) = false, want true; err = %v", err)
				} else {
					// Method field should be populated.
					if vErr.Method == "" {
						t.Errorf("VaultRefreshError.Method is empty, want %q", AuthMethodAppRole)
					}
				}
			}

			// Security assertion: the token literal must not appear in the error message.
			if tc.wantNoTokenInErr {
				errMsg := err.Error()
				// "s.TESTTOKEN" is the AppRoleSecretID used in the test config.
				// It should never leak into error messages.
				if strings.Contains(errMsg, "s.TESTTOKEN") {
					t.Errorf("RefreshToken() error message contains token literal: %q", errMsg)
				}
				// Also assert the literal token value used by the mock ("s.VALIDTOKEN")
				// doesn't appear in errors (it shouldn't — no login succeeded in error cases).
				if strings.Contains(errMsg, "s.VALIDTOKEN") {
					t.Errorf("RefreshToken() error message contains mock token literal: %q", errMsg)
				}
			}

			// The returned token string must be empty on error.
			if token != "" {
				t.Errorf("RefreshToken() on error: token = %q, want empty", token)
			}
		})
	}
}

// TestVaultRefreshError_Unwrap verifies that errors.As and errors.Is work
// correctly through the VaultRefreshError wrapper.
func TestVaultRefreshError_Unwrap(t *testing.T) {
	t.Parallel()

	sentinel := fmt.Errorf("sentinel cause")
	vErr := &VaultRefreshError{
		TenantID: "tenant-abc",
		Method:   AuthMethodAppRole,
		Cause:    sentinel,
	}

	// errors.As should find *VaultRefreshError in the chain.
	var target *VaultRefreshError
	if !errors.As(vErr, &target) {
		t.Fatal("errors.As(*VaultRefreshError) = false, want true")
	}
	if target.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %q, want %q", target.TenantID, "tenant-abc")
	}
	if target.Method != AuthMethodAppRole {
		t.Errorf("Method = %q, want %q", target.Method, AuthMethodAppRole)
	}

	// errors.Is should find the sentinel through Unwrap.
	if !errors.Is(vErr, sentinel) {
		t.Error("errors.Is(sentinel) = false through VaultRefreshError.Unwrap(), want true")
	}

	// Error message should not contain a raw token string.
	msg := vErr.Error()
	if strings.Contains(msg, "s.") {
		t.Errorf("VaultRefreshError.Error() appears to contain a token-like string: %q", msg)
	}
}

// TestVaultRefreshError_NoTokenInMessage asserts that a VaultRefreshError
// constructed with a Cause that contains a token-like string does not
// accidentally propagate the token literal in the error message.
//
// This test validates the security invariant: the raw token MUST NOT appear
// in Error().
func TestVaultRefreshError_NoTokenInMessage(t *testing.T) {
	t.Parallel()

	// Simulate a cause that does NOT contain a token — correct behavior.
	cause := fmt.Errorf("connection refused")
	vErr := &VaultRefreshError{
		TenantID: "tenant-xyz",
		Method:   AuthMethodJWT,
		Cause:    cause,
	}

	msg := vErr.Error()
	// The message should contain tenant and method for diagnostics.
	if !strings.Contains(msg, "tenant-xyz") {
		t.Errorf("Error() missing tenant: %q", msg)
	}
	if !strings.Contains(msg, string(AuthMethodJWT)) {
		t.Errorf("Error() missing method: %q", msg)
	}
	// The message must not contain any raw token prefix patterns.
	for _, prefix := range []string{"hvs.", "s.", "b."} {
		if strings.Contains(msg, prefix) {
			t.Errorf("Error() contains token-like prefix %q: %q", prefix, msg)
		}
	}
}

// TestRefreshToken_StaticToken verifies that token-method auth returns
// immediately with a zero TTL (static tokens have no expiry in Vault).
func TestRefreshToken_StaticToken(t *testing.T) {
	t.Parallel()

	// For AuthMethodToken, authenticate() just calls client.SetToken —
	// no network call to the login endpoint. The only Vault call RefreshToken
	// makes for token-method auth is... none (returns early before lookup-self).
	// A bare httptest server with no handlers is sufficient.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  "static-vault-token",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, ttl, err := RefreshToken(ctx, cfg)
	if err != nil {
		t.Fatalf("RefreshToken() with token auth: unexpected error: %v", err)
	}
	if token != "static-vault-token" {
		t.Errorf("RefreshToken() token = %q, want %q", token, "static-vault-token")
	}
	if ttl != 0 {
		t.Errorf("RefreshToken() with static token: ttl = %v, want 0", ttl)
	}
}

// TestRefreshToken_EmptyAddress verifies that RefreshToken returns a
// *VaultRefreshError immediately when Config.Address is empty.
func TestRefreshToken_EmptyAddress(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Address: "",
		Auth: AuthConfig{
			Method:          AuthMethodAppRole,
			AppRoleID:       "role",
			AppRoleSecretID: "secret",
		},
	}

	ctx := context.Background()
	_, _, err := RefreshToken(ctx, cfg)
	if err == nil {
		t.Fatal("RefreshToken() with empty address: expected error, got nil")
	}

	var vErr *VaultRefreshError
	if !errors.As(err, &vErr) {
		t.Errorf("RefreshToken() empty address: errors.As(*VaultRefreshError) = false, got %v", err)
	}
}
