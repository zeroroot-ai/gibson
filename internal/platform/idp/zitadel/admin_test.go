package zitadel_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// setupServer returns a test server that serves OIDC discovery plus an OAuth2
// token endpoint, and routes management API calls to the provided handler.
// We use a closure over srvURL so the discovery doc can embed the server URL.
func setupServer(t *testing.T, managementHandler http.HandlerFunc) (*httptest.Server, zitadel.Config) {
	t.Helper()

	var srvURL string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			doc := map[string]string{
				"token_endpoint": srvURL + "/oauth/v2/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)

		case r.URL.Path == "/oauth/v2/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-admin-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		case strings.HasPrefix(r.URL.Path, "/management/"):
			managementHandler(w, r)

		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(handler)
	srvURL = srv.URL

	cfg := zitadel.Config{
		Issuer:       srv.URL,
		ClientID:     "admin-client",
		ClientSecret: "admin-secret",
		OrgID:        "org-123",
	}

	t.Cleanup(srv.Close)
	return srv, cfg
}

// jsonResp is a helper to write a JSON response.
func jsonResp(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// errorResp writes a Zitadel-style error envelope.
func errorResp(w http.ResponseWriter, status int, code, message string) {
	jsonResp(w, status, map[string]interface{}{
		"code":    status,
		"message": message,
		"details": []map[string]string{{"errorCode": code}},
	})
}

// ---------------------------------------------------------------------------
// CreateServiceAccount tests
// ---------------------------------------------------------------------------

func TestCreateServiceAccount_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/users/machine") {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{"userId": "user-abc"})
	})

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	sa, err := client.CreateServiceAccount(context.Background(), idp.CreateServiceAccountRequest{
		Name: "agent-acme-redteam",
		Role: idp.RoleAgent,
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if sa.AccountID != "user-abc" {
		t.Errorf("AccountID = %q, want %q", sa.AccountID, "user-abc")
	}
}

func TestCreateServiceAccount_Conflict(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusConflict, "ALREADY_EXISTS", "machine user already exists")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.CreateServiceAccount(context.Background(), idp.CreateServiceAccountRequest{Name: "agent-dup"})
	if !errors.Is(err, idp.ErrAlreadyExists) {
		t.Errorf("want ErrAlreadyExists, got: %v", err)
	}
}

func TestCreateServiceAccount_Upstream5xx(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusInternalServerError, "INTERNAL", "database error")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.CreateServiceAccount(context.Background(), idp.CreateServiceAccountRequest{Name: "agent-err"})
	if !errors.Is(err, idp.ErrUpstream) {
		t.Errorf("want ErrUpstream, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteServiceAccount tests
// ---------------------------------------------------------------------------

func TestDeleteServiceAccount_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if err := client.DeleteServiceAccount(context.Background(), "user-abc"); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
}

func TestDeleteServiceAccount_NotFound(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusNotFound, "NOT_FOUND", "user not found")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	delErr := client.DeleteServiceAccount(context.Background(), "missing")
	if !errors.Is(delErr, idp.ErrNotFound) {
		t.Errorf("want ErrNotFound, got: %v", delErr)
	}
}

// ---------------------------------------------------------------------------
// ListServiceAccounts tests
// ---------------------------------------------------------------------------

func TestListServiceAccounts_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"result": []map[string]interface{}{
				{
					"userId":       "user-1",
					"userName":     "agent-acme-redteam",
					"creationDate": "2026-01-01T00:00:00Z",
					"machine": map[string]string{
						"name":        "agent-acme-redteam",
						"description": "Red team agent",
					},
				},
			},
		})
	})

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	resp, err := client.ListServiceAccounts(context.Background(), idp.ListServiceAccountsRequest{
		TenantScopeID: "proj-456",
		PageSize:      50,
	})
	if err != nil {
		t.Fatalf("ListServiceAccounts: %v", err)
	}
	if len(resp.ServiceAccounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(resp.ServiceAccounts))
	}
	if resp.ServiceAccounts[0].AccountID != "user-1" {
		t.Errorf("AccountID = %q, want %q", resp.ServiceAccounts[0].AccountID, "user-1")
	}
	if resp.ServiceAccounts[0].Role != idp.RoleAgent {
		t.Errorf("Role = %q, want %q", resp.ServiceAccounts[0].Role, idp.RoleAgent)
	}
}

func TestListServiceAccounts_EmptyResult(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
	})

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	resp, err := client.ListServiceAccounts(context.Background(), idp.ListServiceAccountsRequest{PageSize: 50})
	if err != nil {
		t.Fatalf("ListServiceAccounts: %v", err)
	}
	if len(resp.ServiceAccounts) != 0 {
		t.Errorf("got %d accounts, want 0", len(resp.ServiceAccounts))
	}
}

func TestListServiceAccounts_Upstream5xx(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusInternalServerError, "INTERNAL", "db error")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.ListServiceAccounts(context.Background(), idp.ListServiceAccountsRequest{PageSize: 50})
	if !errors.Is(err, idp.ErrUpstream) {
		t.Errorf("want ErrUpstream, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUserProfile tests
// ---------------------------------------------------------------------------

func TestGetUserProfile_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/management/v1/users/") {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"user": map[string]interface{}{
				"id":    "user-xyz",
				"state": "USER_STATE_ACTIVE",
				"human": map[string]interface{}{
					"profile": map[string]string{
						"displayName": "Alice Example",
					},
					"email": map[string]string{
						"email": "alice@example.com",
					},
				},
				"createdAt": "2024-01-01T00:00:00Z",
			},
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	profile, err := client.GetUserProfile(context.Background(), "user-xyz")
	if err != nil {
		t.Fatalf("GetUserProfile: %v", err)
	}
	if profile.DisplayName != "Alice Example" {
		t.Errorf("DisplayName: got %q, want %q", profile.DisplayName, "Alice Example")
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", profile.Email, "alice@example.com")
	}
}

func TestGetUserProfile_NotFound(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusNotFound, "NOT_FOUND", "user not found")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.GetUserProfile(context.Background(), "missing-user")
	if !errors.Is(err, idp.ErrNotFound) {
		t.Errorf("want ErrNotFound, got: %v", err)
	}
}

// TestGetUserProfile_EmptyDetails guards against the panic at parseZitadelError
// when Zitadel returns an error body with no "details" field (empty slice).
// Regression test for the index-out-of-range panic that crashed ListMembers.
func TestGetUserProfile_EmptyDetails(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Zitadel sometimes returns errors without a "details" array.
		jsonResp(w, http.StatusInternalServerError, map[string]interface{}{
			"code":    13,
			"message": "Internal error",
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	// Must return an error, not panic.
	_, err = client.GetUserProfile(context.Background(), "user-xyz")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, idp.ErrNotFound) {
		t.Errorf("got ErrNotFound, want ErrUpstream")
	}
}

// TestGetUserProfile_EmptyBody guards against panic when Zitadel returns a
// non-2xx status with an empty response body.
func TestGetUserProfile_EmptyBody(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.GetUserProfile(context.Background(), "user-xyz")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Startup probe tests
// ---------------------------------------------------------------------------

func TestNew_DiscoveryUnreachable(t *testing.T) {
	// Point at an invalid URL so discovery fails.
	cfg := zitadel.Config{
		Issuer:       "http://127.0.0.1:1", // nothing listens here
		ClientID:     "client",
		ClientSecret: "secret",
	}
	_, err := zitadel.New(context.Background(), cfg)
	if !errors.Is(err, idp.ErrUnreachable) {
		t.Errorf("want ErrUnreachable on bad issuer, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DiscoveryURL split tests — spec tier-2-host-aliases-cluster-dns
// ---------------------------------------------------------------------------
//
// The daemon's IdP admin client takes two URLs:
//   - Issuer:       externally-routable issuer claim (kept for token validation).
//   - DiscoveryURL: optional in-cluster URL the client dials for the OIDC
//                   discovery doc + JWKS. Empty → falls back to Issuer.
//
// These tests lock that split against drift.

// TestNew_DiscoveryURL_FallsBackToIssuerWhenEmpty proves the pre-spec behavior
// is preserved: with DiscoveryURL empty, the client dials the issuer for the
// well-known doc.
func TestNew_DiscoveryURL_FallsBackToIssuerWhenEmpty(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // no management API hits in this test
	})
	if cfg.DiscoveryURL != "" {
		t.Fatalf("setupServer should leave DiscoveryURL empty; got %q", cfg.DiscoveryURL)
	}

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()
}

// TestNew_DiscoveryURL_PrefersDiscoveryWhenSet verifies that when both Issuer
// and DiscoveryURL point at distinct httptest servers, the discovery doc is
// fetched from DiscoveryURL — and the issuer server is never asked for it.
// Server B serves only /.well-known/openid-configuration; server A serves
// only the management API + token endpoint that the discovery doc points
// the client at.
func TestNew_DiscoveryURL_PrefersDiscoveryWhenSet(t *testing.T) {
	var serverAURL string
	serverADiscoveryHits := 0

	// Server A — issuer + management API + token endpoint. Records every
	// time someone asks it for the discovery doc (must be zero).
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			serverADiscoveryHits++
			http.NotFound(w, r)
		case r.URL.Path == "/oauth/v2/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-admin-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(serverA.Close)
	serverAURL = serverA.URL

	// Server B — discovery-only. Hands clients server A's token endpoint.
	serverBDiscoveryHits := 0
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		serverBDiscoveryHits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": serverAURL + "/oauth/v2/token",
		})
	}))
	t.Cleanup(serverB.Close)

	cfg := zitadel.Config{
		Issuer:       serverAURL,  // external issuer (used for management API + iss claim)
		DiscoveryURL: serverB.URL, // in-cluster discovery URL
		ClientID:     "admin-client",
		ClientSecret: "admin-secret",
		OrgID:        "org-123",
	}

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if serverBDiscoveryHits != 1 {
		t.Errorf("expected exactly 1 discovery hit on serverB, got %d", serverBDiscoveryHits)
	}
	if serverADiscoveryHits != 0 {
		t.Errorf("expected 0 discovery hits on serverA (the issuer), got %d", serverADiscoveryHits)
	}
}

// TestNew_DiscoveryURL_FailsFastOnUnreachableInClusterURL proves that when the
// operator sets DiscoveryURL to a bad in-cluster address, the daemon fails
// fast with ErrUnreachable AND the wrapped error mentions the discovery URL,
// not the issuer URL — so an operator triaging a CrashLoopBackOff sees the
// right URL in the pod log line.
func TestNew_DiscoveryURL_FailsFastOnUnreachableInClusterURL(t *testing.T) {
	const badDiscovery = "http://127.0.0.1:1" // nothing listens here

	cfg := zitadel.Config{
		Issuer:       "http://example.invalid",
		DiscoveryURL: badDiscovery,
		ClientID:     "client",
		ClientSecret: "secret",
		HTTPTimeout:  100 * time.Millisecond,
	}
	_, err := zitadel.New(context.Background(), cfg)
	if !errors.Is(err, idp.ErrUnreachable) {
		t.Fatalf("want ErrUnreachable on bad discovery URL, got: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "127.0.0.1:1") {
		t.Errorf("error message should mention the bad discovery host (127.0.0.1:1); got: %v", err)
	}
	if strings.Contains(msg, "example.invalid") {
		t.Errorf("error message should NOT mention the issuer host (example.invalid); got: %v", err)
	}
}

// TestDiscoverTokenEndpoint_DoesNotMutateIssuer is the contract test for
// "DiscoveryURL is the dial URL only; the iss claim and the management API
// base URL stay Issuer". We set DiscoveryURL distinct from Issuer, exercise
// a management API call, and verify the request hits Issuer (server A) —
// not DiscoveryURL (server B).
func TestDiscoverTokenEndpoint_DoesNotMutateIssuer(t *testing.T) {
	var serverAURL string
	serverAMgmtHits := 0

	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/v2/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-admin-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case strings.HasPrefix(r.URL.Path, "/management/"):
			serverAMgmtHits++
			jsonResp(w, http.StatusOK, map[string]string{"userId": "user-from-A"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(serverA.Close)
	serverAURL = serverA.URL

	serverBMgmtHits := 0
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": serverAURL + "/oauth/v2/token",
			})
		case strings.HasPrefix(r.URL.Path, "/management/"):
			serverBMgmtHits++
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(serverB.Close)

	cfg := zitadel.Config{
		Issuer:       serverAURL,
		DiscoveryURL: serverB.URL,
		ClientID:     "admin-client",
		ClientSecret: "admin-secret",
		OrgID:        "org-123",
	}

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if _, err := client.CreateServiceAccount(context.Background(), idp.CreateServiceAccountRequest{
		Name: "agent-sanity",
		Role: idp.RoleAgent,
	}); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}

	if serverAMgmtHits == 0 {
		t.Errorf("expected management API call to land on serverA (Issuer), got 0 hits")
	}
	if serverBMgmtHits != 0 {
		t.Errorf("management API call must NOT land on serverB (DiscoveryURL); got %d hits", serverBMgmtHits)
	}
}
