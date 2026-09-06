// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

		// Both API surfaces reach the test handler. Zitadel's v1 Management
		// API carries profile and membership; the v2 user endpoint carries the
		// credential timestamps. A helper that routed only /management/ made a
		// /v2/ call 404, which reads in a test as an upstream error rather than
		// as "this helper does not serve that path".
		case strings.HasPrefix(r.URL.Path, "/management/"), strings.HasPrefix(r.URL.Path, "/v2/"):
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
		// The REAL management v1 users/_search row shape (verified live):
		// the user id is `id` — NOT `userId` — and creationDate lives under
		// `details`. The old fixture used `userId` and mirrored the decoder
		// bug it should have caught: every AccountID decoded empty and
		// `gibson agent list` dropped every identity.
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"result": []map[string]interface{}{
				{
					"id":       "user-1",
					"userName": "agent-acme-redteam",
					"details": map[string]string{
						"creationDate": "2026-01-01T00:00:00Z",
					},
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

// TestManagementCallsFollowTheInClusterBase is the contract test for
// gibson#1560: when DiscoveryURL is set it is the base URL for ALL Zitadel
// HTTP traffic — discovery, token, AND the Management API calls. The external
// Issuer host is the ext_authz-gated public gateway that 403s admin writes, so
// management calls must NOT egress there. We set DiscoveryURL (server B,
// standing in for the in-cluster Envoy listener) distinct from Issuer
// (server A, the public gateway), exercise a management API call, and verify
// it lands on server B — never on Issuer/server A.
func TestManagementCallsFollowTheInClusterBase(t *testing.T) {
	var serverBURL string

	// Server A is the external token endpoint the discovery doc points at.
	// It must NEVER receive a management call (that is the public gateway
	// that 403s admin writes).
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
	serverAURL := serverA.URL

	// Server B is the in-cluster base (DiscoveryURL). It serves discovery and
	// the Management API. The token_endpoint in its discovery doc points at
	// the external server A, mirroring how Envoy's in-cluster listener proxies
	// discovery while the doc advertises the external token endpoint.
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
			jsonResp(w, http.StatusOK, map[string]string{"userId": "user-from-B"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(serverB.Close)
	serverBURL = serverB.URL

	cfg := zitadel.Config{
		Issuer:       serverAURL,
		DiscoveryURL: serverBURL,
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

	if serverBMgmtHits == 0 {
		t.Errorf("expected the management API call to land on serverB (DiscoveryURL), got 0 hits")
	}
	if serverAMgmtHits != 0 {
		t.Errorf("management API call must NOT land on serverA (Issuer/public gateway); got %d hits", serverAMgmtHits)
	}
}

// --- HumanPasswordChangedAt ---------------------------------------------------
//
// This read is what lets the first-admin bootstrap tell a SPENT initial
// credential from a live one, and the caller DELETES a Secret on the strength
// of it. So the failure modes matter as much as the happy path: every one below
// must yield a zero time or an error, never a confident wrong timestamp.

func TestHumanPasswordChangedAt_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/v2/users/") {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"user": map[string]interface{}{
				"userId": "user-xyz",
				"human": map[string]interface{}{
					"passwordChanged": "2026-08-26T15:27:54.361545Z",
				},
			},
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.HumanPasswordChangedAt(context.Background(), "user-xyz")
	if err != nil {
		t.Fatalf("HumanPasswordChangedAt: %v", err)
	}
	want := time.Date(2026, 8, 26, 15, 27, 54, 361545000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// No passwordChanged field means Zitadel holds no change record: the password is
// still the one set at user creation. That MUST read as the zero time, because
// the caller treats zero as "the credential is live, keep it".
func TestHumanPasswordChangedAt_AbsentFieldIsZeroTime(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, _ *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"user": map[string]interface{}{
				"userId": "user-xyz",
				"human":  map[string]interface{}{},
			},
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.HumanPasswordChangedAt(context.Background(), "user-xyz")
	if err != nil {
		t.Fatalf("an absent timestamp is a valid answer, not an error: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("got %v, want the zero time", got)
	}
}

// A timestamp Zitadel sends but Go cannot parse must be an error, never the zero
// time: zero means "never changed", and silently reporting that would keep a
// spent Secret forever while looking like a successful read.
func TestHumanPasswordChangedAt_UnparseableTimestampIsAnError(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, _ *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"user": map[string]interface{}{
				"human": map[string]interface{}{"passwordChanged": "not-a-timestamp"},
			},
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.HumanPasswordChangedAt(context.Background(), "user-xyz"); err == nil {
		t.Fatal("want a parse error, not a silent zero time")
	}
}

func TestHumanPasswordChangedAt_EmptyUserIDIsRejected(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no request should reach the server for an empty user id")
		jsonResp(w, http.StatusOK, map[string]interface{}{})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.HumanPasswordChangedAt(context.Background(), ""); err == nil {
		t.Fatal("want an error for an empty user id")
	}
}

func TestHumanPasswordChangedAt_UpstreamErrorIsSurfaced(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusNotFound, "NOT_FOUND", "user not found")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.HumanPasswordChangedAt(context.Background(), "user-xyz"); err == nil {
		t.Fatal("want the upstream error surfaced")
	}
}
