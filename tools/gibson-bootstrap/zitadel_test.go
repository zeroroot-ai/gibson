package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test server helpers — mirrors admin_test.go style in internal/idp/zitadel/
// ---------------------------------------------------------------------------

// setupBootstrapServer returns an httptest.Server that handles the Zitadel
// Management/Admin API paths exercised by the bootstrap binary, wiring them
// to the provided handler. The server's URL is used as ZITADEL_ISSUER.
func setupBootstrapServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, PATClientConfig) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := PATClientConfig{
		Issuer:   srv.URL,
		AdminPAT: "test-admin-pat",
	}
	return srv, cfg
}

// jsonResp writes a JSON response with the given status code.
func jsonRespB(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// errorRespB writes a Zitadel-style error envelope.
func errorRespB(w http.ResponseWriter, status int, code, message string) {
	jsonRespB(w, status, map[string]interface{}{
		"code":    status,
		"message": message,
		"details": []map[string]string{{"errorCode": code}},
	})
}

// ---------------------------------------------------------------------------
// EnsureOrg tests
// ---------------------------------------------------------------------------

// TestEnsureOrg_Created covers the path where the org does not exist and is
// created successfully.
func TestEnsureOrg_Created(t *testing.T) {
	calls := 0
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs/_search"):
			// First call: org not found.
			jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs"):
			// Second call: create org.
			jsonRespB(w, http.StatusOK, map[string]string{"id": "org-new-123"})

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	result, err := c.EnsureOrg(context.Background(), "my-org")
	if err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if result.OrgID != "org-new-123" {
		t.Errorf("OrgID = %q, want %q", result.OrgID, "org-new-123")
	}
	if !result.Created {
		t.Error("Created should be true for a freshly created org")
	}
	if calls != 2 {
		t.Errorf("expected 2 API calls (search + create), got %d", calls)
	}
}

// TestEnsureOrg_AlreadyExists covers the path where the org is found on the
// initial search.
func TestEnsureOrg_AlreadyExists(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/orgs/_search") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		jsonRespB(w, http.StatusOK, map[string]interface{}{
			"result": []map[string]string{{"id": "org-existing-456"}},
		})
	})

	c := newPATClient(cfg)
	result, err := c.EnsureOrg(context.Background(), "existing-org")
	if err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if result.OrgID != "org-existing-456" {
		t.Errorf("OrgID = %q, want %q", result.OrgID, "org-existing-456")
	}
	if result.Created {
		t.Error("Created should be false for an existing org")
	}
}

// TestEnsureOrg_Conflict_ResolvesOnResearch covers the race-condition path:
// org not found on search, 409 on create, then found on re-search.
func TestEnsureOrg_Conflict_ResolvesOnResearch(t *testing.T) {
	searchCount := 0
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs/_search"):
			searchCount++
			if searchCount == 1 {
				// First search: not found.
				jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
			} else {
				// Re-search after conflict: found.
				jsonRespB(w, http.StatusOK, map[string]interface{}{
					"result": []map[string]string{{"id": "org-race-789"}},
				})
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs"):
			errorRespB(w, http.StatusConflict, "ALREADY_EXISTS", "org already exists")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	result, err := c.EnsureOrg(context.Background(), "race-org")
	if err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if result.OrgID != "org-race-789" {
		t.Errorf("OrgID = %q, want %q", result.OrgID, "org-race-789")
	}
	if result.Created {
		t.Error("Created should be false on conflict-then-research path")
	}
}

// TestEnsureOrg_APIError covers a non-conflict API error on create.
func TestEnsureOrg_APIError(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs"):
			errorRespB(w, http.StatusInternalServerError, "INTERNAL", "database error")
		default:
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	_, err := c.EnsureOrg(context.Background(), "fail-org")
	if err == nil {
		t.Fatal("want error from 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MintOIDCClient tests
// ---------------------------------------------------------------------------

// TestMintOIDCClient_Created covers the happy path where the client is freshly
// created and Zitadel returns both clientId and clientSecret.
func TestMintOIDCClient_Created(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/apps/oidc") {
			jsonRespB(w, http.StatusOK, map[string]string{
				"appId":        "app-1",
				"clientId":     "client-abc",
				"clientSecret": "secret-xyz",
			})
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	c := newPATClient(cfg)
	result, err := c.MintOIDCClient(context.Background(), MintOIDCClientRequest{
		ClientName: "my-app",
		OrgID:      "org-1",
		ProjectID:  "proj-1",
	})
	if err != nil {
		t.Fatalf("MintOIDCClient: %v", err)
	}
	if result.ClientID != "client-abc" {
		t.Errorf("ClientID = %q, want %q", result.ClientID, "client-abc")
	}
	if result.ClientSecret != "secret-xyz" {
		t.Errorf("ClientSecret = %q, want %q", result.ClientSecret, "secret-xyz")
	}
	if result.Rotated {
		t.Error("Rotated should be false on initial create")
	}
}

// TestMintOIDCClient_ExistsNoRotate covers the idempotent path: the client
// already exists and --rotate-secret was NOT passed. The result should
// contain the existing client_id but an empty client_secret.
func TestMintOIDCClient_ExistsNoRotate(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/apps/oidc"):
			errorRespB(w, http.StatusConflict, "ALREADY_EXISTS", "app already exists")

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/apps/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "app-existing", "name": "my-app"}},
			})

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/apps/app-existing"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"app": map[string]interface{}{
					"oidcConfig": map[string]string{"clientId": "existing-client-id"},
				},
			})

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	result, err := c.MintOIDCClient(context.Background(), MintOIDCClientRequest{
		ClientName:   "my-app",
		OrgID:        "org-1",
		ProjectID:    "proj-1",
		RotateSecret: false,
	})
	if err != nil {
		t.Fatalf("MintOIDCClient: %v", err)
	}
	if result.ClientID != "existing-client-id" {
		t.Errorf("ClientID = %q, want %q", result.ClientID, "existing-client-id")
	}
	if result.ClientSecret != "" {
		t.Errorf("ClientSecret should be empty when not rotating, got: %q", result.ClientSecret)
	}
	if result.Rotated {
		t.Error("Rotated should be false when not rotating")
	}
}

// TestMintOIDCClient_ExistsRotate covers the --rotate-secret path: the client
// exists and we request a new secret. The result should contain the new secret
// and Rotated=true.
func TestMintOIDCClient_ExistsRotate(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/apps/oidc"):
			errorRespB(w, http.StatusConflict, "ALREADY_EXISTS", "app already exists")

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/apps/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "app-existing", "name": "my-app"}},
			})

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/apps/app-existing"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"app": map[string]interface{}{
					"oidcConfig": map[string]string{"clientId": "existing-client-id"},
				},
			})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/oidc_client_secret"):
			jsonRespB(w, http.StatusOK, map[string]string{"clientSecret": "rotated-secret-new"})

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	result, err := c.MintOIDCClient(context.Background(), MintOIDCClientRequest{
		ClientName:   "my-app",
		OrgID:        "org-1",
		ProjectID:    "proj-1",
		RotateSecret: true,
	})
	if err != nil {
		t.Fatalf("MintOIDCClient: %v", err)
	}
	if result.ClientID != "existing-client-id" {
		t.Errorf("ClientID = %q, want %q", result.ClientID, "existing-client-id")
	}
	if result.ClientSecret != "rotated-secret-new" {
		t.Errorf("ClientSecret = %q, want %q", result.ClientSecret, "rotated-secret-new")
	}
	if !result.Rotated {
		t.Error("Rotated should be true after rotating secret")
	}
}

// TestMintOIDCClient_APIError covers a non-conflict error from Zitadel.
func TestMintOIDCClient_APIError(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorRespB(w, http.StatusInternalServerError, "INTERNAL", "database error")
	})

	c := newPATClient(cfg)
	_, err := c.MintOIDCClient(context.Background(), MintOIDCClientRequest{
		ClientName: "fail-app",
		OrgID:      "org-1",
		ProjectID:  "proj-1",
	})
	if err == nil {
		t.Fatal("want error from 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500, got: %v", err)
	}
}

// TestMintOIDCClient_OrgIDHeader verifies that the x-zitadel-orgid header is
// sent on management API calls.
func TestMintOIDCClient_OrgIDHeader(t *testing.T) {
	receivedOrgID := ""
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedOrgID = r.Header.Get("x-zitadel-orgid")
		jsonRespB(w, http.StatusOK, map[string]string{
			"appId":        "app-1",
			"clientId":     "client-xyz",
			"clientSecret": "secret-xyz",
		})
	})

	c := newPATClient(cfg)
	_, err := c.MintOIDCClient(context.Background(), MintOIDCClientRequest{
		ClientName: "my-app",
		OrgID:      "org-header-test",
		ProjectID:  "proj-1",
	})
	if err != nil {
		t.Fatalf("MintOIDCClient: %v", err)
	}
	if receivedOrgID != "org-header-test" {
		t.Errorf("x-zitadel-orgid header = %q, want %q", receivedOrgID, "org-header-test")
	}
}

// TestEnsureOrg_BearerToken verifies that the Authorization header carries the
// PAT as a Bearer token.
func TestEnsureOrg_BearerToken(t *testing.T) {
	receivedAuth := ""
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		switch {
		case strings.HasSuffix(r.URL.Path, "/orgs/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "org-token-test"}},
			})
		default:
			http.NotFound(w, r)
		}
	})

	c := newPATClient(cfg)
	_, err := c.EnsureOrg(context.Background(), "token-test-org")
	if err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if receivedAuth != "Bearer test-admin-pat" {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, "Bearer test-admin-pat")
	}
}
