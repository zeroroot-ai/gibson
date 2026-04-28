package zitadel_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/idp"
	"github.com/zero-day-ai/gibson/internal/idp/zitadel"
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
		ProjectID:    "proj-456",
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
// MintClientSecret tests
// ---------------------------------------------------------------------------

func TestMintClientSecret_HappyPath(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "/secret") {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{
			"clientId":     "client-id-123",
			"clientSecret": "super-secret-value",
		})
	})

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	secret, err := client.MintClientSecret(context.Background(), "user-abc")
	if err != nil {
		t.Fatalf("MintClientSecret: %v", err)
	}
	if secret != "super-secret-value" {
		t.Errorf("secret = %q, want %q", secret, "super-secret-value")
	}
}

func TestMintClientSecret_NotFound(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusNotFound, "NOT_FOUND", "user not found")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.MintClientSecret(context.Background(), "missing-user")
	if !errors.Is(err, idp.ErrNotFound) {
		t.Errorf("want ErrNotFound, got: %v", err)
	}
}

func TestMintClientSecret_PermissionDenied(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	_, err = client.MintClientSecret(context.Background(), "user-abc")
	if !errors.Is(err, idp.ErrPermission) {
		t.Errorf("want ErrPermission, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AddTenantScopeMembership tests
// ---------------------------------------------------------------------------

func TestAddTenantScopeMembership_HappyPath(t *testing.T) {
	called := false
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/members") {
			called = true
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

	err = client.AddTenantScopeMembership(context.Background(), idp.AddMembershipRequest{
		AccountID:     "user-abc",
		TenantScopeID: "proj-456",
		Role:          idp.RoleAgent,
	})
	if err != nil {
		t.Fatalf("AddTenantScopeMembership: %v", err)
	}
	if !called {
		t.Error("membership endpoint was not called")
	}
}

func TestAddTenantScopeMembership_Upstream5xx(t *testing.T) {
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusServiceUnavailable, "UNAVAILABLE", "service down")
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	err = client.AddTenantScopeMembership(context.Background(), idp.AddMembershipRequest{
		AccountID:     "user-abc",
		TenantScopeID: "proj-456",
		Role:          idp.RoleAgent,
	})
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
