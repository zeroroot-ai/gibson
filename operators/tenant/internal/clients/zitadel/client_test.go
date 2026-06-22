/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// newTestServer creates an httptest.Server that dispatches to the given handler
// map keyed by "METHOD /path". The last registered handler wins for any given
// key. Returns a Client pre-pointed at the test server; the server itself is
// closed via t.Cleanup so callers don't need a handle.
func newTestServer(t *testing.T, routes map[string]http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		handler, ok := routes[key]
		if !ok {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-pat", "")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// TestNew_InvalidURL verifies that an unparseable URL returns an errClient
// that surfaces the error on every call.
func TestNew_InvalidURL(t *testing.T) {
	c := New("://bad-url", "pat", "")
	_, err := c.CreateOrganization(context.Background(), "test", "test")
	if err == nil {
		t.Fatal("expected error from errClient, got nil")
	}
}

// TestCreateOrganization_Success verifies the happy path returns the org ID
// from the response body (v4: POST /v2/organizations).
func TestCreateOrganization_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"organizationId": "org-abc"})
		},
	})
	id, err := c.CreateOrganization(context.Background(), "Acme Corp", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "org-abc" {
		t.Errorf("got id=%q, want %q", id, "org-abc")
	}
}

// TestCreateOrganization_Conflict409 verifies that a 409 triggers a lookup by
// name and returns the existing org's ID (v4: POST /v2/organizations/_search).
func TestCreateOrganization_Conflict409(t *testing.T) {
	callCount := 0
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations": func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			writeJSON(w, http.StatusConflict, map[string]string{"message": "already exists"})
		},
		"POST /v2/organizations/_search": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{{"id": "org-existing", "name": "Acme Corp"}},
			})
		},
	})
	id, err := c.CreateOrganization(context.Background(), "Acme Corp", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "org-existing" {
		t.Errorf("got id=%q, want %q", id, "org-existing")
	}
	if callCount != 1 {
		t.Errorf("expected 1 POST to /v2/organizations, got %d", callCount)
	}
}

// TestGetOrganization_Success verifies the response is mapped to Organization
// (v4: POST /v2/organizations/_search with idQuery).
func TestGetOrganization_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations/_search": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{
					{
						"id":            "org-abc",
						"name":          "Acme Corp",
						"primaryDomain": "acme",
					},
				},
			})
		},
	})
	org, err := c.GetOrganization(context.Background(), "org-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org.ID != "org-abc" || org.Name != "Acme Corp" || org.Slug != "acme" {
		t.Errorf("unexpected org: %+v", org)
	}
}

// TestGetOrganization_NotFound verifies empty result list is wrapped as ErrNotFound.
func TestGetOrganization_NotFound(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations/_search": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"result": []map[string]string{}})
		},
	})
	_, err := c.GetOrganization(context.Background(), "no-such")
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestDeleteOrganization_Success verifies a 200 returns nil
// (v4: DELETE /v2/organizations/{id}).
func TestDeleteOrganization_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /v2/organizations/org-abc": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	})
	if err := c.DeleteOrganization(context.Background(), "org-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDeleteOrganization_Idempotent verifies 404 is treated as success.
func TestDeleteOrganization_Idempotent(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /v2/organizations/gone": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
		},
	})
	if err := c.DeleteOrganization(context.Background(), "gone"); err != nil {
		t.Fatalf("expected nil for 404, got %v", err)
	}
}

// TestAddMember_Success verifies the composite membership ID is returned.
// v4: POST /management/v1/orgs/me/members with x-zitadel-orgid header.
func TestAddMember_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /management/v1/orgs/me/members": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"details": map[string]string{"sequence": "42"},
			})
		},
	})
	id, err := c.AddMember(context.Background(), "org-abc", "user-1", []string{"gibson.owner"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "org-abc/user-1" {
		t.Errorf("got id=%q, want %q", id, "org-abc/user-1")
	}
}

// TestAddMember_Conflict409 verifies 409 returns the composite ID without error.
func TestAddMember_Conflict409(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /management/v1/orgs/me/members": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "already member"})
		},
	})
	id, err := c.AddMember(context.Background(), "org-abc", "user-1", []string{"gibson.owner"})
	if err != nil {
		t.Fatalf("expected nil error for conflict, got %v", err)
	}
	if id != "org-abc/user-1" {
		t.Errorf("got id=%q, want %q", id, "org-abc/user-1")
	}
}

// TestRemoveMember_Success verifies 200 returns nil.
// v4: DELETE /management/v1/orgs/me/members/{userID}.
func TestRemoveMember_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /management/v1/orgs/me/members/user-1": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	})
	if err := c.RemoveMember(context.Background(), "org-abc", "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRemoveMember_Idempotent verifies 404 is treated as success.
func TestRemoveMember_Idempotent(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /management/v1/orgs/me/members/gone": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
		},
	})
	if err := c.RemoveMember(context.Background(), "org-abc", "gone"); err != nil {
		t.Fatalf("expected nil for 404, got %v", err)
	}
}

// TestSendInvitation_NewUser verifies the happy path creates a user then adds
// them as a member, returning the user ID.
// v4: POST /v2/users/human for creation, POST /management/v1/orgs/me/members.
func TestSendInvitation_NewUser(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"userId": "user-new"})
		},
		"POST /management/v1/orgs/me/members": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"details": map[string]string{"sequence": "1"},
			})
		},
	})
	uid, err := c.SendInvitation(context.Background(), "org-abc", "alice@example.com", []string{"gibson.member"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-new" {
		t.Errorf("got uid=%q, want %q", uid, "user-new")
	}
}

// TestSendInvitation_ExistingUser verifies that if user creation returns 409,
// the client looks up the existing user by email via /v2/users and still succeeds.
func TestSendInvitation_ExistingUser(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "user exists"})
		},
		"POST /v2/users": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{{"userId": "user-existing"}},
			})
		},
		"POST /management/v1/orgs/me/members": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"details": map[string]string{"sequence": "2"},
			})
		},
	})
	uid, err := c.SendInvitation(context.Background(), "org-abc", "alice@example.com", []string{"gibson.member"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-existing" {
		t.Errorf("got uid=%q, want %q", uid, "user-existing")
	}
}

// TestUnauthorized verifies 401 is wrapped as a permanent ErrUnauthorized.
func TestUnauthorized(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations/_search": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
		},
	})
	_, err := c.GetOrganization(context.Background(), "org-abc")
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
	if !clients.IsPermanent(err) {
		t.Errorf("expected permanent error, got non-permanent: %v", err)
	}
}

// TestRateLimited verifies 429 is wrapped as ErrRateLimited.
func TestRateLimited(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations/_search": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"message": "slow down"})
		},
	})
	_, err := c.GetOrganization(context.Background(), "org-abc")
	if !errors.Is(err, clients.ErrRateLimited) {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}

// TestNoopClient (deleted) — the NoopClient degradation surface was removed
// in epic one-code-path / deploy#196. Zitadel is now structurally required;
// cmd/main.go exits 1 at startup when ZITADEL_URL is empty or the PAT
// file is unreadable, so no graceful "ErrUnreachable on every method"
// state is reachable.

// TestCreateServiceAccount_Success verifies the happy path creates a machine user
// and then generates a client key, returning all three identifiers.
func TestCreateServiceAccount_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/machine": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"userId": "svc-abc"})
		},
		"POST /v2/users/svc-abc/keys": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"keyId":     "key-123",
				"keyDetail": "super-secret",
			})
		},
	})
	accountID, clientID, secret, err := c.CreateServiceAccount(context.Background(), "org-abc", "my-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accountID != "svc-abc" {
		t.Errorf("accountID: got %q, want %q", accountID, "svc-abc")
	}
	if clientID != "key-123" {
		t.Errorf("clientID: got %q, want %q", clientID, "key-123")
	}
	if secret != "super-secret" {
		t.Errorf("clientSecret: got %q, want %q", secret, "super-secret")
	}
}

// TestCreateServiceAccount_Conflict verifies that a 409 on machine-user creation
// falls through to a name-based lookup and returns the existing account ID with
// an empty secret (caller cannot retrieve secret for existing accounts).
func TestCreateServiceAccount_Conflict(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/machine": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "already exists"})
		},
		"POST /v2/users": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{{"userId": "svc-existing"}},
			})
		},
	})
	accountID, clientID, secret, err := c.CreateServiceAccount(context.Background(), "org-abc", "my-agent")
	if err != nil {
		t.Fatalf("unexpected error on conflict: %v", err)
	}
	if accountID != "svc-existing" {
		t.Errorf("accountID: got %q, want %q", accountID, "svc-existing")
	}
	if clientID != "svc-existing" {
		t.Errorf("clientID (same as accountID on conflict path): got %q, want %q", clientID, "svc-existing")
	}
	if secret != "" {
		t.Errorf("clientSecret should be empty on conflict path, got %q", secret)
	}
}

// TestDeleteServiceAccount_Success verifies a 200 returns nil.
func TestDeleteServiceAccount_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /v2/users/svc-abc": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	})
	if err := c.DeleteServiceAccount(context.Background(), "org-abc", "svc-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDeleteServiceAccount_Idempotent verifies 404 is treated as success.
func TestDeleteServiceAccount_Idempotent(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /v2/users/gone": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
		},
	})
	if err := c.DeleteServiceAccount(context.Background(), "org-abc", "gone"); err != nil {
		t.Fatalf("expected nil for 404, got %v", err)
	}
}

// TestAuthorizationHeader verifies the PAT is sent in Authorization: Bearer.
func TestAuthorizationHeader(t *testing.T) {
	var gotAuth string
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/organizations/_search": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{
					{"id": "org-abc", "name": "test", "primaryDomain": "test"},
				},
			})
		},
	})
	_, _ = c.GetOrganization(context.Background(), "org-abc")
	if gotAuth != "Bearer test-pat" {
		t.Errorf("expected %q, got %q", "Bearer test-pat", gotAuth)
	}
}
