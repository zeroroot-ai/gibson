// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
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
	return mustNew(t, srv.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// testDomain is the public host the test clients claim.
const testDomain = "app.example.test"

// mustNew builds a client that connects to connectURL and claims testDomain.
func mustNew(t *testing.T, connectURL string, tokens oauth2.TokenSource) Client {
	t.Helper()
	ep, err := zitadelconn.New(connectURL, testDomain)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	c, err := New(ep, tokens)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestNew_RefusesAZeroEndpoint: an Endpoint that zitadelconn never validated
// names no Service and no host, so New refuses it at construction time.
func TestNew_RefusesAZeroEndpoint(t *testing.T) {
	c, err := New(zitadelconn.Endpoint{}, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}))
	if err == nil || c != nil {
		t.Fatalf("New(zero endpoint) = %v, %v; want a refusal", c, err)
	}
}

// TestManagementCalls_SelectTheInstanceByHeader proves the Management client
// reaches a Zitadel that selects its instance from x-zitadel-instance-host
// (ADR-0092, gibson#222). The fake answers 404 to a request without the
// header, which is how the real Zitadel answers a call by Service name.
func TestManagementCalls_SelectTheInstanceByHeader(t *testing.T) {
	fake := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"result": []any{}})
	}))
	ep := fake.Endpoint(t)
	tokens, err := TokenSource(context.Background(), ep, "tenant-operator", "s3cret", APIScopes())
	if err != nil {
		t.Fatalf("TokenSource: %v", err)
	}
	c, err := New(ep, tokens)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetOrganization(context.Background(), "org-1"); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("GetOrganization: %v, want ErrNotFound from the empty search", err)
	}
	if n := fake.Refused(); n != 0 {
		t.Errorf("the fake refused %d request(s); every request must carry the instance header", n)
	}
	if !fake.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Error("the token request did not reach the Service")
	}
	var api int
	for _, r := range fake.Requests() {
		if r.Path == "/oauth/v2/token" {
			continue
		}
		api++
		if r.Auth != "Bearer "+zitadelconntest.AccessToken {
			t.Errorf("%s %s Authorization = %q, want the token the Service issued", r.Method, r.Path, r.Auth)
		}
	}
	if api == 0 {
		t.Error("no Management request reached the Service")
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

// TestEnsureHumanUser_Success verifies the happy path returns the newly
// created user's id. Hosted#203: there is no follow-up org-membership call —
// a tenant role (written separately, through tenantrole.Syncer) is the
// membership.
func TestEnsureHumanUser_Success(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"userId": "user-new"})
		},
	})
	uid, err := c.EnsureHumanUser(context.Background(), "org-abc", "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-new" {
		t.Errorf("got uid=%q, want %q", uid, "user-new")
	}
}

// TestEnsureHumanUser_ExistingUser verifies that if user creation returns
// 409, the client looks up the existing user by email via /v2/users and
// still succeeds — idempotent, per the interface doc.
func TestEnsureHumanUser_ExistingUser(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "user exists"})
		},
		"POST /v2/users": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{{"userId": "user-existing"}},
			})
		},
	})
	uid, err := c.EnsureHumanUser(context.Background(), "org-abc", "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-existing" {
		t.Errorf("got uid=%q, want %q", uid, "user-existing")
	}
}

// TestEnsureHumanUser_ConflictLooksUpExistingUser keeps the removed
// TestAddMember_Conflict409 / TestSendInvitation_ExistingUser's
// upstream-conflict-mapping coverage: a 409 on create falls back to the
// by-email lookup and still succeeds (idempotent).
func TestEnsureHumanUser_ConflictLooksUpExistingUser(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "already exists"})
		},
		"POST /v2/users": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"result": []map[string]string{{"userId": "user-1"}},
			})
		},
	})
	id, err := c.EnsureHumanUser(context.Background(), "org-abc", "alice@example.com")
	if err != nil {
		t.Fatalf("expected nil error for conflict, got %v", err)
	}
	if id != "user-1" {
		t.Errorf("got id=%q, want %q", id, "user-1")
	}
}

// TestEnsureHumanUser_NonConflictCreateErrorSurfaces: a create failure that
// is not a 409 must be returned as-is, never fall through to the
// conflict-lookup branch.
func TestEnsureHumanUser_NonConflictCreateErrorSurfaces(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "boom"})
		},
	})
	if _, err := c.EnsureHumanUser(context.Background(), "org-abc", "alice@example.com"); err == nil {
		t.Fatal("expected an error for a non-conflict create failure")
	}
}

// TestEnsureHumanUser_ConflictLookupFailureSurfaces: if the create returns
// 409 but the follow-up lookup by email itself fails, that failure must
// surface, not a stray empty userID.
func TestEnsureHumanUser_ConflictLookupFailureSurfaces(t *testing.T) {
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "already exists"})
		},
		"POST /v2/users": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "lookup boom"})
		},
	})
	if _, err := c.EnsureHumanUser(context.Background(), "org-abc", "alice@example.com"); err == nil {
		t.Fatal("expected an error when the conflict-lookup itself fails")
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

// TestAuthorizationHeader verifies the token source's token is sent in Authorization: Bearer.
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
	if gotAuth != "Bearer test-token" {
		t.Errorf("expected %q, got %q", "Bearer test-token", gotAuth)
	}
}

// TestEnsureProjectGrant_CreatesUpdatesAndIsANoOp covers the three
// convergence branches: no grant creates one, a grant with different keys
// updates it, and a grant already holding exactly the wanted keys is a
// no-op (no CreateProjectGrant/UpdateProjectGrant call).
func TestEnsureProjectGrant_CreatesUpdatesAndIsANoOp(t *testing.T) {
	t.Run("creates when none exists", func(t *testing.T) {
		var created bool
		c := newTestServer(t, map[string]http.HandlerFunc{
			"POST /zitadel.project.v2.ProjectService/ListProjectGrants": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"projectGrants": []any{}})
			},
			"POST /zitadel.project.v2.ProjectService/CreateProjectGrant": func(w http.ResponseWriter, _ *http.Request) {
				created = true
				writeJSON(w, http.StatusOK, map[string]any{})
			},
		})
		if err := c.EnsureProjectGrant(context.Background(), "PROJ-1", "ORG-1", []string{"owner", "admin"}); err != nil {
			t.Fatalf("EnsureProjectGrant: %v", err)
		}
		if !created {
			t.Fatal("expected CreateProjectGrant to be called")
		}
	})

	t.Run("updates when keys differ", func(t *testing.T) {
		var updatedKeys []string
		c := newTestServer(t, map[string]http.HandlerFunc{
			"POST /zitadel.project.v2.ProjectService/ListProjectGrants": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{
					"projectGrants": []map[string]any{
						{"grantedOrganizationId": "ORG-1", "grantedRoleKeys": []string{"owner"}},
					},
				})
			},
			"POST /zitadel.project.v2.ProjectService/UpdateProjectGrant": func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					RoleKeys []string `json:"roleKeys"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				updatedKeys = req.RoleKeys
				writeJSON(w, http.StatusOK, map[string]any{})
			},
		})
		if err := c.EnsureProjectGrant(context.Background(), "PROJ-1", "ORG-1", []string{"owner", "admin", "editor", "viewer"}); err != nil {
			t.Fatalf("EnsureProjectGrant: %v", err)
		}
		if len(updatedKeys) != 4 {
			t.Fatalf("updatedKeys = %v, want 4 entries", updatedKeys)
		}
	})

	t.Run("no-op when already converged", func(t *testing.T) {
		c := newTestServer(t, map[string]http.HandlerFunc{
			"POST /zitadel.project.v2.ProjectService/ListProjectGrants": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{
					"projectGrants": []map[string]any{
						{"grantedOrganizationId": "ORG-1", "grantedRoleKeys": []string{"owner", "admin", "editor", "viewer"}},
					},
				})
			},
			// No Create/Update route registered: any call there fails the test
			// via newTestServer's "unexpected request" branch.
		})
		if err := c.EnsureProjectGrant(context.Background(), "PROJ-1", "ORG-1", []string{"viewer", "editor", "admin", "owner"}); err != nil {
			t.Fatalf("EnsureProjectGrant: %v", err)
		}
	})
}

// TestSendInvitation_UsernameIsNormalizedEmail pins ADR-0093 decision 1:
// SendInvitation derives the Zitadel username from
// idp.UsernameForEmail(email), the same function every other human-user
// create path uses, so a stray case or whitespace difference in the
// invited address can never mint a second username for the same mailbox.
func TestEnsureHumanUser_UsernameIsNormalizedEmail(t *testing.T) {
	const rawEmail = " Alice@Example.COM "
	var gotUsername string
	c := newTestServer(t, map[string]http.HandlerFunc{
		"POST /v2/users/human": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Username string `json:"username"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotUsername = body.Username
			writeJSON(w, http.StatusOK, map[string]string{"userId": "user-new"})
		},
	})
	if _, err := c.EnsureHumanUser(context.Background(), "org-abc", rawEmail); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := idp.UsernameForEmail(rawEmail)
	if gotUsername != want {
		t.Errorf("username = %q, want %q (normalized)", gotUsername, want)
	}
	if gotUsername == rawEmail {
		t.Errorf("username was sent verbatim as %q, want it normalized", rawEmail)
	}
}
