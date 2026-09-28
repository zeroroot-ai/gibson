// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// setupUsersServer stands up an httptest server that serves OIDC discovery +
// the OAuth2 token endpoint (via zitadelconntest) so zitadel.New succeeds,
// and routes the Zitadel Management user API calls (/management/v1/users...)
// to the provided handler.
func setupUsersServer(t *testing.T, usersHandler http.HandlerFunc) zitadel.Config {
	t.Helper()
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/management/v1/users") {
			usersHandler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	return testConfig(t, srv)
}

// closeClient closes the client, satisfying errcheck without a per-call
// boilerplate closure.
func closeClient(t *testing.T, c interface{ Close() error }) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("client.Close: %v", err)
	}
}

func TestCreateHumanUser_HappyPath(t *testing.T) {
	var gotBody map[string]interface{}
	cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/management/v1/users/human" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		jsonResp(w, http.StatusCreated, map[string]string{"userId": "user-new"})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	res, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		Email:         "owner@example.com",
		GivenName:     "Ada",
		FamilyName:    "Lovelace",
		Password:      "s3cret-passw0rd!",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("CreateHumanUser: %v", err)
	}
	if res.UserID != "user-new" {
		t.Errorf("UserID = %q, want user-new", res.UserID)
	}

	// Verify request shape matches the Zitadel Management (v1) create body.
	if gotBody["userName"] != "owner@example.com" {
		t.Errorf("userName = %v", gotBody["userName"])
	}
	prof, _ := gotBody["profile"].(map[string]interface{})
	if prof["firstName"] != "Ada" || prof["lastName"] != "Lovelace" {
		t.Errorf("profile = %v", prof)
	}
	email, _ := gotBody["email"].(map[string]interface{})
	if email["isEmailVerified"] != true {
		t.Errorf("email.isEmailVerified = %v, want true", email["isEmailVerified"])
	}
	if gotBody["initialPassword"] != "s3cret-passw0rd!" {
		t.Errorf("initialPassword not forwarded in body: %v", gotBody["initialPassword"])
	}
}

// TestCreateHumanUser_ConflictWritesNoCredential is the regression test for the
// credential write this change removes.
//
// The old shape treated a 409 on create as "resume": it searched for the
// existing user by email and POSTed that user's /password endpoint with the
// password carried in the signup form. A form submission establishes nothing
// about who sent it, so that path let a signup for an already-registered
// address overwrite the existing account's password.
//
// The assertion is on the WIRE, not on the return value: exactly one upstream
// request, to the create endpoint, and never a request to any /password path.
// A return-value assertion would still pass if the credential write happened
// and its result were discarded.
func TestCreateHumanUser_ConflictWritesNoCredential(t *testing.T) {
	var paths []string
	cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/management/v1/users/human":
			errorResp(w, http.StatusConflict, "ALREADY_EXISTS", "user already exists")
		default:
			// Any other call is a failure of the property under test. Answer
			// it successfully so the assertion below reports the offending
			// path rather than a confusing transport error.
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "user-existing"}},
			})
		}
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	res, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		Email:    "existing@example.com",
		Password: "some-other-passw0rd!",
	})
	if err == nil {
		t.Fatalf("CreateHumanUser on a conflicting address must fail, got %+v", res)
	}
	if !errors.Is(err, idp.ErrAlreadyExists) {
		t.Errorf("error = %v, want idp.ErrAlreadyExists", err)
	}
	if res.UserID != "" {
		t.Errorf("UserID = %q, want empty on conflict", res.UserID)
	}

	// Exactly one upstream call: the create attempt.
	if len(paths) != 1 || paths[0] != "POST /management/v1/users/human" {
		t.Fatalf("upstream calls = %v, want exactly [POST /management/v1/users/human]", paths)
	}
	for _, p := range paths {
		if strings.Contains(p, "/password") {
			t.Fatalf("a credential write reached the IdP on the conflict path: %v", paths)
		}
	}
}

func TestCreateHumanUser_RequiresEmailAndPassword(t *testing.T) {
	cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{Password: "x"}); err == nil {
		t.Errorf("expected error when email is empty")
	}
	if _, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{Email: "a@b.c"}); err == nil {
		t.Errorf("expected error when password is empty")
	}
}

// TestFindUserIDByEmail covers the read-only lookup that replaced the search
// half of the old resume branch. It must issue the search and nothing else.
func TestFindUserIDByEmail(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		var methods []string
		cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) {
			methods = append(methods, r.Method+" "+r.URL.Path)
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "user-existing"}},
			})
		})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)

		id, err := client.FindUserIDByEmail(context.Background(), "owner@example.com")
		if err != nil {
			t.Fatalf("FindUserIDByEmail: %v", err)
		}
		if id != "user-existing" {
			t.Errorf("id = %q, want user-existing", id)
		}
		if len(methods) != 1 || methods[0] != "POST /management/v1/users/_search" {
			t.Errorf("upstream calls = %v, want exactly the search", methods)
		}
	})

	t.Run("not found", func(t *testing.T) {
		cfg := setupUsersServer(t, func(w http.ResponseWriter, _ *http.Request) {
			jsonResp(w, http.StatusOK, map[string]interface{}{"result": []map[string]string{}})
		})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)

		if _, err := client.FindUserIDByEmail(context.Background(), "nobody@example.com"); !errors.Is(err, idp.ErrNotFound) {
			t.Errorf("error = %v, want idp.ErrNotFound", err)
		}
	})

	t.Run("upstream failure is wrapped, not swallowed", func(t *testing.T) {
		cfg := setupUsersServer(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)

		_, err = client.FindUserIDByEmail(context.Background(), "owner@example.com")
		if err == nil {
			t.Fatal("expected an error when the upstream search fails")
		}
		if errors.Is(err, idp.ErrNotFound) {
			t.Errorf("a broken upstream must not be reported the same as a clean not-found: %v", err)
		}
	})

	t.Run("requires email", func(t *testing.T) {
		cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)

		if _, err := client.FindUserIDByEmail(context.Background(), ""); err == nil {
			t.Errorf("expected an error on an empty email")
		}
	})
}

func TestSetHumanPassword_PostsNewPassword(t *testing.T) {
	var gotBody map[string]interface{}
	var gotPath string
	cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if err := client.SetHumanPassword(context.Background(), idp.SetHumanPasswordRequest{
		OrgID: "org-1", UserID: "user-9", Password: "N3w-passw0rd!",
	}); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}
	if gotPath != "/management/v1/users/user-9/password" {
		t.Errorf("path = %q, want /management/v1/users/user-9/password", gotPath)
	}
	if gotBody["password"] != "N3w-passw0rd!" || gotBody["noChangeRequired"] != true {
		t.Errorf("password body wrong: %v", gotBody)
	}
}

func TestSetHumanPassword_RequiresFields(t *testing.T) {
	cfg := setupUsersServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)
	if err := client.SetHumanPassword(context.Background(), idp.SetHumanPasswordRequest{UserID: "u"}); err == nil {
		t.Error("want error when password is empty")
	}
	if err := client.SetHumanPassword(context.Background(), idp.SetHumanPasswordRequest{Password: "p"}); err == nil {
		t.Error("want error when userId is empty")
	}
}

func TestSetHumanPassword_UpstreamError(t *testing.T) {
	cfg := setupUsersServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/management/v1/users/u/password" {
			jsonResp(w, http.StatusBadRequest, map[string]interface{}{"code": 3, "message": "bad"})
			return
		}
		http.NotFound(w, r)
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)
	if err := client.SetHumanPassword(context.Background(), idp.SetHumanPasswordRequest{OrgID: "o", UserID: "u", Password: "p"}); err == nil {
		t.Fatal("want an error on a 400 from the IdP")
	}
}

// TestFindUserIDByEmailInOrg covers the org-scoped resolver (gibson#1560): the
// founding owner lives in the tenant org, so the bootstrap must search that org,
// not the admin client's configured org. Exercises the happy path and both guards.
func TestFindUserIDByEmailInOrg(t *testing.T) {
	t.Run("found in the given org", func(t *testing.T) {
		cfg := setupUsersServer(t, func(w http.ResponseWriter, _ *http.Request) {
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "user-in-tenant"}},
			})
		})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)

		id, err := client.FindUserIDByEmailInOrg(context.Background(), "owner@example.com", "tenant-org-1")
		if err != nil {
			t.Fatalf("FindUserIDByEmailInOrg: %v", err)
		}
		if id != "user-in-tenant" {
			t.Errorf("id = %q, want user-in-tenant", id)
		}
	})

	t.Run("requires email", func(t *testing.T) {
		cfg := setupUsersServer(t, func(http.ResponseWriter, *http.Request) {})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)
		if _, err := client.FindUserIDByEmailInOrg(context.Background(), "", "tenant-org-1"); !errors.Is(err, idp.ErrUpstream) {
			t.Errorf("error = %v, want idp.ErrUpstream", err)
		}
	})

	t.Run("requires orgID", func(t *testing.T) {
		cfg := setupUsersServer(t, func(http.ResponseWriter, *http.Request) {})
		client, err := zitadel.New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer closeClient(t, client)
		if _, err := client.FindUserIDByEmailInOrg(context.Background(), "owner@example.com", ""); !errors.Is(err, idp.ErrUpstream) {
			t.Errorf("error = %v, want idp.ErrUpstream", err)
		}
	})
}
