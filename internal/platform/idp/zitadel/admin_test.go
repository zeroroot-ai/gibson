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
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// setupServer starts a fake Zitadel that selects its instance by header, like
// the real one (zitadelconntest), and routes both API surfaces to the handler.
// Zitadel's v1 Management API carries profile and membership; the v2 user
// endpoint carries the credential timestamps.
func setupServer(t *testing.T, managementHandler http.HandlerFunc) (*httptest.Server, zitadel.Config) {
	t.Helper()
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/management/") || strings.HasPrefix(r.URL.Path, "/v2/") {
			managementHandler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	return srv.Server, testConfig(t, srv)
}

// testConfig is the admin client configuration a correct deployment renders
// for srv (ADR-0092).
func testConfig(t *testing.T, srv *zitadelconntest.Server) zitadel.Config {
	t.Helper()
	return zitadel.Config{
		Issuer:       "https://" + srv.Domain,
		ClientID:     "admin-client",
		ClientSecret: "admin-secret",
		OrgID:        "org-123",
		Endpoint:     srv.Endpoint(t),
	}
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
	var v1Org string
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v2/users/user-xyz" {
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"details": map[string]string{"resourceOwner": "org-tenant-7"},
			})
			return
		}
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/management/v1/users/") {
			http.NotFound(w, r)
			return
		}
		v1Org = r.Header.Get("x-zitadel-orgid")
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
	// A v1 Management call is scoped to the org in x-zitadel-orgid. The user
	// lives in their tenant's org, so the call must send that org, never the
	// platform admin org the client is configured with (hosted#208).
	if v1Org != "org-tenant-7" {
		t.Errorf("v1 x-zitadel-orgid = %q, want the user's own org org-tenant-7", v1Org)
	}
}

// TestUpdateUserProfile_UsesTheUsersOwnOrg pins the same org scoping for the
// profile update.
func TestUpdateUserProfile_UsesTheUsersOwnOrg(t *testing.T) {
	var putOrg string
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/user-xyz":
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"details": map[string]string{"resourceOwner": "org-tenant-7"},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/management/v1/users/user-xyz/profile":
			putOrg = r.Header.Get("x-zitadel-orgid")
			jsonResp(w, http.StatusOK, map[string]interface{}{})
		case r.Method == http.MethodGet && r.URL.Path == "/management/v1/users/user-xyz":
			jsonResp(w, http.StatusOK, map[string]interface{}{"user": map[string]interface{}{"id": "user-xyz"}})
		default:
			http.NotFound(w, r)
		}
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if _, err := client.UpdateUserProfile(context.Background(), "user-xyz", idp.UpdateUserProfileRequest{DisplayName: "Alice"}); err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}
	if putOrg != "org-tenant-7" {
		t.Errorf("v1 x-zitadel-orgid = %q, want the user's own org org-tenant-7", putOrg)
	}
}

// TestUserProfile_OwningOrgUnknownIsAnError pins that a user whose owning org
// cannot be resolved is an error, never a v1 call under the wrong org.
func TestUserProfile_OwningOrgUnknownIsAnError(t *testing.T) {
	var v1Calls int
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/users/") {
			jsonResp(w, http.StatusOK, map[string]interface{}{"details": map[string]string{}})
			return
		}
		v1Calls++
		jsonResp(w, http.StatusOK, map[string]interface{}{})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if _, err := client.GetUserProfile(context.Background(), "user-xyz"); err == nil {
		t.Error("GetUserProfile: expected an error for a user with no owning org")
	}
	if _, err := client.UpdateUserProfile(context.Background(), "user-xyz", idp.UpdateUserProfileRequest{DisplayName: "Alice"}); err == nil {
		t.Error("UpdateUserProfile: expected an error for a user with no owning org")
	}
	if v1Calls != 0 {
		t.Errorf("v1 calls = %d, want none under an unknown org", v1Calls)
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
// Startup
// ---------------------------------------------------------------------------

func TestNew_Unreachable(t *testing.T) {
	e, err := zitadelconn.New("http://127.0.0.1:1", "app.zitadel.invalid") // nothing listens
	if err != nil {
		t.Fatal(err)
	}
	_, err = zitadel.New(context.Background(), zitadel.Config{
		Issuer: "https://app.zitadel.invalid", ClientID: "client", ClientSecret: "secret",
		HTTPTimeout: 200 * time.Millisecond, Endpoint: e,
	})
	if !errors.Is(err, idp.ErrUnreachable) {
		t.Errorf("want ErrUnreachable when nothing answers at the connect base, got: %v", err)
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

// ---------------------------------------------------------------------------
// Username-from-email normalization (ADR-0093 decision 1)
// ---------------------------------------------------------------------------

// TestEnsureHumanUserNoPassword_UsernameIsNormalizedEmail pins that the
// human-user create derives username from idp.UsernameForEmail(email), not
// the raw email as typed — the instance's domain policy keys username
// uniqueness on this exact string, so a stray case or whitespace difference
// must not mint a second account for the same address.
func TestEnsureHumanUserNoPassword_UsernameIsNormalizedEmail(t *testing.T) {
	const rawEmail = " Alice@Example.COM "
	var gotUserName string
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/zitadel.user.v2.UserService/AddHumanUser") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotUserName = body.Username
		jsonResp(w, http.StatusOK, map[string]string{"userId": "user-1"})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.EnsureHumanUserNoPassword(context.Background(), "org-1", rawEmail, "Invited", "User"); err != nil {
		t.Fatalf("EnsureHumanUserNoPassword: %v", err)
	}
	want := idp.UsernameForEmail(rawEmail)
	if gotUserName != want {
		t.Errorf("username = %q, want %q (normalized)", gotUserName, want)
	}
	if gotUserName == rawEmail {
		t.Errorf("username was sent verbatim as %q, want it normalized", rawEmail)
	}
}

// TestCreateHumanUser_UsernameIsNormalizedEmail is the CreateHumanUser
// analogue of the above, covering the self-serve signup and first-admin
// bootstrap path.
func TestCreateHumanUser_UsernameIsNormalizedEmail(t *testing.T) {
	const rawEmail = " Alice@Example.COM "
	var gotUserName string
	_, cfg := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/users/human") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			UserName string `json:"userName"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotUserName = body.UserName
		jsonResp(w, http.StatusOK, map[string]string{"userId": "user-1"})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		Email:    rawEmail,
		Password: "correct-horse-battery-staple",
	}); err != nil {
		t.Fatalf("CreateHumanUser: %v", err)
	}
	want := idp.UsernameForEmail(rawEmail)
	if gotUserName != want {
		t.Errorf("userName = %q, want %q (normalized)", gotUserName, want)
	}
	if gotUserName == rawEmail {
		t.Errorf("userName was sent verbatim as %q, want it normalized", rawEmail)
	}
}

// ---------------------------------------------------------------------------
// CreateSetupLink tests (hosted#203)
//
// Uses the shared zitadelconntest.Identity fake directly (not setupServer's
// minimal management/v2-prefix router) because CreateInviteCode is a plain
// Connect-JSON call with no REST-gateway path, and because the fake's
// request/response field names (userId, returnCode, inviteCode) come from
// real Zitadel v4.18.0 source, not an assumption — the wire shape this test
// needs to trust, not just exercise.
// ---------------------------------------------------------------------------

// TestCreateSetupLink_BuildsFromTheGivenAppURL is the gibson#254 regression:
// the link must start at the appURL the CALLER passed in, never at the
// client's own configured issuer or Zitadel endpoint. cfg.Issuer here is
// deliberately set to something that is NOT the appURL, so a link built from
// the wrong source is caught immediately rather than by coincidence of both
// values matching in the test fixture.
func TestCreateSetupLink_BuildsFromTheGivenAppURL(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	cfg := testConfig(t, srv)
	cfg.Issuer = "https://this-is-not-the-app-url.invalid"

	orgID := id.AddOrg("tenant-1")
	userID := id.AddUser(orgID, "invitee@example.com")

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	const appURL = "https://app.example.com"
	link, err := client.CreateSetupLink(context.Background(), orgID, userID, appURL)
	if err != nil {
		t.Fatalf("CreateSetupLink: %v", err)
	}
	if !strings.HasPrefix(link, appURL+"/ui/v2/login/verify?") {
		t.Fatalf("link = %q, want it to start at %q (the given appURL) — never at cfg.Issuer or any other endpoint", link, appURL)
	}
	if strings.Contains(link, "this-is-not-the-app-url") {
		t.Errorf("link = %q, leaked cfg.Issuer instead of using the given appURL", link)
	}
	if !strings.Contains(link, "userId="+userID) || !strings.Contains(link, "organization="+orgID) || !strings.Contains(link, "invite=true") {
		t.Errorf("link = %q, want userId, organization and invite=true (the Login v2 verify page)", link)
	}
	wantCode := id.InviteCode(userID)
	if wantCode == "" || !strings.Contains(link, "code="+wantCode) {
		t.Errorf("link = %q, want the code the fake minted (%q) substituted in", link, wantCode)
	}
}

// TestCreateSetupLink_RequiresAppURL: an empty appURL must refuse rather
// than silently mint a link with an empty host.
func TestCreateSetupLink_RequiresAppURL(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	cfg := testConfig(t, srv)
	orgID := id.AddOrg("tenant-1")
	userID := id.AddUser(orgID, "invitee@example.com")

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateSetupLink(context.Background(), orgID, userID, ""); err == nil {
		t.Fatal("expected an error for an empty appURL")
	}
}

// TestCreateSetupLink_NeverSendsCode: the request must use returnCode, never
// sendCode — Zitadel must never email the code itself, since the caller
// already owns messaging for this user.
func TestCreateSetupLink_NeverSendsCode(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	cfg := testConfig(t, srv)
	orgID := id.AddOrg("tenant-1")
	userID := id.AddUser(orgID, "invitee@example.com")

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateSetupLink(context.Background(), orgID, userID, "https://app.example.com"); err != nil {
		t.Fatalf("CreateSetupLink: %v", err)
	}
	// The fake's own state proves it took the returnCode branch: sendCode
	// clears u.inviteCode instead of setting it (see handleCreateInviteCode).
	if id.InviteCode(userID) == "" {
		t.Error("no invite code recorded; CreateSetupLink must call returnCode, not sendCode")
	}
}

// TestCreateSetupLink_UnknownUserIsAnError: the fake 404s an unknown user id,
// and that must surface as an error, not a link built for nobody.
func TestCreateSetupLink_UnknownUserIsAnError(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	cfg := testConfig(t, srv)

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateSetupLink(context.Background(), "org-1", "no-such-user", "https://app.example.com"); err == nil {
		t.Fatal("expected an error for an unknown user id")
	}
}

// TestCreateSetupLink_RequiresUserID: an empty userID must refuse before
// making any call.
func TestCreateSetupLink_RequiresUserID(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	cfg := testConfig(t, srv)

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateSetupLink(context.Background(), "org-1", "", "https://app.example.com"); err == nil {
		t.Fatal("expected an error for an empty userID")
	}
}

// TestCreateSetupLink_EmptyInviteCodeIsAnError guards against silently
// returning a link with no code substituted when Zitadel's response is
// malformed: a 200 OK with no inviteCode field. The shared Identity fake
// never produces this shape for a returnCode request (it is exercised in
// TestCreateSetupLink_NeverSendsCode instead), so this uses a minimal
// handler standing in for a malformed upstream response.
func TestCreateSetupLink_EmptyInviteCodeIsAnError(t *testing.T) {
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zitadel.user.v2.UserService/CreateInviteCode" {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{})
	}))
	cfg := testConfig(t, srv)

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CreateSetupLink(context.Background(), "org-1", "user-1", "https://app.example.com"); err == nil {
		t.Fatal("expected an error for a response with no inviteCode")
	}
}
