// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for EnsureHumanUserNoPassword and CreateSetupInviteCode — the
// no-password setup-link mechanism this client reuses from the Platform
// owner work (ADR-0093 decisions 6/8, hosted#201/#202).
package zitadel_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// setupUserServiceV2Server starts a fake Zitadel that routes v2 UserService
// Connect calls (path prefix "/zitadel.user.v2.UserService/") to v2Handler,
// and v1 Management user search calls to searchHandler (used by the
// EnsureHumanUserNoPassword conflict-lookup fallback, which reuses the same
// v1 search every other by-email resolve in this client uses).
func setupUserServiceV2Server(t *testing.T, v2Handler, searchHandler http.HandlerFunc) zitadel.Config {
	t.Helper()
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/zitadel.user.v2.UserService/"):
			v2Handler(w, r)
		case r.URL.Path == "/management/v1/users/_search":
			if searchHandler == nil {
				http.NotFound(w, r)
				return
			}
			searchHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	return testConfig(t, srv)
}

func decodeBody(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
	}
	return m
}

func TestEnsureHumanUserNoPassword_HappyPath_NeverSendsPassword(t *testing.T) {
	var gotBody map[string]interface{}
	var gotOrgHeader string
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zitadel.user.v2.UserService/AddHumanUser" {
			http.NotFound(w, r)
			return
		}
		gotOrgHeader = r.Header.Get("x-zitadel-orgid")
		gotBody = decodeBody(t, r)
		jsonResp(w, http.StatusOK, map[string]string{"userId": "user-new"})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	userID, err := client.EnsureHumanUserNoPassword(context.Background(), "org-tenant-1", "owner@acme.example", "Ada", "Owner")
	if err != nil {
		t.Fatalf("EnsureHumanUserNoPassword: %v", err)
	}
	if userID != "user-new" {
		t.Errorf("userID = %q, want user-new", userID)
	}
	if gotOrgHeader != "org-tenant-1" {
		t.Errorf("x-zitadel-orgid header = %q, want org-tenant-1 (AddHumanUser resolves org from the header, not a body field)", gotOrgHeader)
	}
	if _, hasOrg := gotBody["organization"]; hasOrg {
		t.Errorf("body carries an organization field: %v — AddHumanUser resolves org from the header only", gotBody["organization"])
	}
	if _, hasPassword := gotBody["password"]; hasPassword {
		t.Fatal("request body carries a password field — no password may ever be sent (ADR-0093)")
	}
	prof, _ := gotBody["profile"].(map[string]interface{})
	if prof["givenName"] != "Ada" || prof["familyName"] != "Owner" {
		t.Errorf("profile = %v, want givenName=Ada familyName=Owner", prof)
	}
	email, _ := gotBody["email"].(map[string]interface{})
	if email["isVerified"] != true {
		t.Errorf("email.isVerified = %v, want true", email["isVerified"])
	}
}

func TestEnsureHumanUserNoPassword_Conflict_FallsBackToSearch(t *testing.T) {
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusConflict, "ALREADY_EXISTS", "user already exists")
	}, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{
			"result": []map[string]string{{"id": "user-existing"}},
		})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	userID, err := client.EnsureHumanUserNoPassword(context.Background(), "org-tenant-1", "owner@acme.example", "Ada", "Owner")
	if err != nil {
		t.Fatalf("EnsureHumanUserNoPassword: %v", err)
	}
	if userID != "user-existing" {
		t.Errorf("userID = %q, want user-existing (resolved via the conflict fallback search)", userID)
	}
}

func TestEnsureHumanUserNoPassword_ConflictThenNotFound_ReturnsError(t *testing.T) {
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusConflict, "ALREADY_EXISTS", "user already exists")
	}, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, http.StatusOK, map[string]interface{}{"result": []map[string]string{}})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.EnsureHumanUserNoPassword(context.Background(), "org-tenant-1", "owner@acme.example", "Ada", "Owner"); err == nil {
		t.Fatal("expected an error when the conflict fallback search finds nothing")
	}
}

func TestEnsureHumanUserNoPassword_ServerError_ReturnsWrappedError(t *testing.T) {
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusInternalServerError, "INTERNAL", "boom")
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.EnsureHumanUserNoPassword(context.Background(), "org-1", "owner@acme.example", "Ada", "Owner"); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

func TestEnsureHumanUserNoPassword_EmptyEmail_ReturnsErrorWithoutRequest(t *testing.T) {
	called := false
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		jsonResp(w, http.StatusOK, map[string]string{"userId": "should-not-be-used"})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.EnsureHumanUserNoPassword(context.Background(), "org-1", "", "Ada", "Owner"); err == nil {
		t.Fatal("expected an error for an empty email")
	}
	if called {
		t.Error("expected no request to be sent for an empty email")
	}
}

func TestCreateSetupInviteCode_Send_UsesSendCode(t *testing.T) {
	var gotBody map[string]interface{}
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zitadel.user.v2.UserService/CreateInviteCode" {
			http.NotFound(w, r)
			return
		}
		gotBody = decodeBody(t, r)
		jsonResp(w, http.StatusOK, map[string]string{})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	code, err := client.CreateSetupInviteCode(context.Background(), "user-1", "https://app.example.com/invite", true)
	if err != nil {
		t.Fatalf("CreateSetupInviteCode: %v", err)
	}
	if code != "" {
		t.Errorf("code = %q, want empty when send=true (Zitadel emails the link and returns no usable code)", code)
	}
	if gotBody["userId"] != "user-1" {
		t.Errorf("userId = %v, want user-1", gotBody["userId"])
	}
	sendCode, _ := gotBody["sendCode"].(map[string]interface{})
	if sendCode == nil {
		t.Fatal("expected a sendCode field in the request body when send=true")
	}
	if sendCode["urlTemplate"] != "https://app.example.com/invite" {
		t.Errorf("sendCode.urlTemplate = %v, want https://app.example.com/invite", sendCode["urlTemplate"])
	}
	if _, hasReturn := gotBody["returnCode"]; hasReturn {
		t.Error("expected no returnCode field when send=true")
	}
}

func TestCreateSetupInviteCode_Offline_ReturnsRawCode(t *testing.T) {
	var gotBody map[string]interface{}
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody = decodeBody(t, r)
		jsonResp(w, http.StatusOK, map[string]string{"inviteCode": "raw-one-time-code"})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	code, err := client.CreateSetupInviteCode(context.Background(), "user-1", "https://app.example.com/invite", false)
	if err != nil {
		t.Fatalf("CreateSetupInviteCode: %v", err)
	}
	if code != "raw-one-time-code" {
		t.Errorf("code = %q, want raw-one-time-code", code)
	}
	if _, hasReturn := gotBody["returnCode"]; !hasReturn {
		t.Error("expected a returnCode field in the request body when send=false")
	}
	if _, hasSend := gotBody["sendCode"]; hasSend {
		t.Error("expected no sendCode field when send=false")
	}
}

func TestCreateSetupInviteCode_ServerError_ReturnsWrappedError(t *testing.T) {
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		errorResp(w, http.StatusInternalServerError, "INTERNAL", "boom")
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.CreateSetupInviteCode(context.Background(), "user-1", "https://app.example.com/invite", true); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

func TestCreateSetupInviteCode_EmptyUserID_ReturnsErrorWithoutRequest(t *testing.T) {
	called := false
	cfg := setupUserServiceV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		jsonResp(w, http.StatusOK, map[string]string{"inviteCode": "x"})
	}, nil)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.CreateSetupInviteCode(context.Background(), "", "https://app.example.com/invite", false); err == nil {
		t.Fatal("expected an error for an empty userID")
	}
	if called {
		t.Error("expected no request to be sent for an empty userID")
	}
}
