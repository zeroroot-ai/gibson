// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// setupManagementServer stands up an httptest server serving OIDC discovery +
// token (so zitadel.New succeeds) and routes /management/v1/users/... calls to
// the provided handler.
func setupManagementServer(t *testing.T, handler http.HandlerFunc) zitadel.Config {
	t.Helper()
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/management/v1/users/") {
			handler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	return testConfig(t, srv)
}

// TestClearHumanFactors_RemovesEveryRegisteredType proves the three
// credential families (TOTP, U2F, passkeys/passwordless) are each listed and
// each entry removed, matching the field names confirmed against the
// vendored Zitadel v4.18.0 proto/zitadel/user.proto (AuthFactor's oneof
// otp/u2f, WebAuthNToken.id).
func TestClearHumanFactors_RemovesEveryRegisteredType(t *testing.T) {
	var deletedPaths []string
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[
				{"state":"AUTH_FACTOR_STATE_READY","otp":{}},
				{"state":"AUTH_FACTOR_STATE_READY","u2f":{"id":"u2f-1","name":"key one"}},
				{"state":"AUTH_FACTOR_STATE_READY","u2f":{"id":"u2f-2","name":"key two"}}
			]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[{"id":"pk-1","state":"AUTH_FACTOR_STATE_READY","name":"face"}]}`))
		case r.Method == http.MethodDelete:
			deletedPaths = append(deletedPaths, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	res, err := client.ClearHumanFactors(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ClearHumanFactors: %v", err)
	}
	if !res.OTPCleared {
		t.Error("expected OTPCleared=true")
	}
	if res.U2FCleared != 2 {
		t.Errorf("U2FCleared = %d, want 2", res.U2FCleared)
	}
	if res.PasskeysCleared != 1 {
		t.Errorf("PasskeysCleared = %d, want 1", res.PasskeysCleared)
	}

	wantSuffixes := []string{
		"/auth_factors/otp",
		"/auth_factors/u2f/u2f-1",
		"/auth_factors/u2f/u2f-2",
		"/passwordless/pk-1",
	}
	for _, want := range wantSuffixes {
		found := false
		for _, got := range deletedPaths {
			if strings.HasSuffix(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a DELETE to a path ending %q; got deletes %v", want, deletedPaths)
		}
	}
}

// TestClearHumanFactors_NoFactors_NoOp proves a user with nothing registered
// yields an all-zero result and no DELETE calls, not an error.
func TestClearHumanFactors_NoFactors_NoOp(t *testing.T) {
	var deleteCalls int
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodDelete:
			deleteCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	res, err := client.ClearHumanFactors(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ClearHumanFactors: %v", err)
	}
	if res.OTPCleared || res.U2FCleared != 0 || res.PasskeysCleared != 0 {
		t.Errorf("expected all-zero result, got %+v", res)
	}
	if deleteCalls != 0 {
		t.Errorf("expected no DELETE calls, got %d", deleteCalls)
	}
}

// TestClearHumanFactors_RequiresUserID proves the client refuses to call
// upstream with an empty user id.
func TestClearHumanFactors_RequiresUserID(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty userID")
	}
}

// TestClearHumanFactors_ListAuthFactorsError propagates a failure listing
// second factors.
func TestClearHumanFactors_ListAuthFactorsError(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/auth_factors/_search") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), "user-1"); err == nil {
		t.Fatal("expected an error when listing auth factors fails")
	}
}

// TestClearHumanFactors_ListPasswordlessError propagates a failure listing
// passkeys, distinct from the auth-factors list call.
func TestClearHumanFactors_ListPasswordlessError(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), "user-1"); err == nil {
		t.Fatal("expected an error when listing passkeys fails")
	}
}

// TestClearHumanFactors_RemoveNotFoundIsIdempotent proves a 404 on an
// individual remove (the credential vanished between list and delete) does
// not fail the whole operation.
func TestClearHumanFactors_RemoveNotFoundIsIdempotent(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[{"state":"AUTH_FACTOR_STATE_READY","otp":{}}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	res, err := client.ClearHumanFactors(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ClearHumanFactors: %v", err)
	}
	if !res.OTPCleared {
		t.Error("expected OTPCleared=true even though the remove 404'd")
	}
}

// TestClearHumanFactors_RemoveU2FNonNotFoundErrorFails proves a real failure
// (not 404) removing a credential surfaces to the caller.
func TestClearHumanFactors_RemoveU2FNonNotFoundErrorFails(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[{"state":"AUTH_FACTOR_STATE_READY","u2f":{"id":"u2f-1","name":"key"}}]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), "user-1"); err == nil {
		t.Fatal("expected a non-404 remove failure to surface")
	}
}

// TestClearHumanFactors_RemoveOTPNonNotFoundErrorFails is the OTP-branch
// twin of TestClearHumanFactors_RemoveU2FNonNotFoundErrorFails: a real
// failure removing the authenticator-app factor also surfaces.
func TestClearHumanFactors_RemoveOTPNonNotFoundErrorFails(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[{"state":"AUTH_FACTOR_STATE_READY","otp":{}}]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), "user-1"); err == nil {
		t.Fatal("expected a non-404 OTP remove failure to surface")
	}
}

// TestClearHumanFactors_SkipsU2FWithEmptyID proves a U2F entry with no id
// (a malformed or unexpected upstream response) is skipped rather than
// attempted as a delete with an empty path segment.
func TestClearHumanFactors_SkipsU2FWithEmptyID(t *testing.T) {
	var deleteCalls int
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[{"state":"AUTH_FACTOR_STATE_READY","u2f":{"id":"","name":"key"}}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodDelete:
			deleteCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	res, err := client.ClearHumanFactors(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ClearHumanFactors: %v", err)
	}
	if res.U2FCleared != 0 {
		t.Errorf("U2FCleared = %d, want 0 for an empty-id entry", res.U2FCleared)
	}
	if deleteCalls != 0 {
		t.Errorf("expected no DELETE call for an empty-id U2F entry, got %d", deleteCalls)
	}
}

// TestClearHumanFactors_SkipsPasskeyWithEmptyID is the passkey-branch twin
// of TestClearHumanFactors_SkipsU2FWithEmptyID.
func TestClearHumanFactors_SkipsPasskeyWithEmptyID(t *testing.T) {
	var deleteCalls int
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[{"id":"","state":"AUTH_FACTOR_STATE_READY","name":"face"}]}`))
		case r.Method == http.MethodDelete:
			deleteCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	res, err := client.ClearHumanFactors(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ClearHumanFactors: %v", err)
	}
	if res.PasskeysCleared != 0 {
		t.Errorf("PasskeysCleared = %d, want 0 for an empty-id entry", res.PasskeysCleared)
	}
	if deleteCalls != 0 {
		t.Errorf("expected no DELETE call for an empty-id passkey entry, got %d", deleteCalls)
	}
}

// TestClearHumanFactors_RemovePasskeyNonNotFoundErrorFails is the passkey
// twin of TestClearHumanFactors_RemoveU2FNonNotFoundErrorFails.
func TestClearHumanFactors_RemovePasskeyNonNotFoundErrorFails(t *testing.T) {
	cfg := setupManagementServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth_factors/_search"):
			_, _ = w.Write([]byte(`{"result":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/passwordless/_search"):
			_, _ = w.Write([]byte(`{"result":[{"id":"pk-1","state":"AUTH_FACTOR_STATE_READY","name":"face"}]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if _, err := client.ClearHumanFactors(context.Background(), "user-1"); err == nil {
		t.Fatal("expected a non-404 passkey remove failure to surface")
	}
}
