package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// MintUserPAT — table-driven, exercises every branch
// ---------------------------------------------------------------------------

// TestMintUserPAT_FirstTimeNoExistingPAT covers the happy bootstrap path:
// no existing service user, no existing PAT → user created, PAT minted,
// returned with rotated=true.
func TestMintUserPAT_FirstTimeNoExistingPAT(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/_search"):
			// User not found yet.
			jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/machine"):
			jsonRespB(w, http.StatusOK, map[string]string{"userId": "u-1"})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/pats/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/u-1/pats"):
			jsonRespB(w, http.StatusOK, map[string]string{"token": "fresh-pat-secret"})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/admin/v1/members"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	})

	c := newPATClient(cfg)
	res, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "gibson-signup-bot",
		Roles:    []string{"IAM_USER_MANAGER"},
		Rotate:   false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.UserID != "u-1" {
		t.Errorf("UserID: got %q, want u-1", res.UserID)
	}
	if res.PAT != "fresh-pat-secret" {
		t.Errorf("PAT: got %q, want fresh-pat-secret", res.PAT)
	}
	if !res.Rotated {
		t.Error("Rotated should be true on first-time mint")
	}
}

// TestMintUserPAT_UserExistsNoPAT covers the path where the user already
// exists but has no active PATs (e.g. a prior PAT was manually revoked).
// Expected: fresh mint, rotated=true.
func TestMintUserPAT_UserExistsNoPAT(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "u-existing"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/pats/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{"result": []interface{}{}})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/u-existing/pats"):
			jsonRespB(w, http.StatusOK, map[string]string{"token": "minted-token"})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/admin/v1/members"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	})

	c := newPATClient(cfg)
	res, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "gibson-signup-bot",
		Roles:    []string{"IAM_USER_MANAGER"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.UserID != "u-existing" || res.PAT != "minted-token" || !res.Rotated {
		t.Errorf("got %+v", res)
	}
}

// TestMintUserPAT_ExistingPATNoRotate covers the error path: user exists with
// at least one active PAT, but --rotate was not passed. Zitadel's list API
// doesn't return PAT secrets, so we can't return one — must error.
func TestMintUserPAT_ExistingPATNoRotate(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "u-1"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/pats/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "pat-existing"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/admin/v1/members"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, path)
		}
	})

	c := newPATClient(cfg)
	_, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "gibson-signup-bot",
		Rotate:   false,
	})
	if err == nil {
		t.Fatal("expected error when PAT exists and --rotate not passed")
	}
	if !strings.Contains(err.Error(), "--rotate") {
		t.Errorf("error should mention --rotate; got: %v", err)
	}
}

// TestMintUserPAT_ExistingPATRotate covers the rotation path: existing PAT
// is revoked, fresh PAT is returned.
func TestMintUserPAT_ExistingPATRotate(t *testing.T) {
	var deletedPAT string
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "u-1"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/pats/_search"):
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"id": "pat-old"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/users/u-1/pats"):
			jsonRespB(w, http.StatusOK, map[string]string{"token": "rotated-token"})
		case r.Method == http.MethodDelete && strings.HasSuffix(path, "/users/u-1/pats/pat-old"):
			deletedPAT = "pat-old"
			jsonRespB(w, http.StatusOK, map[string]interface{}{})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, path)
		}
	})

	c := newPATClient(cfg)
	res, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "gibson-signup-bot",
		Rotate:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PAT != "rotated-token" {
		t.Errorf("PAT: got %q, want rotated-token", res.PAT)
	}
	if !res.Rotated {
		t.Error("Rotated should be true")
	}
	if deletedPAT != "pat-old" {
		t.Errorf("expected pat-old to be deleted; got %q", deletedPAT)
	}
}

// TestMintUserPAT_AmbiguousUsername covers the safety path: two service users
// with the same username (shouldn't happen, but covered as fail-closed).
func TestMintUserPAT_AmbiguousUsername(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/users/_search") {
			jsonRespB(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{
					{"id": "u-1"},
					{"id": "u-2"},
				},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, path)
	})

	c := newPATClient(cfg)
	_, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "duplicate-name",
	})
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error should mention ambiguity; got: %v", err)
	}
}

// TestMintUserPAT_APIError covers a 5xx from Zitadel mid-flow — returns
// error with non-zero exit.
func TestMintUserPAT_APIError(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	})

	c := newPATClient(cfg)
	_, err := c.MintUserPAT(context.Background(), MintUserPATRequest{
		Username: "gibson-signup-bot",
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestMintUserPAT_EmptyUsername covers the early-return validation.
func TestMintUserPAT_EmptyUsername(t *testing.T) {
	_, cfg := setupBootstrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called when username is empty")
	})

	c := newPATClient(cfg)
	_, err := c.MintUserPAT(context.Background(), MintUserPATRequest{Username: ""})
	if err == nil {
		t.Fatal("expected error on empty username")
	}
}

// Unused import shake-out — keeps json package referenced if a future case
// adds inline JSON assertions.
var _ = json.RawMessage(nil)
