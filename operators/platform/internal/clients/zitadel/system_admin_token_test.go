// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// fakeAdminZitadel answers the five calls of the admin token mint, as Zitadel
// v4.19.4 did in the proof of gibson#794. existingUser makes the user search
// find the machine user. It records the org header of each Management call.
func fakeAdminZitadel(t *testing.T, existingUser bool, created *int, orgHeaders *[]string) map[string]http.HandlerFunc {
	t.Helper()
	jsonOK := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	return map[string]http.HandlerFunc{
		"GET /admin/v1/orgs/default": func(w http.ResponseWriter, r *http.Request) {
			if bearerFromAuth(r) == "revoked-pat" {
				http.Error(w, `{"code":16}`, http.StatusUnauthorized)
				return
			}
			jsonOK(w, `{"org":{"id":"org-1"}}`)
		},
		"POST /management/v1/users/_search": func(w http.ResponseWriter, r *http.Request) {
			*orgHeaders = append(*orgHeaders, r.Header.Get("x-zitadel-orgid"))
			if existingUser {
				jsonOK(w, `{"result":[{"id":"user-old"}]}`)
				return
			}
			jsonOK(w, `{}`)
		},
		"POST /management/v1/users/machine": func(w http.ResponseWriter, r *http.Request) {
			*orgHeaders = append(*orgHeaders, r.Header.Get("x-zitadel-orgid"))
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["userName"] != "iam-admin" {
				t.Errorf("machine user name = %v", body["userName"])
			}
			*created++
			jsonOK(w, `{"userId":"user-new"}`)
		},
		"POST /admin/v1/members": func(w http.ResponseWriter, _ *http.Request) {
			if existingUser {
				http.Error(w, `{"code":6,"message":"Errors.Instance.Member.AlreadyExists"}`, http.StatusConflict)
				return
			}
			jsonOK(w, `{}`)
		},
		"POST /management/v1/users/user-new/pats": func(w http.ResponseWriter, r *http.Request) {
			*orgHeaders = append(*orgHeaders, r.Header.Get("x-zitadel-orgid"))
			jsonOK(w, `{"tokenId":"pat-id-new","token":"new-pat"}`)
		},
		"POST /management/v1/users/user-old/pats": func(w http.ResponseWriter, _ *http.Request) {
			jsonOK(w, `{"tokenId":"pat-id-another","token":"another-pat"}`)
		},
	}
}

func adminSystemClient(t *testing.T, routes map[string]http.HandlerFunc) SystemClient {
	t.Helper()
	srv := newFakeServer(t, routes)
	c, err := NewSystemClient(srv.URL, "gibson-system-bot", "auth.example.org", writeKeyFile(t, generateTestRSAKey(t)))
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	return c
}

// On an instance with no admin user, the mint creates the machine user, makes
// it IAM_OWNER and returns its token. Each Management call names the default
// organization.
func TestMintAdminToken_FreshInstance(t *testing.T) {
	var created int
	var orgs []string
	c := adminSystemClient(t, fakeAdminZitadel(t, false, &created, &orgs))
	userID, pat, err := c.MintAdminToken(context.Background(), "iam-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("MintAdminToken: %v", err)
	}
	if userID != "user-new" || pat.Token != "new-pat" || pat.ID != "pat-id-new" || created != 1 {
		t.Fatalf("user=%q pat=%q created=%d", userID, pat, created)
	}
	for _, o := range orgs {
		if o != "org-1" {
			t.Errorf("a Management call named the org %q, want org-1", o)
		}
	}
}

// On an instance that has the user, the mint reuses it, and an existing
// membership is not an error.
func TestMintAdminToken_ExistingUser(t *testing.T) {
	var created int
	var orgs []string
	c := adminSystemClient(t, fakeAdminZitadel(t, true, &created, &orgs))
	userID, pat, err := c.MintAdminToken(context.Background(), "iam-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("MintAdminToken: %v", err)
	}
	if userID != "user-old" || pat.Token != "another-pat" || created != 0 {
		t.Fatalf("user=%q pat=%q created=%d", userID, pat, created)
	}
}

func TestAdminTokenValid(t *testing.T) {
	var created int
	var orgs []string
	c := adminSystemClient(t, fakeAdminZitadel(t, false, &created, &orgs))
	if ok, err := c.AdminTokenValid(context.Background(), "good-pat"); !ok || err != nil {
		t.Errorf("good token: %v %v", ok, err)
	}
	if ok, err := c.AdminTokenValid(context.Background(), "revoked-pat"); ok || err != nil {
		t.Errorf("revoked token: %v %v, want false and no error", ok, err)
	}
	if ok, err := c.AdminTokenValid(context.Background(), ""); ok || err != nil {
		t.Errorf("empty token: %v %v", ok, err)
	}
}

// Each step of the mint that fails, or that answers with no id or token,
// fails the mint. No partial result returns.
func TestMintAdminToken_EachStepCanFail(t *testing.T) {
	fail := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":13}`, http.StatusInternalServerError)
	}
	empty := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}
	cases := map[string]map[string]http.HandlerFunc{
		"default org fails":      {"GET /admin/v1/orgs/default": fail},
		"default org has no id":  {"GET /admin/v1/orgs/default": empty},
		"user search fails":      {"POST /management/v1/users/_search": fail},
		"user create fails":      {"POST /management/v1/users/machine": fail},
		"created user has no id": {"POST /management/v1/users/machine": empty},
		"membership fails":       {"POST /admin/v1/members": fail},
		"token mint fails":       {"POST /management/v1/users/user-new/pats": fail},
		"minted token is empty":  {"POST /management/v1/users/user-new/pats": empty},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			var created int
			var orgs []string
			routes := fakeAdminZitadel(t, false, &created, &orgs)
			for k, h := range override {
				routes[k] = h
			}
			c := adminSystemClient(t, routes)
			userID, pat, err := c.MintAdminToken(context.Background(), "iam-admin", time.Now().Add(time.Hour))
			if err == nil || userID != "" || pat != (PAT{}) {
				t.Fatalf("got user=%q pat=%q err=%v, want an error and no result", userID, pat, err)
			}
		})
	}

	c := adminSystemClient(t, map[string]http.HandlerFunc{})
	if _, _, err := c.MintAdminToken(context.Background(), "", time.Now()); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("no user name: %v, want ErrInvalidInput", err)
	}
}

// A token check that fails for a reason other than a refused token returns
// the error.
func TestAdminTokenValid_OtherErrorReturns(t *testing.T) {
	c := adminSystemClient(t, map[string]http.HandlerFunc{
		"GET /admin/v1/orgs/default": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"code":13}`, http.StatusInternalServerError)
		},
	})
	if ok, err := c.AdminTokenValid(context.Background(), "some-pat"); ok || err == nil {
		t.Errorf("got %v %v, want false and an error", ok, err)
	}
}
