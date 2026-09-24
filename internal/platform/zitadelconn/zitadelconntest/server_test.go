// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// The fake is only useful if it refuses what real Zitadel refuses. These tests
// pin that behavior, so a regression test built on it cannot pass vacuously.

func do(t *testing.T, method, url, instance string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	if instance != "" {
		req.Header.Set(zitadelconn.InstanceHostHeader, instance)
	}
	req.Header.Set("x-zitadel-orgid", "org-1")
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestFake_RefusesARequestThatNamesNoInstance(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	resp := do(t, http.MethodGet, srv.URL+"/.well-known/openid-configuration", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if !strings.Contains(body["message"].(string), "Instance not found") {
		t.Errorf("message = %v, want Zitadel's instance-not-found text", body["message"])
	}
	if srv.Refused() != 1 || len(srv.Requests()) != 0 {
		t.Errorf("refused=%d accepted=%d, want 1 and 0", srv.Refused(), len(srv.Requests()))
	}
}

func TestFake_RefusesAPortedOrWrongInstance(t *testing.T) {
	srv := zitadelconntest.New(t, "app.example.invalid", nil)
	for _, inst := range []string{"app.example.invalid:443", "other.example.invalid"} {
		if resp := do(t, http.MethodPost, srv.URL+"/oauth/v2/token", inst); resp.StatusCode != http.StatusNotFound {
			t.Errorf("instance %q: status = %d, want 404", inst, resp.StatusCode)
		}
	}
	if srv.Refused() != 2 {
		t.Errorf("refused = %d, want 2", srv.Refused())
	}
}

func TestFake_IssuesATokenAndRecordsTheRequest(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	resp := do(t, http.MethodPost, srv.URL+"/oauth/v2/token", srv.Domain)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var tok map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok["access_token"] != zitadelconntest.AccessToken {
		t.Fatalf("token body = %v (%v), want access_token %q", tok, err, zitadelconntest.AccessToken)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %v, want one", reqs)
	}
	r := reqs[0]
	if r.Method != http.MethodPost || r.Path != "/oauth/v2/token" || r.Instance != srv.Domain || r.OrgID != "org-1" || r.Auth != "Bearer abc" {
		t.Errorf("recorded %+v", r)
	}
	if !srv.HasPath(http.MethodPost, "/oauth/v2/token") || srv.HasPath(http.MethodGet, "/oauth/v2/token") {
		t.Errorf("HasPath disagrees with the recorded request: %v", srv.Paths())
	}
}

func TestFake_NilHandlerAnswers404AndAHandlerServes(t *testing.T) {
	bare := zitadelconntest.New(t, "", nil)
	if resp := do(t, http.MethodGet, bare.URL+"/management/v1/users/me", bare.Domain); resp.StatusCode != http.StatusNotFound {
		t.Errorf("nil handler: status = %d, want 404", resp.StatusCode)
	}

	served := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	if resp := do(t, http.MethodGet, served.URL+"/management/v1/users/me", served.Domain); resp.StatusCode != http.StatusTeapot {
		t.Errorf("handler: status = %d, want the handler's 418", resp.StatusCode)
	}
	if got := served.Paths(); len(got) != 1 || got[0] != "GET /management/v1/users/me" {
		t.Errorf("Paths = %v", got)
	}
}

func TestFake_EndpointIsWhatACorrectClientUses(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	e := srv.Endpoint(t)
	if e.BaseURL() != srv.URL || e.Host() != srv.Domain {
		t.Errorf("endpoint = %s claiming %s, want %s claiming %s", e.BaseURL(), e.Host(), srv.URL, srv.Domain)
	}
}
