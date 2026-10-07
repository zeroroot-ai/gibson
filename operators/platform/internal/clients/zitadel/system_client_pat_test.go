// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"net/http"
	"sort"
	"testing"
	"time"
)

// patServer is a fake Zitadel with one org, one machine user and a set of
// personal access tokens, the API surface of a token rotation (ADR-0171).
type patServer struct {
	pats    map[string]bool // token id -> exists
	removed []string
	minted  int
	orgSeen []string
}

func (p *patServer) routes(t *testing.T) map[string]http.HandlerFunc {
	t.Helper()
	return map[string]http.HandlerFunc{
		"GET /admin/v1/orgs/default": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"org":{"id":"org-1"}}`))
		},
		"POST /management/v1/users/_search": func(w http.ResponseWriter, r *http.Request) {
			p.orgSeen = append(p.orgSeen, r.Header.Get("x-zitadel-orgid"))
			_, _ = w.Write([]byte(`{"result":[{"id":"user-1"}]}`))
		},
		"POST /management/v1/users/user-1/pats": func(w http.ResponseWriter, r *http.Request) {
			p.orgSeen = append(p.orgSeen, r.Header.Get("x-zitadel-orgid"))
			p.minted++
			id := "pat-new"
			p.pats[id] = true
			_, _ = w.Write([]byte(`{"tokenId":"` + id + `","token":"secret-new"}`))
		},
		"POST /management/v1/users/user-1/pats/_search": func(w http.ResponseWriter, _ *http.Request) {
			ids := make([]string, 0, len(p.pats))
			for id := range p.pats {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			body := `{"result":[`
			for i, id := range ids {
				if i > 0 {
					body += ","
				}
				body += `{"id":"` + id + `"}`
			}
			_, _ = w.Write([]byte(body + `]}`))
		},
		"DELETE /management/v1/users/user-1/pats/pat-old-1": p.del("pat-old-1"),
		"DELETE /management/v1/users/user-1/pats/pat-old-2": p.del("pat-old-2"),
		"DELETE /management/v1/users/user-1/pats/pat-new":   p.del("pat-new"),
		"GET /auth/v1/users/me": func(w http.ResponseWriter, r *http.Request) {
			if bearerFromAuth(r) != "secret-new" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":16}`))
				return
			}
			_, _ = w.Write([]byte(`{"user":{"id":"user-1"}}`))
		},
	}
}

func (p *patServer) del(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		delete(p.pats, id)
		p.removed = append(p.removed, id)
		_, _ = w.Write([]byte(`{}`))
	}
}

func newPATClient(t *testing.T, p *patServer) SystemClient {
	t.Helper()
	srv := newFakeServer(t, p.routes(t))
	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", testDomain, writeKeyFile(t, generateTestRSAKey(t)))
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	return sc
}

func TestMintUserTokenReturnsTheIDAndTheToken(t *testing.T) {
	p := &patServer{pats: map[string]bool{"pat-old-1": true}}
	sc := newPATClient(t, p)
	userID, pat, err := sc.MintUserToken(context.Background(), "login-client", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	if userID != "user-1" || pat.ID != "pat-new" || pat.Token != "secret-new" {
		t.Fatalf("got user %q pat %+v", userID, pat)
	}
	for _, org := range p.orgSeen {
		if org != "org-1" {
			t.Fatalf("a management call carried org %q, want org-1", org)
		}
	}
}

func TestRemoveOtherTokensKeepsOnlyTheNamedToken(t *testing.T) {
	p := &patServer{pats: map[string]bool{"pat-old-1": true, "pat-old-2": true, "pat-new": true}}
	sc := newPATClient(t, p)
	n, err := sc.RemoveOtherTokens(context.Background(), "user-1", "pat-new")
	if err != nil {
		t.Fatalf("RemoveOtherTokens: %v", err)
	}
	if n != 2 || len(p.pats) != 1 || !p.pats["pat-new"] {
		t.Fatalf("removed %d, left %v; want only pat-new", n, p.pats)
	}
}

func TestRemoveOtherTokensRefusesAnEmptyKeepID(t *testing.T) {
	p := &patServer{pats: map[string]bool{"pat-new": true}}
	sc := newPATClient(t, p)
	if _, err := sc.RemoveOtherTokens(context.Background(), "user-1", ""); err == nil {
		t.Fatal("an empty kept id would remove every token; it must be refused")
	}
	if len(p.removed) != 0 {
		t.Fatalf("removed %v", p.removed)
	}
}

func TestTokenValidAcceptsAWorkingTokenAndRefusesAnother(t *testing.T) {
	sc := newPATClient(t, &patServer{pats: map[string]bool{}})
	if ok, err := sc.TokenValid(context.Background(), "secret-new"); err != nil || !ok {
		t.Fatalf("working token: ok=%v err=%v", ok, err)
	}
	if ok, err := sc.TokenValid(context.Background(), "secret-old"); err != nil || ok {
		t.Fatalf("refused token: ok=%v err=%v", ok, err)
	}
}
