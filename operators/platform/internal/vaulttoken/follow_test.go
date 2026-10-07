// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vaulttoken

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeVaultTokens is a fake OpenBao that accepts each token in its set. A test
// adds a token to start a rotation and removes one to revoke it.
type fakeVaultTokens struct {
	mu   sync.Mutex
	good map[string]bool
}

func (f *fakeVaultTokens) set(tok string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.good[tok] = ok
}

func (f *fakeVaultTokens) accepts(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.good[tok]
}

func newFakeVaultTokens(t *testing.T, tokens ...string) (*fakeVaultTokens, *httptest.Server) {
	t.Helper()
	f := &fakeVaultTokens{good: map[string]bool{}}
	for _, tok := range tokens {
		f.good[tok] = true
	}
	answer := func(w http.ResponseWriter, r *http.Request, body string) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.accepts(tok) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, body, tok)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		answer(w, r, `{"data":{"renewable":true,"ttl":3600,"id":%q}}`)
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		answer(w, r, `{"auth":{"client_token":%q,"lease_duration":3600}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func waitForToken(t *testing.T, r *Renewer, want string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if tok, err := r.Token(); err == nil && tok == want {
			return
		}
		select {
		case <-deadline:
			tok, err := r.Token()
			t.Fatalf("Token() = %q, %v; want %q", tok, err, want)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// The sidecar writes a new token while the old one is still valid (ADR-0171).
// The Renewer must move to the new token before the old one is revoked, with
// no renewal failure first.
func TestRenewerFollowsARotatedTokenBeforeTheOldOneIsRevoked(t *testing.T) {
	oldFollow := followInterval
	followInterval = 10 * time.Millisecond
	defer func() { followInterval = oldFollow }()

	vault, srv := newFakeVaultTokens(t, "token-old")
	path := filepath.Join(t.TempDir(), "VAULT_ADMIN_TOKEN")
	if err := os.WriteFile(path, []byte("token-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), srv.URL, "", path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Close() }()
	waitForToken(t, r, "token-old")

	// The sidecar mints the new token and writes it. The old one stays valid.
	vault.set("token-new", true)
	if err := os.WriteFile(path, []byte("token-new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForToken(t, r, "token-new")

	// The sidecar revokes the old token. The Renewer already uses the new one.
	vault.set("token-old", false)
	time.Sleep(50 * time.Millisecond)
	if tok, err := r.Token(); err != nil || tok != "token-new" {
		t.Fatalf("after the revoke Token() = %q, %v; want token-new", tok, err)
	}
}

// A file token that OpenBao refuses is not a rotation. The token in force
// stays, and Token() reports no error.
func TestRenewerIgnoresAFileTokenThatOpenBaoRefuses(t *testing.T) {
	oldFollow := followInterval
	followInterval = 10 * time.Millisecond
	defer func() { followInterval = oldFollow }()

	_, srv := newFakeVaultTokens(t, "token-good")
	path := filepath.Join(t.TempDir(), "VAULT_ADMIN_TOKEN")
	if err := os.WriteFile(path, []byte("token-good"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), srv.URL, "", path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Close() }()
	waitForToken(t, r, "token-good")

	if err := os.WriteFile(path, []byte("token-bogus"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if tok, err := r.Token(); err != nil || tok != "token-good" {
		t.Fatalf("Token() = %q, %v; want token-good to stay in force", tok, err)
	}
}
