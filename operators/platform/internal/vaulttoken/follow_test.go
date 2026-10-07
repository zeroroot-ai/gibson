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

	vaultapi "github.com/openbao/openbao/api/v2"
)

// fakeVaultTokens is a fake OpenBao that accepts each token in its set. A test
// adds a token to start a rotation and removes one to revoke it.
type fakeVaultTokens struct {
	mu        sync.Mutex
	good      map[string]bool
	fixedOnes map[string]bool
}

// setRenewable adds a token that OpenBao accepts, with or without renewal.
func (f *fakeVaultTokens) setRenewable(tok string, renewable bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.good[tok] = true
	f.fixedOnes[tok] = !renewable
}

func (f *fakeVaultTokens) renewable(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.fixedOnes[tok]
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
	f := &fakeVaultTokens{good: map[string]bool{}, fixedOnes: map[string]bool{}}
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
		if !f.renewable(r.Header.Get("X-Vault-Token")) {
			answer(w, r, `{"data":{"renewable":false,"ttl":0,"id":%q}}`)
			return
		}
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

// A file token that OpenBao accepts and that has no renewal still replaces
// the token in force, and the loop keeps following the file.
func TestRenewerFollowsANonRenewableFileToken(t *testing.T) {
	oldFollow := followInterval
	followInterval = 10 * time.Millisecond
	defer func() { followInterval = oldFollow }()

	vault, srv := newFakeVaultTokens(t, "token-old")
	path := filepath.Join(t.TempDir(), "VAULT_ADMIN_TOKEN")
	if err := os.WriteFile(path, []byte("token-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), srv.URL, "", path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Close() }()
	waitForToken(t, r, "token-old")

	vault.setRenewable("token-fixed", false)
	if err := os.WriteFile(path, []byte("token-fixed"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForToken(t, r, "token-fixed")

	vault.set("token-later", true)
	if err := os.WriteFile(path, []byte("token-later"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForToken(t, r, "token-later")
}

// After a move, the client that renews holds the new token, so each later
// renewal sends it.
func TestAMoveSetsTheNewTokenOnTheRenewalClient(t *testing.T) {
	vault, srv := newFakeVaultTokens(t, "token-old")
	path := filepath.Join(t.TempDir(), "VAULT_ADMIN_TOKEN")
	if err := os.WriteFile(path, []byte("token-new"), 0o600); err != nil {
		t.Fatal(err)
	}
	vault.set("token-new", true)
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("token-old")
	r := &Renewer{token: "token-old", cancel: func() {}, done: make(chan struct{})}

	interval, ok := r.followRotatedToken(context.Background(), client, path)
	if !ok {
		t.Fatal("followRotatedToken did not move to an accepted file token")
	}
	if interval <= 0 {
		t.Fatalf("interval = %v, want the renewal interval of the new token", interval)
	}
	if got := client.Token(); got != "token-new" {
		t.Fatalf("the renewal client holds %q, want token-new", got)
	}
	if tok, err := r.Token(); err != nil || tok != "token-new" {
		t.Fatalf("Token() = %q, %v; want token-new", tok, err)
	}
}
