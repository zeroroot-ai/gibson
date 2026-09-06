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
	"testing"
	"time"

	vaultapi "github.com/openbao/openbao/api/v2"
)

// TestNew_TokenFromEnv verifies that a token supplied directly is stored.
func TestNew_TokenFromEnv(t *testing.T) {
	t.Parallel()
	r, err := New(context.Background(), "http://127.0.0.1:19999", "test-token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	tok, err := r.Token()
	if err != nil {
		t.Fatalf("Token() returned error: %v", err)
	}
	if tok != "test-token" {
		t.Errorf("Token() = %q, want %q", tok, "test-token")
	}
}

// TestNew_TokenFromFile verifies that tokenPath is read and trimmed.
func TestNew_TokenFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault-token")
	if err := os.WriteFile(path, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := New(context.Background(), "http://127.0.0.1:19999", "", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	tok, err := r.Token()
	if err != nil {
		t.Fatalf("Token() returned error: %v", err)
	}
	if tok != "file-token" {
		t.Errorf("Token() = %q, want %q", tok, "file-token")
	}
}

// TestNew_MissingAddress verifies required address validation.
func TestNew_MissingAddress(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(), "", "tok", "")
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

// TestNew_MissingToken verifies that both token and tokenPath empty is rejected.
func TestNew_MissingToken(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(), "http://127.0.0.1:19999", "", "")
	if err == nil {
		t.Fatal("expected error for empty token and tokenPath")
	}
}

// TestNew_EmptyTokenFile verifies that an all-whitespace token file is
// TOLERATED at startup (deploy#971): New succeeds and Token() returns a
// transient error until a real token appears, so the reconciler requeues
// instead of the pod crash-looping and deadlocking the bringup.
func TestNew_EmptyTokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte("  \n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), "http://127.0.0.1:19999", "", path)
	if err != nil {
		t.Fatalf("New should tolerate an empty token file, got: %v", err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.Token(); err == nil {
		t.Fatal("Token() should error while the token is not yet available")
	}
}

// TestNew_TolerateAbsentThenAcquire verifies the from-zero path (deploy#971):
// New with a tokenPath whose file does not exist yet succeeds; Token() errors
// until the file is written, then returns the token without a pod restart.
func TestNew_TolerateAbsentThenAcquire(t *testing.T) {
	old := acquirePollInterval
	acquirePollInterval = 20 * time.Millisecond
	defer func() { acquirePollInterval = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "vault-token") // does not exist yet

	r, err := New(context.Background(), "http://127.0.0.1:19999", "", path)
	if err != nil {
		t.Fatalf("New should tolerate an absent token file, got: %v", err)
	}
	defer func() { _ = r.Close() }()

	if _, err := r.Token(); err == nil {
		t.Fatal("Token() should error before the token file exists")
	}

	if err := os.WriteFile(path, []byte("late-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if tok, err := r.Token(); err == nil {
			if tok != "late-token" {
				t.Fatalf("Token() = %q, want %q", tok, "late-token")
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("Token() never became available after the file was written")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestClose_Idempotent verifies that Close does not block or panic on repeated calls.
func TestClose_Idempotent(t *testing.T) {
	t.Parallel()
	r, err := New(context.Background(), "http://127.0.0.1:19999", "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close: cancel is idempotent, done is already closed — reading it
	// again would panic. Wrap in goroutine + timeout to detect a hang instead.
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Close blocked")
	}
}

// TestRenewLoop_NonRenewable verifies that interval==0 exits the loop immediately.
func TestRenewLoop_NonRenewable(t *testing.T) {
	t.Parallel()
	r := &Renewer{
		token:  "tok",
		cancel: func() {},
		done:   make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// renewLoop no longer closes r.done (its caller run() owns that); assert it
	// simply returns for a non-renewable (interval==0) token.
	finished := make(chan struct{})
	go func() { r.renewLoop(ctx, nil, 0, ""); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("renewLoop did not exit for interval==0")
	}
}

// TestClampInterval covers the boundary conditions.
func TestClampInterval(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, minRenewInterval},
		{10 * time.Second, minRenewInterval},
		{minRenewInterval, minRenewInterval},
		{5 * time.Minute, 5 * time.Minute},
		{maxRenewInterval, maxRenewInterval},
		{20 * time.Minute, maxRenewInterval},
	}
	for _, tc := range cases {
		got := clampInterval(tc.in)
		if got != tc.want {
			t.Errorf("clampInterval(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestLookupRenewInterval_NonReachableVault verifies that a lookup failure
// returns (0, err) without panicking — so New can proceed without renewal.
func TestLookupRenewInterval_NonReachableVault(t *testing.T) {
	t.Parallel()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = "http://127.0.0.1:19999"
	cfg.Timeout = 100 * time.Millisecond
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("tok")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	interval, err := lookupRenewInterval(ctx, client)
	if interval != 0 {
		t.Errorf("expected 0 interval on unreachable vault, got %v", interval)
	}
	if err == nil {
		t.Error("expected non-nil error on unreachable vault")
	}
}

// fakeVaultTokenServer returns an httptest.Server implementing just enough of
// the Vault HTTP API for the vaulttoken package: GET
// /v1/auth/token/lookup-self and PUT /v1/auth/token/renew-self. Requests
// carrying goodToken succeed; every other X-Vault-Token value gets a 403,
// simulating a rejected placeholder/stale token.
func fakeVaultTokenServer(t *testing.T, goodToken string, renewable bool, ttlSeconds int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != goodToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"renewable":%t,"ttl":%d}}`, renewable, ttlSeconds)
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != goodToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":%d}}`, goodToken, ttlSeconds)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestRenewer_RecoversFromStaleTokenViaTokenPathReread reproduces gibson#1173:
// a from-zero bringup where this process's fast-path read of tokenPath raced
// OpenBao writing the real admin token, so New() cached a stale/placeholder
// value. Before the fix, a LookupSelf failure on that stale token discarded
// the error and handed renewLoop an interval of 0, which returned
// immediately and left Token() returning the bad value with a nil error
// FOREVER — no further attempt, no visible failure, recoverable only by
// restarting the pod. After the fix, the failure is retried indefinitely
// (waitForVerifiedToken) and tokenPath is re-read on every attempt, so
// correcting the file — exactly what happens when OpenBao (re)writes the
// projected Secret — is picked up without recreating the Renewer.
func TestRenewer_RecoversFromStaleTokenViaTokenPathReread(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = 20 * time.Millisecond
	defer func() { retryBackoff = oldBackoff }()

	dir := t.TempDir()
	path := filepath.Join(dir, "vault-token")
	if err := os.WriteFile(path, []byte("stale-placeholder-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := fakeVaultTokenServer(t, "the-real-token", false /* renewable */, 0)

	r, err := New(context.Background(), srv.URL, "", path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Close() }()

	// While the cached token is the stale placeholder, LookupSelf keeps
	// 403ing and Token() must surface that (never silently succeed with a
	// token Vault has already rejected).
	deadline := time.After(2 * time.Second)
	for {
		if _, err := r.Token(); err != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Token() never surfaced the stale-token LookupSelf failure")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Simulate OpenBao correcting the projected Secret in place — no pod
	// restart, no new Renewer.
	if err := os.WriteFile(path, []byte("the-real-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline = time.After(2 * time.Second)
	for {
		tok, err := r.Token()
		if err == nil {
			if tok != "the-real-token" {
				t.Fatalf("Token() = %q, want %q", tok, "the-real-token")
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("Token() never recovered after tokenPath was corrected (no pod restart)")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestWaitForVerifiedToken_CtxCancelledDuringRetryWait verifies that
// cancelling ctx while waitForVerifiedToken is backed off waiting to retry a
// failed LookupSelf returns promptly (-1) instead of blocking for the full
// retryBackoff duration — this is what lets Renewer.Close() during a stuck
// verify loop exit cleanly rather than leaking the goroutine.
func TestWaitForVerifiedToken_CtxCancelledDuringRetryWait(t *testing.T) {
	// Not t.Parallel(): mutates the package-level retryBackoff var, like the
	// other retryBackoff-mutating tests in this file (and the existing
	// acquirePollInterval-mutating TestNew_TolerateAbsentThenAcquire).
	oldBackoff := retryBackoff
	retryBackoff = time.Hour // would hang the test if the ctx.Done() case is not honored
	defer func() { retryBackoff = oldBackoff }()

	cfg := vaultapi.DefaultConfig()
	cfg.Address = "http://127.0.0.1:19999" // nothing listening: LookupSelf fails fast
	cfg.Timeout = 100 * time.Millisecond
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("tok")

	r := &Renewer{token: "tok"}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan time.Duration, 1)
	go func() { done <- r.waitForVerifiedToken(ctx, client, "") }()

	// Give the first (failing) LookupSelf attempt time to run, then cancel
	// while waitForVerifiedToken is parked in its retryBackoff wait.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case interval := <-done:
		if interval != -1 {
			t.Errorf("waitForVerifiedToken() = %v, want -1 (ctx cancelled)", interval)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForVerifiedToken did not return promptly after ctx cancellation")
	}
}

// TestRenewLoop_RecoversAfterRenewSelfFailureViaTokenPathReread verifies the
// same re-read fix applies mid-life: a RenewSelf failure (e.g. the admin
// token was revoked and rotated, not just mis-acquired at startup) must not
// keep retrying forever against the same now-invalid in-memory token.
func TestRenewLoop_RecoversAfterRenewSelfFailureViaTokenPathReread(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = 20 * time.Millisecond
	defer func() { retryBackoff = oldBackoff }()

	dir := t.TempDir()
	path := filepath.Join(dir, "vault-token")
	if err := os.WriteFile(path, []byte("revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := fakeVaultTokenServer(t, "rotated-token", true, 3600)

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("revoked-token")

	r := &Renewer{
		token:  "revoked-token",
		cancel: func() {},
		done:   make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	// Start renewLoop with a short interval so the first RenewSelf attempt
	// (against the revoked token) happens almost immediately.
	go func() { r.renewLoop(ctx, client, 10*time.Millisecond, path); close(finished) }()

	// Confirm the failure is surfaced rather than silently ignored.
	deadline := time.After(2 * time.Second)
	for {
		if _, err := r.Token(); err != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Token() never surfaced the revoked-token RenewSelf failure")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Rotate the token on disk — simulates an operator (or automation)
	// correcting the Secret without restarting the pod.
	if err := os.WriteFile(path, []byte("rotated-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline = time.After(2 * time.Second)
	for {
		if tok, err := r.Token(); err == nil {
			if tok != "rotated-token" {
				t.Fatalf("Token() = %q, want %q", tok, "rotated-token")
			}
			cancel()
			<-finished
			return
		}
		select {
		case <-deadline:
			t.Fatal("renewLoop never recovered after tokenPath was corrected (no pod restart)")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
