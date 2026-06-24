package vaulttoken

import (
	"context"
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
	go func() { r.renewLoop(ctx, nil, 0); close(finished) }()
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
