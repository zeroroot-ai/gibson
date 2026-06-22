package jwtsource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// makeTestToken returns a JWT-shaped string with the given expiry unix
// timestamp embedded in the payload's `exp` claim. The header and
// signature segments are fixed strings — the cache only reads the payload.
func makeTestToken(expUnix int64) string {
	payload, _ := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{Exp: expUnix})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// mockJWTSource is a configurable test double for JWTSource.
// tokens[i] is returned on call i. If i >= len(tokens), the last token is
// repeated. errs[i], if non-nil, takes precedence over tokens[i].
type mockJWTSource struct {
	mu     sync.Mutex
	n      int      // number of Token calls so far (guarded by mu)
	tokens []string // tokens returned in sequence; last is repeated
	errs   []error  // parallel slice; non-nil entry returned instead of token
}

func newMockSource(tokens ...string) *mockJWTSource {
	return &mockJWTSource{tokens: tokens}
}

func (m *mockJWTSource) Token(_ context.Context, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := m.n
	m.n++

	// Check error slot first.
	if idx < len(m.errs) && m.errs[idx] != nil {
		return "", m.errs[idx]
	}
	if idx < len(m.tokens) {
		return m.tokens[idx], nil
	}
	if len(m.tokens) > 0 {
		return m.tokens[len(m.tokens)-1], nil
	}
	return "", errors.New("mockJWTSource: no token configured")
}

func (m *mockJWTSource) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

// testLogger returns a *slog.Logger writing to stdout (captured by go test).
func testLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestJWTCache_SatisfiesJWTSource is a compile-time assertion.
func TestJWTCache_SatisfiesJWTSource(t *testing.T) {
	t.Parallel()
	var _ JWTSource = (*JWTCache)(nil)
}

// TestJWTCache_HappyPath verifies that after Start, Token returns the cached
// value WITHOUT calling the underlying source again.
func TestJWTCache_HappyPath(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(1 * time.Hour).Unix()
	tok := makeTestToken(exp)
	src := newMockSource(tok)

	cache := NewJWTCache(src, "vault-aud", testLogger(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cache.Close() //nolint:errcheck

	callsAfterStart := src.callCount() // should be exactly 1

	got, err := cache.Token(ctx, "vault-aud")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != tok {
		t.Errorf("Token = %q, want %q", got, tok)
	}

	// Underlying source must not have been called by Token itself.
	if src.callCount() != callsAfterStart {
		t.Errorf("underlying source called %d extra times after start, want 0",
			src.callCount()-callsAfterStart)
	}
}

// TestJWTCache_BackgroundRefresh verifies the background goroutine refreshes
// the token near half-TTL. We issue a token with a very short TTL (200ms)
// so the half-TTL fires within the test timeout.
func TestJWTCache_BackgroundRefresh(t *testing.T) {
	t.Parallel()

	shortTTL := 200 * time.Millisecond
	tok1 := makeTestToken(time.Now().Add(shortTTL).Unix())
	tok2 := makeTestToken(time.Now().Add(1 * time.Hour).Unix())

	src := &mockJWTSource{tokens: []string{tok1, tok2}}

	cache := NewJWTCache(src, "vault-aud", testLogger(t))
	cache.retryAfter = 50 * time.Millisecond // shrink failure-retry interval
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cache.Close() //nolint:errcheck

	// Wait for the background goroutine to perform a refresh.
	// Half of 200ms = 100ms; add generous buffer for CI scheduling.
	deadline := time.Now().Add(3 * time.Second)
	var refreshed bool
	for time.Now().Before(deadline) {
		got, err := cache.Token(ctx, "vault-aud")
		if err == nil && got == tok2 {
			refreshed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !refreshed {
		t.Error("background refresh did not update cached token to tok2 within 3s")
	}
	if src.callCount() < 2 {
		t.Errorf("underlying source called %d times, want >= 2 (initial + refresh)", src.callCount())
	}
}

// TestJWTCache_LastKnownGoodOnFailure verifies that on source failure the
// goroutine keeps the last-known-good token and the Prometheus error counter
// increments.
func TestJWTCache_LastKnownGoodOnFailure(t *testing.T) {
	t.Parallel()

	// Use a unique audience so this test's counter reads are isolated.
	const aud = "vault-aud-lkg"

	// Use an already-expired token: nextRefreshDelay returns the minimum
	// 1s, so the background refresh fires within ~1s. We sleep 2s to be
	// safe on slow CI machines.
	tok1 := makeTestToken(time.Now().Add(-1 * time.Second).Unix())
	refreshErr := errors.New("spire-agent gone")

	// First call (Start) returns tok1; every subsequent call returns error.
	src := &mockJWTSource{
		tokens: []string{tok1},
		errs:   []error{nil, refreshErr},
	}

	counterBefore := testutil.ToFloat64(cacheRefreshErrors.WithLabelValues(aud))

	cache := NewJWTCache(src, aud, testLogger(t))
	cache.retryAfter = 20 * time.Millisecond // shrink failure-retry interval
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cache.Close() //nolint:errcheck

	// Wait for the background to attempt a refresh and fail.
	// nextRefreshDelay returns 1s minimum for expired/zero expiry.
	time.Sleep(2 * time.Second)

	// Token should still return the original tok1 (last-known-good).
	got, err := cache.Token(ctx, aud)
	if err != nil {
		t.Fatalf("Token after failed refresh: %v", err)
	}
	if got != tok1 {
		t.Errorf("Token = %q, want last-known-good %q", got, tok1)
	}

	// Counter must have been incremented at least once.
	counterAfter := testutil.ToFloat64(cacheRefreshErrors.WithLabelValues(aud))
	if counterAfter <= counterBefore {
		t.Errorf("gibson_jwtsource_cache_refresh_errors_total not incremented: before=%.0f after=%.0f",
			counterBefore, counterAfter)
	}
}

// TestJWTCache_StartFailFast verifies that a source error on the first call
// causes Start to return an error and Token to return ErrJWTSourceDisabled.
func TestJWTCache_StartFailFast(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("workload api down")
	src := &mockJWTSource{errs: []error{wantErr}}

	cache := NewJWTCache(src, "vault-aud", testLogger(t))
	ctx := context.Background()

	err := cache.Start(ctx)
	if err == nil {
		t.Fatal("Start: expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("errors.Is(err, wantErr) = false; got %v", err)
	}

	// Token must return ErrJWTSourceDisabled since Start failed (cache never
	// marked as started).
	_, tokErr := cache.Token(ctx, "vault-aud")
	if !errors.Is(tokErr, ErrJWTSourceDisabled) {
		t.Errorf("Token after failed Start: want ErrJWTSourceDisabled, got %v", tokErr)
	}
}

// TestJWTCache_AudienceMismatch verifies Token rejects a mismatched audience.
func TestJWTCache_AudienceMismatch(t *testing.T) {
	t.Parallel()

	tok := makeTestToken(time.Now().Add(1 * time.Hour).Unix())
	src := newMockSource(tok)

	cache := NewJWTCache(src, "vault-aud", testLogger(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cache.Close() //nolint:errcheck

	_, err := cache.Token(ctx, "wrong-aud")
	if err == nil {
		t.Fatal("Token with wrong audience: expected error, got nil")
	}
	if errors.Is(err, ErrJWTSourceDisabled) {
		t.Error("Token with wrong audience: should not return ErrJWTSourceDisabled")
	}
}

// TestJWTCache_TokenBeforeStart verifies Token returns ErrJWTSourceDisabled
// when called before Start.
func TestJWTCache_TokenBeforeStart(t *testing.T) {
	t.Parallel()

	tok := makeTestToken(time.Now().Add(1 * time.Hour).Unix())
	src := newMockSource(tok)

	cache := NewJWTCache(src, "vault-aud", testLogger(t))

	_, err := cache.Token(context.Background(), "vault-aud")
	if !errors.Is(err, ErrJWTSourceDisabled) {
		t.Errorf("Token before Start: want ErrJWTSourceDisabled, got %v", err)
	}
}

// TestJWTCache_CloseExitsPromptly verifies that Close returns quickly and
// does not block after the background goroutine is running.
func TestJWTCache_CloseExitsPromptly(t *testing.T) {
	t.Parallel()

	tok := makeTestToken(time.Now().Add(1 * time.Hour).Unix())
	src := newMockSource(tok)

	cache := NewJWTCache(src, "vault-aud", testLogger(t))
	ctx := context.Background()

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cache.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s")
	}
}

// TestJWTCache_CloseBeforeStart verifies that Close is safe to call before
// Start (no-op).
func TestJWTCache_CloseBeforeStart(t *testing.T) {
	t.Parallel()
	cache := NewJWTCache(newMockSource("tok"), "vault-aud", testLogger(t))
	if err := cache.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
}

// TestJWTCache_RawTokenNotInLogs verifies that on a background refresh
// failure, the raw token string does not appear in log output — only its
// SHA-256 hash is logged.
func TestJWTCache_RawTokenNotInLogs(t *testing.T) {
	t.Parallel()

	// Use an already-expired token so the refresh fires at the minimum 1s delay.
	rawTok := makeTestToken(time.Now().Add(-1 * time.Second).Unix())

	// Capture log output via a pipe.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { pr.Close() })

	logger := slog.New(slog.NewTextHandler(pw, &slog.HandlerOptions{Level: slog.LevelDebug}))

	refreshErr := errors.New("spire-gone-for-log-test")
	src := &mockJWTSource{
		tokens: []string{rawTok},
		errs:   []error{nil, refreshErr},
	}

	cache := NewJWTCache(src, "vault-aud-log", logger)
	cache.retryAfter = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())

	if err := cache.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for a background failure to be logged (1s min delay + buffer).
	time.Sleep(2 * time.Second)
	cancel()
	if err := cache.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	pw.Close()

	// Read log output.
	buf := make([]byte, 8192)
	n, _ := pr.Read(buf)
	logOutput := string(buf[:n])

	// The raw token must never appear in logs.
	if strings.Contains(logOutput, rawTok) {
		t.Errorf("log output contains raw token; only hash should be logged:\n%s", logOutput)
	}
}

// TestParseExp_ValidToken verifies the exp parsing helper on a well-formed token.
func TestParseExp_ValidToken(t *testing.T) {
	t.Parallel()
	wantUnix := time.Now().Add(1 * time.Hour).Unix()
	tok := makeTestToken(wantUnix)
	got := parseExp(tok)
	if got.IsZero() {
		t.Fatal("parseExp returned zero time for valid token")
	}
	if got.Unix() != wantUnix {
		t.Errorf("parseExp = %v (unix %d), want unix %d", got, got.Unix(), wantUnix)
	}
}

// TestParseExp_InvalidToken verifies that parseExp returns zero on garbage input.
func TestParseExp_InvalidToken(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "notenoughparts", "a.b", "a.!!!.c"} {
		if got := parseExp(bad); !got.IsZero() {
			t.Errorf("parseExp(%q) = %v, want zero", bad, got)
		}
	}
}
