// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/health"
)

// --- minimal pinger fakes ---

type okPinger struct{}

func (okPinger) Ping(_ context.Context) error { return nil }

type errPinger struct{ err error }

func (e errPinger) Ping(_ context.Context) error { return e.err }

type slowPinger struct{ delay time.Duration }

func (s slowPinger) Ping(ctx context.Context) error {
	select {
	case <-time.After(s.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- PingDashboard ---

func TestPingDashboard_OK(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := health.PingDashboard(ctx, okPinger{}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPingDashboard_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	want := errors.New("dashboard down")
	if err := health.PingDashboard(ctx, errPinger{err: want}); !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

func TestPingDashboard_Timeout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// slowPinger waits 5s; PingDashboard has a 1s budget — should time out.
	err := health.PingDashboard(ctx, slowPinger{delay: 5 * time.Second})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

// --- PingFGA ---

func TestPingFGA_OK(t *testing.T) {
	t.Parallel()
	if err := health.PingFGA(context.Background(), okPinger{}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPingFGA_Error(t *testing.T) {
	t.Parallel()
	want := errors.New("fga unreachable")
	err := health.PingFGA(context.Background(), errPinger{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// --- PingRedis ---

func TestPingRedis_OK(t *testing.T) {
	t.Parallel()
	if err := health.PingRedis(context.Background(), okPinger{}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPingRedis_Error(t *testing.T) {
	t.Parallel()
	want := errors.New("redis down")
	err := health.PingRedis(context.Background(), errPinger{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// --- PingNeo4j ---

func TestPingNeo4j_OK(t *testing.T) {
	t.Parallel()
	if err := health.PingNeo4j(context.Background(), okPinger{}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPingNeo4j_Error(t *testing.T) {
	t.Parallel()
	want := errors.New("neo4j down")
	err := health.PingNeo4j(context.Background(), errPinger{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// --- PingStripe ---

func TestPingStripe_NilClient_Skipped(t *testing.T) {
	t.Parallel()
	// A nil StripePinger means STRIPE_API_KEY is unset; no error.
	if err := health.PingStripe(context.Background(), nil); err != nil {
		t.Fatalf("expected nil for nil stripe client, got %v", err)
	}
}

func TestPingStripe_OK(t *testing.T) {
	t.Parallel()
	if err := health.PingStripe(context.Background(), okPinger{}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPingStripe_Error(t *testing.T) {
	t.Parallel()
	want := errors.New("stripe down")
	err := health.PingStripe(context.Background(), errPinger{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// --- Composite ---

func TestComposite_AllOK(t *testing.T) {
	t.Parallel()
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "fga", Ping: okPinger{}.Ping},
		{Name: "redis", Ping: okPinger{}.Ping},
		{Name: "neo4j", Ping: okPinger{}.Ping},
	}, 0)

	summary := comp.Run(context.Background())

	if !summary.OK {
		t.Fatalf("expected OK=true, got false: %+v", summary.Checks)
	}
	for name, status := range summary.Checks {
		if status != "ok" {
			t.Errorf("check %q: expected ok, got %q", name, status)
		}
	}
}

func TestComposite_OneFailing_ReturnsFalse(t *testing.T) {
	t.Parallel()
	redisErr := errors.New("connection refused")
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "redis", Ping: errPinger{err: redisErr}.Ping},
		{Name: "neo4j", Ping: okPinger{}.Ping},
	}, 0)

	summary := comp.Run(context.Background())

	if summary.OK {
		t.Fatal("expected OK=false when a dep is down")
	}
	if !strings.Contains(summary.Checks["redis"], "error:") {
		t.Errorf("redis check should contain 'error:': got %q", summary.Checks["redis"])
	}
	if summary.Checks["dashboard"] != "ok" {
		t.Errorf("dashboard should be ok, got %q", summary.Checks["dashboard"])
	}
}

func TestComposite_StripeSkipped_WhenNilPing(t *testing.T) {
	t.Parallel()
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "stripe", Ping: nil}, // nil == skipped
	}, 0)

	summary := comp.Run(context.Background())

	if !summary.OK {
		t.Fatal("skipped check should not make OK=false")
	}
	if summary.Checks["stripe"] != "skipped" {
		t.Errorf("stripe should be 'skipped', got %q", summary.Checks["stripe"])
	}
}

func TestComposite_Checker_ReturnsError_WhenFailing(t *testing.T) {
	t.Parallel()
	dbErr := errors.New("neo4j timeout")
	comp := health.NewComposite([]health.Dep{
		{Name: "neo4j", Ping: errPinger{err: dbErr}.Ping},
	}, 0)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	err := comp.Checker(req)
	if err == nil {
		t.Fatal("expected non-nil error from Checker when dep is down")
	}
	// Error message must be valid JSON containing the summary.
	var got health.Summary
	if jerr := json.Unmarshal([]byte(err.Error()), &got); jerr != nil {
		t.Fatalf("Checker error is not valid JSON: %v — raw: %s", jerr, err.Error())
	}
	if got.OK {
		t.Errorf("summary.ok should be false")
	}
	if !strings.Contains(got.Checks["neo4j"], "error:") {
		t.Errorf("neo4j check should contain 'error:', got %q", got.Checks["neo4j"])
	}
}

func TestComposite_Checker_ReturnsNil_WhenAllOK(t *testing.T) {
	t.Parallel()
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "fga", Ping: okPinger{}.Ping},
	}, 0)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := comp.Checker(req); err != nil {
		t.Fatalf("expected nil from Checker when all deps ok, got %v", err)
	}
}

func TestComposite_ServeHTTP_200_WhenAllOK(t *testing.T) {
	t.Parallel()
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "redis", Ping: okPinger{}.Ping},
	}, 0)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	comp.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var got health.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v — body: %s", err, w.Body.String())
	}
	if !got.OK {
		t.Errorf("expected ok=true in body")
	}
}

func TestComposite_ServeHTTP_503_WhenFailing(t *testing.T) {
	t.Parallel()
	comp := health.NewComposite([]health.Dep{
		{Name: "stripe", Ping: errPinger{err: errors.New("service unavailable")}.Ping},
	}, 0)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	comp.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	var got health.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got.OK {
		t.Errorf("expected ok=false in body")
	}
}

func TestComposite_ConcurrentTimeout(t *testing.T) {
	t.Parallel()
	// All pings are slow; the composite should time out within the budget.
	comp := health.NewComposite([]health.Dep{
		{Name: "a", Ping: slowPinger{delay: 10 * time.Second}.Ping},
		{Name: "b", Ping: slowPinger{delay: 10 * time.Second}.Ping},
	}, 200*time.Millisecond)

	start := time.Now()
	summary := comp.Run(context.Background())
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("composite took too long: %v (budget 200ms)", elapsed)
	}
	if summary.OK {
		t.Errorf("timed-out checks should make OK=false")
	}
}

func TestComposite_JSON_SampleBody(t *testing.T) {
	t.Parallel()
	// Produce the sample JSON body documented in the task.
	comp := health.NewComposite([]health.Dep{
		{Name: "dashboard", Ping: okPinger{}.Ping},
		{Name: "fga", Ping: okPinger{}.Ping},
		{Name: "redis", Ping: okPinger{}.Ping},
		{Name: "neo4j", Ping: okPinger{}.Ping},
		{Name: "stripe", Ping: nil}, // skipped — STRIPE_API_KEY not set
	}, 0)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	comp.ServeHTTP(w, r)

	t.Logf("sample readyz JSON body:\n%s", w.Body.String())

	var got health.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !got.OK {
		t.Errorf("expected ok=true")
	}
	if got.Checks["stripe"] != "skipped" {
		t.Errorf("stripe should be skipped, got %q", got.Checks["stripe"])
	}
	for _, name := range []string{"dashboard", "fga", "redis", "neo4j"} {
		if got.Checks[name] != "ok" {
			t.Errorf("%s should be ok, got %q", name, got.Checks[name])
		}
	}
}
