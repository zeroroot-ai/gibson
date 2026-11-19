// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/readiness"
)

// stubProbe is a readiness probe whose answer the test sets.
type stubProbe struct{ failing atomic.Bool }

func (*stubProbe) Name() string { return "stub" }
func (s *stubProbe) Check(context.Context) error {
	if s.failing.Load() {
		return errors.New("the dependency is down")
	}
	return nil
}

func probeStatus(t *testing.T, h http.Handler, method, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, http.NoBody))
	return rec.Code
}

// The probe listener serves the two probe paths, and every other path and
// method gets 404. No metrics, pprof or version path exists on it.
func TestProbeMux_ServesOnlyTheTwoPaths(t *testing.T) {
	h := probeMux(readiness.NewAggregator())
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusNotFound},
		{http.MethodHead, "/readyz", http.StatusNotFound},
		{http.MethodGet, "/metrics", http.StatusNotFound},
		{http.MethodGet, "/debug/pprof/", http.StatusNotFound},
		{http.MethodGet, "/version", http.StatusNotFound},
		{http.MethodGet, "/healthz/", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
	} {
		if got := probeStatus(t, h, tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, got, tc.want)
		}
	}
}

// /readyz follows the real condition of the aggregator, the one that the mTLS
// health listener reports. /healthz stays 200 whatever the dependency does.
func TestProbeMux_ReadinessFollowsTheCondition(t *testing.T) {
	agg := readiness.NewAggregator()
	p := &stubProbe{}
	agg.Register(p)
	h := probeMux(agg)

	if got := probeStatus(t, h, http.MethodGet, "/readyz"); got != http.StatusOK {
		t.Fatalf("ready dependency: /readyz = %d, want 200", got)
	}
	p.failing.Store(true)
	if got := probeStatus(t, h, http.MethodGet, "/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("failing dependency: /readyz = %d, want 503", got)
	}
	if got := probeStatus(t, h, http.MethodGet, "/healthz"); got != http.StatusOK {
		t.Fatalf("failing dependency: /healthz = %d, want 200", got)
	}
	p.failing.Store(false)
	if got := probeStatus(t, h, http.MethodGet, "/readyz"); got != http.StatusOK {
		t.Fatalf("recovered dependency: /readyz = %d, want 200", got)
	}
}

// An empty address starts no listener. A real address serves, and it stops with
// the context.
func TestStartProbeListener(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errC, err := startProbeListener(ctx, log, "", readiness.NewAggregator())
	if err != nil || errC != nil {
		t.Fatalf("unset address: err = %v, channel = %v, want no listener", err, errC)
	}

	if _, err := startProbeListener(ctx, log, "256.0.0.1:1", readiness.NewAggregator()); err == nil {
		t.Fatal("a bad address must fail at start")
	}

	// A real listener on a free port serves and stops with the context.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	errC, err = startProbeListener(ctx, log, addr, readiness.NewAggregator())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var code int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, gerr := http.Get("http://" + addr + "/healthz") //nolint:noctx // a local test server
		if gerr == nil {
			code = resp.StatusCode
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	cancel()
	select {
	case err := <-errC:
		t.Fatalf("the listener reported an error on a clean stop: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}
