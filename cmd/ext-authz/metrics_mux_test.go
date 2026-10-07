// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// The metrics port carries no API (charts#515): it answers GET /metrics and
// refuses every other path, so a network rule can admit the scraper to it.
func TestMetricsMuxServesOnlyMetrics(t *testing.T) {
	h := metricsMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodGet, "/readyz", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, http.NoBody))
		if rec.Code != c.want {
			t.Errorf("%s %s: got %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}

// The series of the D9 alert reaches the metrics port: the counter is on the
// default registry that the metrics listener serves.
func TestMetricsMuxServesTheReplayStoreCounter(t *testing.T) {
	h := metricsMux(observability.DefaultPrometheusHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: got %d", rec.Code)
	}
	if !strings.Contains(string(body), "extauthz_cgjwt_component_replay_state_unavailable_total") {
		t.Fatal("the replay-store counter of the D9 alert is not on the metrics port")
	}
}
