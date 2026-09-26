// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestWriteTuple_NoOpWhenAlreadyTrue pins WriteTuple's idempotency contract:
// it Checks first and never calls Write when the tuple already holds, since
// OpenFGA's own Write errors on a duplicate write rather than treating it as
// a no-op (hosted#201, platform_owner: [user] has no other path to true).
func TestWriteTuple_NoOpWhenAlreadyTrue(t *testing.T) {
	var writeCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/STORE-1/check", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allowed":true}`))
	})
	mux.HandleFunc("/stores/STORE-1/write", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&writeCalls, 1)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.WriteTuple(context.Background(), "STORE-1", "MODEL-1", "user:UID-1", "platform_owner", "system_tenant:_system"); err != nil {
		t.Fatalf("WriteTuple: %v", err)
	}
	if got := atomic.LoadInt32(&writeCalls); got != 0 {
		t.Fatalf("Write called %d times, want 0 (Check already reported true)", got)
	}
}

// TestWriteTuple_WritesWhenAbsent pins the write path: when Check reports
// false, WriteTuple issues exactly one Write with the tuple key.
func TestWriteTuple_WritesWhenAbsent(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/STORE-1/check", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allowed":false}`))
	})
	mux.HandleFunc("/stores/STORE-1/write", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.WriteTuple(context.Background(), "STORE-1", "MODEL-1", "user:UID-1", "platform_owner", "system_tenant:_system"); err != nil {
		t.Fatalf("WriteTuple: %v", err)
	}
	for _, want := range []string{"user:UID-1", "platform_owner", "system_tenant:_system", "MODEL-1"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("write body missing %q: %s", want, gotBody)
		}
	}
}

// TestWriteTuple_CheckErrorPropagates ensures a Check transport failure is
// surfaced rather than silently proceeding to Write.
func TestWriteTuple_CheckErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.WriteTuple(context.Background(), "STORE-1", "MODEL-1", "user:UID-1", "platform_owner", "system_tenant:_system"); err == nil {
		t.Fatal("WriteTuple: expected an error when Check fails, got nil")
	}
}

// TestWriteTuple_WriteErrorPropagates ensures a Write transport/server
// failure (after a successful, false Check) is surfaced.
func TestWriteTuple_WriteErrorPropagates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/STORE-1/check", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allowed":false}`))
	})
	mux.HandleFunc("/stores/STORE-1/write", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.WriteTuple(context.Background(), "STORE-1", "MODEL-1", "user:UID-1", "platform_owner", "system_tenant:_system"); err == nil {
		t.Fatal("WriteTuple: expected an error when Write fails, got nil")
	}
}

// TestCheck_ReadsAllowedField pins the response decode.
func TestCheck_ReadsAllowedField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	t.Cleanup(srv.Close)

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	allowed, err := c.Check(context.Background(), "STORE-1", "MODEL-1", "user:UID-1", "platform_owner", "system_tenant:_system")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check: allowed = false, want true")
	}
}
