// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/fgakey"
)

// testKeyDir writes an OpenFGA key directory (fgakey) and returns its path.
func testKeyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fgakey.FileKey), []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// OpenFGA refuses a call with no preshared key, so New refuses a key
// directory with no key.
func TestNew_RequiresAKey(t *testing.T) {
	if _, err := New("http://fga:8080", t.TempDir()); !errors.Is(err, fgakey.ErrNoKey) {
		t.Fatalf("New with an empty key directory: err %v, want fgakey.ErrNoKey", err)
	}
}

// Each request of the model load carries the key.
func TestEnsureStore_SendsTheKey(t *testing.T) {
	var unauthenticated int32
	mux := http.NewServeMux()
	mux.HandleFunc("/stores", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			atomic.AddInt32(&unauthenticated, 1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"stores":[{"id":"STORE-1","name":"gibson"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(srv.URL, testKeyDir(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := c.EnsureStore(context.Background(), "gibson")
	if err != nil || id != "STORE-1" {
		t.Fatalf("EnsureStore = %q, %v", id, err)
	}
	if n := atomic.LoadInt32(&unauthenticated); n != 0 {
		t.Fatalf("%d requests had no key", n)
	}
}

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

	c, err := New(srv.URL, testKeyDir(t))
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

	c, err := New(srv.URL, testKeyDir(t))
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

	c, err := New(srv.URL, testKeyDir(t))
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

	c, err := New(srv.URL, testKeyDir(t))
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

	c, err := New(srv.URL, testKeyDir(t))
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
