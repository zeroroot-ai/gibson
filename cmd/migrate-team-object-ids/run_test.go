// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The exit code is this binary's entire contract with the Kubernetes Job that
// runs it: 0 means the store is namespaced, 1 means retry, 2 means a human has
// to look. These tests drive run() against a fake OpenFGA rather than the real
// one, because the codes are what the Job keys off and nothing else asserts
// them.

// fakeFGA serves the two endpoints the migration touches. listUsers is the
// tenant enumeration; readTuples is keyed by the object filter in the request
// body, and anything unstaged answers empty.
type fakeFGA struct {
	tenants    []string
	readTuples map[string][]map[string]string
}

func (f fakeFGA) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/list-users"):
			users := make([]map[string]any, 0, len(f.tenants))
			for _, tn := range f.tenants {
				users = append(users, map[string]any{
					"object": map[string]string{"type": "tenant", "id": tn},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"users": users})

		case strings.HasSuffix(r.URL.Path, "/read"):
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				TupleKey struct {
					Object string `json:"object"`
					User   string `json:"user"`
				} `json:"tuple_key"`
			}
			_ = json.Unmarshal(raw, &body)
			key := body.TupleKey.User + "|" + body.TupleKey.Object
			tuples := make([]map[string]any, 0, len(f.readTuples[key]))
			for _, tk := range f.readTuples[key] {
				tuples = append(tuples, map[string]any{
					"key":       tk,
					"timestamp": "2026-01-01T00:00:00Z",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tuples": tuples, "continuation_token": ""})

		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
}

func setFGAEnv(t *testing.T, url string) {
	t.Helper()
	t.Setenv("EXT_AUTHZ_FGA_ADDR", url)
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FBV")
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestRun_ExitsNonZeroOnAnInvalidConfiguration pins the fail-closed boot. This
// binary deletes tuples, so a missing store id must stop it rather than let the
// SDK fall back to a default.
func TestRun_ExitsNonZeroOnAnInvalidConfiguration(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "")

	if got := run(context.Background(), discardLogger(), io.Discard, false); got != 1 {
		t.Errorf("run() = %d, want 1 on an unusable configuration", got)
	}
}

// TestRun_ExitsZeroOnAnAlreadyNamespacedStore is the idempotent re-run: a store
// with nothing legacy left in it is a success, not a no-op to be retried.
func TestRun_ExitsZeroOnAnAlreadyNamespacedStore(t *testing.T) {
	srv := fakeFGA{
		tenants: []string{"acme"},
		readTuples: map[string][]map[string]string{
			"tenant:acme|team:": {
				{"user": "tenant:acme", "relation": "parent", "object": "team:acme/ops"},
			},
		},
	}.server(t)
	defer srv.Close()
	setFGAEnv(t, srv.URL)

	var out bytes.Buffer
	if got := run(context.Background(), discardLogger(), &out, false); got != 0 {
		t.Errorf("run() = %d, want 0 — the store is already namespaced", got)
	}
	if !strings.Contains(out.String(), "teams already namespaced: 1") {
		t.Errorf("report does not account for the already-namespaced team:\n%s", out.String())
	}
}

// TestRun_ExitsTwoWhenAnIDNeedsAHuman pins the code that separates "done" from
// "done, but something was left behind". A team id containing the namespace
// separator cannot be moved, and exiting 0 would let the Job report success
// while a legacy object stayed in the store.
func TestRun_ExitsTwoWhenAnIDNeedsAHuman(t *testing.T) {
	srv := fakeFGA{
		tenants: []string{"acme"},
		readTuples: map[string][]map[string]string{
			"tenant:acme|team:": {
				{"user": "tenant:acme", "relation": "parent", "object": "team:weird/id"},
			},
		},
	}.server(t)
	defer srv.Close()
	setFGAEnv(t, srv.URL)

	var out bytes.Buffer
	if got := run(context.Background(), discardLogger(), &out, true); got != 2 {
		t.Errorf("run() = %d, want 2 — an unmovable id needs an operator", got)
	}
	// The report is the hand-off; a bare exit code names nothing.
	if !strings.Contains(out.String(), "team:weird/id") {
		t.Errorf("report does not name the id that needs a human:\n%s", out.String())
	}
}

// TestRun_ExitsOneWhenFGAIsUnreachable pins that a transport failure is a
// retryable failure, not an empty-but-successful migration.
func TestRun_ExitsOneWhenFGAIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
	}))
	defer srv.Close()
	setFGAEnv(t, srv.URL)

	if got := run(context.Background(), discardLogger(), io.Discard, false); got != 1 {
		t.Errorf("run() = %d, want 1 when the store cannot be read", got)
	}
}
