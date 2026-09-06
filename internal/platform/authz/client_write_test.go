// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fgaPartialExistsServer models OpenFGA's transactional /write: the first
// batch is rejected with "already exists" because one tuple is present, /read
// reports which tuples exist, and the retry batch is accepted and captured.
type fgaPartialExistsServer struct {
	mu      sync.Mutex
	present map[string]bool // "user|relation|object" of tuples that exist
	writes  [][]map[string]string
}

func (s *fgaPartialExistsServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/write"):
			var body struct {
				Writes struct {
					TupleKeys []map[string]string `json:"tuple_keys"`
				} `json:"writes"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, k := range body.Writes.TupleKeys {
				if s.present[k["user"]+"|"+k["relation"]+"|"+k["object"]] {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`))
					return
				}
			}
			s.writes = append(s.writes, body.Writes.TupleKeys)
			for _, k := range body.Writes.TupleKeys {
				s.present[k["user"]+"|"+k["relation"]+"|"+k["object"]] = true
			}
			_, _ = w.Write([]byte("{}"))
		case strings.HasSuffix(r.URL.Path, "/read"):
			var body struct {
				TupleKey map[string]string `json:"tuple_key"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			k := body.TupleKey
			s.mu.Lock()
			exists := s.present[k["user"]+"|"+k["relation"]+"|"+k["object"]]
			s.mu.Unlock()
			if !exists {
				_, _ = w.Write([]byte(`{"tuples":[],"continuation_token":""}`))
				return
			}
			resp := map[string]any{"continuation_token": "", "tuples": []map[string]any{{
				"key":       map[string]string{"user": k["user"], "relation": k["relation"], "object": k["object"]},
				"timestamp": "2026-01-01T00:00:00Z",
			}}}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}
}

// TestWrite_PartialBatchExists_WritesTheRest is the regression test for the
// silent drop: one tuple of the batch already existed, OpenFGA rejected the
// whole batch, and Write returned nil having written nothing.
func TestWrite_PartialBatchExists_WritesTheRest(t *testing.T) {
	fake := &fgaPartialExistsServer{present: map[string]bool{
		"tenant:acme|tenant_enabled|component:agent/zerocool-claude": true,
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)

	tuples := []Tuple{
		{User: "user:admin", Relation: "owner", Object: "agent_principal:2"},
		{User: "tenant:acme", Relation: "belongs_to", Object: "agent_principal:2"},
		{User: "tenant:acme", Relation: "tenant_enabled", Object: "component:agent/zerocool-claude"},
	}
	if err := az.Write(context.Background(), tuples); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(fake.writes) != 1 {
		t.Fatalf("accepted writes = %d, want 1 (the retry with the missing subset)", len(fake.writes))
	}
	got := fake.writes[0]
	if len(got) != 2 {
		t.Fatalf("retry wrote %d tuples, want 2: %v", len(got), got)
	}
	for _, k := range got {
		if k["relation"] == "tenant_enabled" {
			t.Errorf("retry re-sent the existing tuple: %v", k)
		}
	}
	for _, want := range []string{"owner", "belongs_to"} {
		if !fake.present["user:admin|owner|agent_principal:2"] || !fake.present["tenant:acme|belongs_to|agent_principal:2"] {
			t.Errorf("tuple with relation %q was not written", want)
		}
	}
}

// TestWrite_WholeBatchExists_NoOp: a retry of an applied write stays a no-op.
func TestWrite_WholeBatchExists_NoOp(t *testing.T) {
	fake := &fgaPartialExistsServer{present: map[string]bool{
		"user:admin|owner|agent_principal:2":       true,
		"tenant:acme|belongs_to|agent_principal:2": true,
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)
	err := az.Write(context.Background(), []Tuple{
		{User: "user:admin", Relation: "owner", Object: "agent_principal:2"},
		{User: "tenant:acme", Relation: "belongs_to", Object: "agent_principal:2"},
	})
	if err != nil {
		t.Fatalf("Write: expected nil on an all-existing batch, got %v", err)
	}
	if len(fake.writes) != 0 {
		t.Errorf("accepted writes = %d, want 0", len(fake.writes))
	}
}

// fgaFailAfterConflictServer rejects the first /write with already-exists and
// then fails the step named by failOn ("read" or "write") with a 500, so the
// error branches of the retry path are exercised.
func fgaFailAfterConflictServer(failOn string) http.HandlerFunc {
	var writes int
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/write"):
			writes++
			if writes == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`))
				return
			}
			if failOn == "write" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
				return
			}
			_, _ = w.Write([]byte("{}"))
		case strings.HasSuffix(r.URL.Path, "/read"):
			if failOn == "read" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
				return
			}
			_, _ = w.Write([]byte(`{"tuples":[],"continuation_token":""}`))
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}
}

// TestWrite_ConflictThenReadFails: a failed read-back surfaces as an error,
// never as a silent no-op.
func TestWrite_ConflictThenReadFails(t *testing.T) {
	srv := httptest.NewServer(fgaFailAfterConflictServer("read"))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)
	err := az.Write(context.Background(), []Tuple{{User: "user:a", Relation: "owner", Object: "agent_principal:1"}})
	if err == nil {
		t.Fatal("Write: expected an error when the read-back fails")
	}
	if !strings.Contains(err.Error(), "read back") {
		t.Errorf("error = %q, want the read-back context", err)
	}
}

// TestWrite_ConflictThenRetryWriteFails: a failed retry write surfaces as an
// error.
func TestWrite_ConflictThenRetryWriteFails(t *testing.T) {
	srv := httptest.NewServer(fgaFailAfterConflictServer("write"))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)
	err := az.Write(context.Background(), []Tuple{{User: "user:a", Relation: "owner", Object: "agent_principal:1"}})
	if err == nil {
		t.Fatal("Write: expected an error when the retry write fails")
	}
}
