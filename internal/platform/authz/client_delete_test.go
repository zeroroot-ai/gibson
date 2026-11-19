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

// strictDeleteServer behaves as OpenFGA does on a batch delete. A delete of an
// absent tuple fails the whole batch and removes nothing, unless the request
// says on_missing=ignore. With ignore, the server removes the present tuples
// and skips the absent ones. It is the failure of the first Agent Skills exit
// test run (cannot delete a tuple which does not exist).
type strictDeleteServer struct {
	mu      sync.Mutex
	present map[string]bool
}

func (s *strictDeleteServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/write") {
			_, _ = w.Write([]byte("{}"))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Deletes struct {
				TupleKeys []struct {
					User, Relation, Object string
				} `json:"tuple_keys"`
				OnMissing string `json:"on_missing"`
			} `json:"deletes"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode the write body: %v", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, k := range body.Deletes.TupleKeys {
			if !s.present[k.User+"|"+k.Relation+"|"+k.Object] && body.Deletes.OnMissing != "ignore" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist: user: '` +
					k.User + `', relation: '` + k.Relation + `', object: '` + k.Object + `'"}`))
				return
			}
		}
		for _, k := range body.Deletes.TupleKeys {
			delete(s.present, k.User+"|"+k.Relation+"|"+k.Object)
		}
		_, _ = w.Write([]byte("{}"))
	}
}

// TestDelete_AbsentTupleIsANoOpAndThePresentOneGoes pins the Authorizer
// contract: one absent and one present tuple in one batch succeed, and the
// present tuple is gone.
func TestDelete_AbsentTupleIsANoOpAndThePresentOneGoes(t *testing.T) {
	fga := &strictDeleteServer{present: map[string]bool{
		"user:alice|member|tenant:acme": true,
	}}
	srv := httptest.NewServer(fga.handler(t))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)

	err := az.Delete(context.Background(), []Tuple{
		{User: "tenant:acme", Relation: "owner", Object: "agent_skill:acme/absent"},
		{User: "user:alice", Relation: "member", Object: "tenant:acme"},
	})
	if err != nil {
		t.Fatalf("Delete of an absent and a present tuple: %v", err)
	}
	if fga.present["user:alice|member|tenant:acme"] {
		t.Fatal("the present tuple is still in the store")
	}
}

// TestDelete_OnlyAbsentTuplesSucceed covers the first exit test run: a delete
// of a name that was never published.
func TestDelete_OnlyAbsentTuplesSucceed(t *testing.T) {
	fga := &strictDeleteServer{present: map[string]bool{}}
	srv := httptest.NewServer(fga.handler(t))
	defer srv.Close()
	az := newTestFgaAuthorizer(t, srv.URL)

	if err := az.Delete(context.Background(), []Tuple{
		{User: "tenant:primary", Relation: "owner", Object: "agent_skill:primary/e2e-alpha"},
	}); err != nil {
		t.Fatalf("Delete of an absent tuple: %v", err)
	}
}
