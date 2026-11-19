// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/fgakey"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

func newHTTPClient(t *testing.T, handler http.HandlerFunc) fga.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fgakey.FileKey), []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := fga.NewHTTPClient(fga.Config{BaseURL: srv.URL, StoreID: "store-1", ModelID: "model-1", KeyDir: dir})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

// TestRead_FollowsContinuationTokens pins that Read walks every page: a
// server that returns one tuple per call and a continuation token until the
// third call is asked three times, and every tuple is returned.
func TestRead_FollowsContinuationTokens(t *testing.T) {
	calls := 0
	c := newHTTPClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tuples":             []map[string]any{{"key": map[string]string{"user": "user:1", "relation": "member", "object": "tenant:acme"}}},
				"continuation_token": "page-2",
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tuples":             []map[string]any{{"key": map[string]string{"user": "user:2", "relation": "member", "object": "tenant:acme"}}},
				"continuation_token": "page-3",
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tuples": []map[string]any{{"key": map[string]string{"user": "user:3", "relation": "member", "object": "tenant:acme"}}},
			})
		}
	})

	got, err := c.Read(context.Background(), fga.Tuple{Object: "tenant:acme"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Read returned %d tuples, want 3 (one per page)", len(got))
	}
	if calls != 3 {
		t.Fatalf("Read made %d requests, want 3", calls)
	}
}

// TestRead_StopsAndSurfacesAnErrorMidPagination pins that a page fetch
// failure after some pages already succeeded still returns the error (not
// a partial, silently-truncated result).
func TestRead_StopsAndSurfacesAnErrorMidPagination(t *testing.T) {
	calls := 0
	c := newHTTPClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tuples":             []map[string]any{{"key": map[string]string{"user": "user:1", "relation": "member", "object": "tenant:acme"}}},
				"continuation_token": "page-2",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := c.Read(context.Background(), fga.Tuple{Object: "tenant:acme"}); err == nil {
		t.Fatal("Read: got nil error, want the second page's failure to surface")
	}
	if calls != 2 {
		t.Fatalf("Read made %d requests, want 2 (stop at the failing page)", calls)
	}
}

// TestWriteAndDelete_SendsOneRequest pins that both lists ride in a single
// POST /stores/:id/write, so OpenFGA applies all of it or none of it.
func TestWriteAndDelete_SendsOneRequest(t *testing.T) {
	var calls int
	var gotBody map[string]any
	c := newHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	writes := []fga.Tuple{{User: "user:bob", Relation: "owner", Object: "tenant:acme"}}
	deletes := []fga.Tuple{{User: "user:alice", Relation: "owner", Object: "tenant:acme"}}
	if err := c.WriteAndDelete(context.Background(), writes, deletes); err != nil {
		t.Fatalf("WriteAndDelete: %v", err)
	}
	if calls != 1 {
		t.Fatalf("WriteAndDelete made %d requests, want 1", calls)
	}
	if _, ok := gotBody["writes"]; !ok {
		t.Errorf("request body missing writes: %v", gotBody)
	}
	if _, ok := gotBody["deletes"]; !ok {
		t.Errorf("request body missing deletes: %v", gotBody)
	}
}

// TestWriteAndDelete_EmptyIsANoOp pins that no request is sent when both
// lists are empty.
func TestWriteAndDelete_EmptyIsANoOp(t *testing.T) {
	var calls int
	c := newHTTPClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	if err := c.WriteAndDelete(context.Background(), nil, nil); err != nil {
		t.Fatalf("WriteAndDelete: %v", err)
	}
	if calls != 0 {
		t.Fatalf("WriteAndDelete made %d requests for empty input, want 0", calls)
	}
}

// TestHTTPClient_MapsEachOpenFGAMessageText pins the 400 mapping for the old
// and the current OpenFGA texts (gibson#879). A write of a tuple that exists is
// an idempotent success. A delete sets on_missing to ignore, so a refusal of a
// delete stays an error (TestDelete_MixedBatch below).
func TestHTTPClient_MapsEachOpenFGAMessageText(t *testing.T) {
	tuple := fga.Tuple{User: "tenant:acme#member", Relation: "can_invoke", Object: "plugin:acme/gitlab"}
	answer := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"` + body + `"}`))
		}
	}
	for _, msg := range []string{
		"cannot write a tuple which already exists: user: 'tenant:acme#member'",
		"tuple to be written already existed",
	} {
		err := newHTTPClient(t, answer(msg)).Write(context.Background(), []fga.Tuple{tuple})
		if !errors.Is(err, clients.ErrAlreadyExists) {
			t.Errorf("write answered %q: err = %v, want ErrAlreadyExists", msg, err)
		}
	}
	// The control: another 400 is still an error.
	if err := newHTTPClient(t, answer("type 'nope' not found")).Delete(context.Background(), []fga.Tuple{tuple}); err == nil {
		t.Error("an unrelated 400 must stay an error")
	}
}

// TestDelete_MixedBatch uses a server that acts as OpenFGA does. A delete of an
// absent tuple fails the whole batch and removes nothing, unless the deletes
// object holds on_missing ignore. One absent and one present tuple in one batch
// must succeed and the present tuple must be gone.
func TestDelete_MixedBatch(t *testing.T) {
	present := map[string]bool{"user:alice|member|tenant:acme": true}
	c := newHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Deletes struct {
				TupleKeys []map[string]string `json:"tuple_keys"`
				OnMissing string              `json:"on_missing"`
			} `json:"deletes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode the write body: %v", err)
		}
		key := func(k map[string]string) string { return k["user"] + "|" + k["relation"] + "|" + k["object"] }
		for _, k := range body.Deletes.TupleKeys {
			if !present[key(k)] && body.Deletes.OnMissing != "ignore" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist: user: '` + k["user"] + `'"}`))
				return
			}
		}
		for _, k := range body.Deletes.TupleKeys {
			delete(present, key(k))
		}
		_, _ = w.Write([]byte("{}"))
	})
	err := c.Delete(context.Background(), []fga.Tuple{
		{User: "tenant:acme", Relation: "owner", Object: "agent_skill:acme/absent"},
		{User: "user:alice", Relation: "member", Object: "tenant:acme"},
	})
	if err != nil {
		t.Fatalf("Delete of an absent and a present tuple: %v", err)
	}
	if present["user:alice|member|tenant:acme"] {
		t.Fatal("the present tuple of the mixed batch is still in the store")
	}
}

// TestDelete_ARealErrorStaysAnError pins that an unknown store (404) is not
// read as a successful delete.
func TestDelete_ARealErrorStaysAnError(t *testing.T) {
	c := newHTTPClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"store_id_not_found","message":"store not found"}`))
	})
	err := c.Delete(context.Background(), []fga.Tuple{{User: "user:a", Relation: "member", Object: "tenant:t"}})
	if err == nil {
		t.Fatal("a 404 on delete must be an error")
	}
}
