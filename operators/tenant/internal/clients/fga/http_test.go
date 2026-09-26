// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

func newHTTPClient(t *testing.T, handler http.HandlerFunc) fga.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := fga.NewHTTPClient(fga.Config{BaseURL: srv.URL, StoreID: "store-1", ModelID: "model-1"})
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
	c := newHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
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
	c := newHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
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
