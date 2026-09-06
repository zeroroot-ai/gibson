// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for ReadTuples' cursor walk against a fake OpenFGA Read endpoint,
// following the httptest pattern in client_conditional_test.go — no
// testcontainers, no real OpenFGA.
//
// The walk is load-bearing for the team object-id migration (gibson#1231): the
// migration deletes the legacy tuples it has copied, so a page it never read is
// a tuple it never moved and then deleted. A single-page read would look
// perfectly healthy in every test that seeds fewer tuples than one page.
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// readPage is the subset of OpenFGA's Read response the SDK needs.
type readPage struct {
	Tuples            []readTuple `json:"tuples"`
	ContinuationToken string      `json:"continuation_token"`
}

type readTuple struct {
	Key       Tuple  `json:"key"`
	Timestamp string `json:"timestamp"`
}

// fgaReadServer serves the given pages in order, one per Read call, and records
// each request body so the test can assert what filter went on the wire.
func fgaReadServer(t *testing.T, pages []readPage, bodies *[]map[string]any) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/read") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		*bodies = append(*bodies, body)

		i := int(calls.Add(1)) - 1
		if i >= len(pages) {
			t.Errorf("Read called %d times, only %d pages were staged", i+1, len(pages))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pages[i])
	}))
}

// TestReadTuples_WalksTheContinuationCursor is the regression for a
// single-page read: the server hands back a continuation token, and every
// tuple behind it must come back in order.
func TestReadTuples_WalksTheContinuationCursor(t *testing.T) {
	pages := []readPage{
		{
			Tuples: []readTuple{
				{Key: Tuple{User: "user:alice", Relation: "member", Object: "team:acme/ops"}, Timestamp: "2026-01-01T00:00:00Z"},
				{Key: Tuple{User: "tenant:acme", Relation: "parent", Object: "team:acme/ops"}, Timestamp: "2026-01-01T00:00:00Z"},
			},
			ContinuationToken: "page-2",
		},
		{
			Tuples: []readTuple{
				{Key: Tuple{User: "user:bob", Relation: "member", Object: "team:acme/ops"}, Timestamp: "2026-01-01T00:00:00Z"},
			},
			ContinuationToken: "",
		},
	}

	var bodies []map[string]any
	srv := fgaReadServer(t, pages, &bodies)
	defer srv.Close()

	got, err := newTestFgaAuthorizer(t, srv.URL).
		ReadTuples(context.Background(), "", "", "team:acme/ops")
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}

	want := []Tuple{
		{User: "user:alice", Relation: "member", Object: "team:acme/ops"},
		{User: "tenant:acme", Relation: "parent", Object: "team:acme/ops"},
		{User: "user:bob", Relation: "member", Object: "team:acme/ops"},
	}
	if len(got) != len(want) {
		t.Fatalf("ReadTuples returned %d tuples (%v), want %d — the second page was dropped", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tuple %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("Read was called %d times, want 2 (one per page)", len(bodies))
	}
	// The object filter must reach the server: a dropped filter would read the
	// whole store and the migration would move tuples it never inspected.
	if obj, _ := bodies[0]["tuple_key"].(map[string]any); obj == nil || obj["object"] != "team:acme/ops" {
		t.Errorf("first Read body = %v, want tuple_key.object = team:acme/ops", bodies[0])
	}
}

// TestReadTuples_OmitsEmptyFilterFields pins that a wildcard stays a wildcard.
// Sending user="" as an explicit empty string matches nothing in OpenFGA, so a
// migration reading "everything on this object" would come back empty and
// report the team as already migrated.
func TestReadTuples_OmitsEmptyFilterFields(t *testing.T) {
	var bodies []map[string]any
	srv := fgaReadServer(t, []readPage{{}}, &bodies)
	defer srv.Close()

	if _, err := newTestFgaAuthorizer(t, srv.URL).
		ReadTuples(context.Background(), "", "", "team:"); err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("Read was called %d times, want 1", len(bodies))
	}
	key, _ := bodies[0]["tuple_key"].(map[string]any)
	if key == nil {
		t.Fatalf("Read body has no tuple_key: %v", bodies[0])
	}
	if _, present := key["user"]; present {
		t.Errorf("empty user was sent as a filter field: %v", key)
	}
	if _, present := key["relation"]; present {
		t.Errorf("empty relation was sent as a filter field: %v", key)
	}
}

// TestReadTuples_SendsEveryPopulatedFilterField is the positive control for the
// test above: a filter that IS set must reach the server. The migration's
// component-access read is user+relation+object, and dropping any one of them
// would widen it into tuples it then deletes.
func TestReadTuples_SendsEveryPopulatedFilterField(t *testing.T) {
	var bodies []map[string]any
	srv := fgaReadServer(t, []readPage{{}}, &bodies)
	defer srv.Close()

	if _, err := newTestFgaAuthorizer(t, srv.URL).
		ReadTuples(context.Background(), "team:acme/ops#member", "can_use", "component:"); err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("Read was called %d times, want 1", len(bodies))
	}
	key, _ := bodies[0]["tuple_key"].(map[string]any)
	for field, want := range map[string]string{
		"user":     "team:acme/ops#member",
		"relation": "can_use",
		"object":   "component:",
	} {
		if key[field] != want {
			t.Errorf("tuple_key.%s = %v, want %q", field, key[field], want)
		}
	}
}

// TestReadTuples_SurfacesAServerError pins that a failed page is an error, not
// a short read. Returning the tuples gathered so far would make a partial read
// indistinguishable from a complete one, and the migration deletes what it
// believes it has copied.
func TestReadTuples_SurfacesAServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/read") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
	}))
	defer srv.Close()

	got, err := newTestFgaAuthorizer(t, srv.URL).
		ReadTuples(context.Background(), "", "", "team:acme/ops")
	if err == nil {
		t.Fatal("ReadTuples returned no error for a 500 response")
	}
	if got != nil {
		t.Errorf("ReadTuples returned %v alongside the error; a partial read must not look like a result", got)
	}
}

// TestReadTuples_StopsAtThePageBound pins the loop bound. A server that always
// hands back a continuation token — a bug, or a filter matching far more than a
// migration should touch — must stop the walk with an error rather than spin
// forever inside a CI job.
func TestReadTuples_StopsAtThePageBound(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/read") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readPage{
			Tuples:            []readTuple{{Key: Tuple{User: "user:a", Relation: "member", Object: "team:acme/ops"}, Timestamp: "2026-01-01T00:00:00Z"}},
			ContinuationToken: fmt.Sprintf("page-%d", n+1),
		})
	}))
	defer srv.Close()

	_, err := newTestFgaAuthorizer(t, srv.URL).
		ReadTuples(context.Background(), "", "", "team:acme/ops")
	if err == nil {
		t.Fatal("ReadTuples followed an endless cursor without complaining")
	}
	if !strings.Contains(err.Error(), "pages") {
		t.Errorf("error %q does not say the page bound was hit", err)
	}
	if got := int(calls.Load()); got != readTuplesMaxPages {
		t.Errorf("Read was called %d times, want exactly the %d-page bound", got, readTuplesMaxPages)
	}
}
