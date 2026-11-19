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

// gateServer is a fake OpenFGA. It answers /check with checkAllowed (and keeps
// the consistency that the call asked for) and answers each /write with the next
// of writeReplies. It records the shape of each write: "write" or "delete".
type gateServer struct {
	mu           sync.Mutex
	checkAllowed bool
	consistency  []string
	writeReplies []fgaWriteResponse
	shapes       []string
}

func (g *gateServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/check"):
			c, _ := body["consistency"].(string)
			g.consistency = append(g.consistency, c)
			_, _ = w.Write([]byte(`{"allowed":` + map[bool]string{true: "true", false: "false"}[g.checkAllowed] + `}`))
		case strings.HasSuffix(r.URL.Path, "/write"):
			shape := ""
			if _, ok := body["writes"]; ok {
				shape += "write"
			}
			if _, ok := body["deletes"]; ok {
				shape += "delete"
			}
			g.shapes = append(g.shapes, shape)
			reply := fgaWriteResponse{http.StatusOK, "{}"}
			if len(g.writeReplies) > 0 {
				reply, g.writeReplies = g.writeReplies[0], g.writeReplies[1:]
			}
			w.WriteHeader(reply.status)
			_, _ = w.Write([]byte(reply.body))
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The gate is absent and has to open: one write request with no delete, so the
// key is never absent between two requests. The read asks for higher
// consistency.
func TestSetMissionGate_OpensWithOneWriteAndNoDelete(t *testing.T) {
	g := &gateServer{}
	az := newTestFgaAuthorizer(t, g.start(t).URL)
	if err := az.SetMissionGate(context.Background(), "acme", "m1", true); err != nil {
		t.Fatalf("SetMissionGate: %v", err)
	}
	if strings.Join(g.shapes, ",") != "write" {
		t.Fatalf("write requests = %v, want one write and no delete", g.shapes)
	}
	if len(g.consistency) != 1 || g.consistency[0] != "HIGHER_CONSISTENCY" {
		t.Fatalf("read consistency = %v, want HIGHER_CONSISTENCY", g.consistency)
	}
}

// The gate is open already: no write at all. The old code deleted the tuple and
// wrote it again, so the key was absent for a moment.
func TestSetMissionGate_AnOpenGateIsNotWrittenAgain(t *testing.T) {
	g := &gateServer{checkAllowed: true}
	az := newTestFgaAuthorizer(t, g.start(t).URL)
	if err := az.SetMissionGate(context.Background(), "acme", "m1", true); err != nil {
		t.Fatalf("SetMissionGate: %v", err)
	}
	if len(g.shapes) != 0 {
		t.Fatalf("write requests = %v, want none for a gate that is open", g.shapes)
	}
}

// A closed gate is a delete in one request. A tuple that is absent is fine.
func TestSetMissionGate_ClosesWithOneDelete(t *testing.T) {
	g := &gateServer{}
	az := newTestFgaAuthorizer(t, g.start(t).URL)
	if err := az.SetMissionGate(context.Background(), "acme", "m1", false); err != nil {
		t.Fatalf("SetMissionGate: %v", err)
	}
	if strings.Join(g.shapes, ",") != "delete" {
		t.Fatalf("write requests = %v, want one delete", g.shapes)
	}

	g2 := &gateServer{writeReplies: []fgaWriteResponse{
		{http.StatusBadRequest, `{"code":"write_failed_due_to_invalid_input","message":"tuple to be deleted did not exist"}`},
	}}
	az2 := newTestFgaAuthorizer(t, g2.start(t).URL)
	if err := az2.SetMissionGate(context.Background(), "acme", "m1", false); err != nil {
		t.Fatalf("closing an absent gate: %v", err)
	}
}

// A tuple of the older shape (active false) exists. Opening replaces it. The
// gate was closed, so the delete and write leave no open gate absent.
func TestSetMissionGate_ReplacesAClosedTupleOfTheOlderShape(t *testing.T) {
	g := &gateServer{writeReplies: []fgaWriteResponse{
		{http.StatusBadRequest, `{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`},
		{http.StatusOK, "{}"}, {http.StatusOK, "{}"},
	}}
	az := newTestFgaAuthorizer(t, g.start(t).URL)
	if err := az.SetMissionGate(context.Background(), "acme", "m1", true); err != nil {
		t.Fatalf("SetMissionGate: %v", err)
	}
	if got := strings.Join(g.shapes, ","); got != "write,delete,write" {
		t.Fatalf("write requests = %s, want write, delete, write", got)
	}
}

func TestSetMissionGate_RefusesAnEmptyField(t *testing.T) {
	az := newTestFgaAuthorizer(t, "http://127.0.0.1:1")
	if err := az.SetMissionGate(context.Background(), "", "m1", true); err == nil {
		t.Fatal("want an error for an empty tenant")
	}
}
