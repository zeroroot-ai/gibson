// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for WriteAndDelete on fgaAuthorizer (hosted#190 — ownership transfer
// needs a single-transaction write+delete over plain, unconditioned tuples).
// Uses httptest.Server to serve fake OpenFGA responses, same harness as
// client_conditional_test.go.
package authz

import (
	"context"
	"net/http"
	"testing"
)

func TestWriteAndDelete_SendsWritesAndDeletesInOneCall(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	writes := []Tuple{
		{User: "user:bob", Relation: "owner", Object: "tenant:acme"},
		{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
	}
	deletes := []Tuple{
		{User: "user:alice", Relation: "owner", Object: "tenant:acme"},
	}
	if err := az.WriteAndDelete(context.Background(), writes, deletes); err != nil {
		t.Fatalf("WriteAndDelete: unexpected error: %v", err)
	}
	if capture.called.Load() != 1 {
		t.Fatalf("expected exactly 1 call to the FGA write endpoint, got %d", capture.called.Load())
	}

	writesSection, ok := capture.body["writes"].(map[string]any)
	if !ok {
		t.Fatalf("request body has no writes section: %+v", capture.body)
	}
	deletesSection, ok := capture.body["deletes"].(map[string]any)
	if !ok {
		t.Fatalf("request body has no deletes section: %+v", capture.body)
	}

	writeKeys, ok := writesSection["tuple_keys"].([]any)
	if !ok || len(writeKeys) != 2 {
		t.Fatalf("expected 2 write tuple_keys, got %+v", writesSection)
	}
	deleteKeys, ok := deletesSection["tuple_keys"].([]any)
	if !ok || len(deleteKeys) != 1 {
		t.Fatalf("expected 1 delete tuple_key, got %+v", deletesSection)
	}

	first, ok := writeKeys[0].(map[string]any)
	if !ok {
		t.Fatalf("write tuple key is not an object: %+v", writeKeys[0])
	}
	assertString(t, first, "user", "user:bob")
	assertString(t, first, "relation", "owner")
	assertString(t, first, "object", "tenant:acme")

	del, ok := deleteKeys[0].(map[string]any)
	if !ok {
		t.Fatalf("delete tuple key is not an object: %+v", deleteKeys[0])
	}
	assertString(t, del, "user", "user:alice")
	assertString(t, del, "relation", "owner")
	assertString(t, del, "object", "tenant:acme")
}

// TestWriteAndDelete_NoRetryOnAlreadyExists asserts WriteAndDelete does NOT
// swallow or retry around an "already exists" error the way Write does. The
// whole point of this method (hosted#190) is that a failure means NOTHING
// was applied; a caller that gets an error back must be able to trust that,
// which rules out the writeMissing-style partial-retry Write performs.
func TestWriteAndDelete_NoRetryOnAlreadyExists(t *testing.T) {
	capture := &capturedWrite{}
	body := `{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`
	srv := fgaWriteServer(t, http.StatusBadRequest, body, capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	writes := []Tuple{{User: "user:bob", Relation: "admin", Object: "tenant:acme"}}
	err := az.WriteAndDelete(context.Background(), writes, nil)
	if err == nil {
		t.Fatal("expected an error from WriteAndDelete on already-exists, got nil")
	}
	if capture.called.Load() != 1 {
		t.Fatalf("expected exactly 1 call (no retry), got %d", capture.called.Load())
	}
}

func TestWriteAndDelete_ServerError_MapsToSDKError(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusInternalServerError,
		`{"code":"internal_error","message":"internal server error"}`,
		capture,
	)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	err := az.WriteAndDelete(context.Background(),
		[]Tuple{{User: "user:bob", Relation: "owner", Object: "tenant:acme"}},
		[]Tuple{{User: "user:alice", Relation: "owner", Object: "tenant:acme"}},
	)
	if err == nil {
		t.Fatal("expected error from WriteAndDelete on 500 response, got nil")
	}
}

func TestWriteAndDelete_EmptyIsNoOp(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	if err := az.WriteAndDelete(context.Background(), nil, nil); err != nil {
		t.Fatalf("WriteAndDelete with no tuples: unexpected error: %v", err)
	}
	if capture.called.Load() != 0 {
		t.Errorf("expected no FGA call for an empty WriteAndDelete, got %d", capture.called.Load())
	}
}

// TestFgaAuthorizerImplementsAtomicWriter pins that the production
// implementation satisfies the optional AtomicWriter interface TransferOwnership
// type-asserts against.
func TestFgaAuthorizerImplementsAtomicWriter(t *testing.T) {
	var _ AtomicWriter = (*fgaAuthorizer)(nil)
}
