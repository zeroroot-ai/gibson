// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for HTTPClient.WriteConditional — httptest-based, no live FGA.
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
package fga

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// newTestHTTPClient wires the FGA HTTPClient to the given test server URL.
func newTestHTTPClient(t *testing.T, serverURL string) *HTTPClient {
	t.Helper()
	c, err := NewHTTPClient(Config{
		BaseURL: serverURL,
		StoreID: "test-store-id",
		ModelID: "test-model-id",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

// captureBody captures the parsed JSON body of the last POST to /write.
type captureBody struct {
	parsed map[string]any
}

func writeServerWithCode(t *testing.T, code int, body string, capture *captureBody) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if capture != nil {
			_ = json.Unmarshal(raw, &capture.parsed)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if body != "" {
			_, _ = w.Write([]byte(body))
		} else {
			_, _ = w.Write([]byte("{}"))
		}
	}))
}

// TestHTTPClient_WriteConditional_Success verifies that a 200 response
// produces a nil error and that the request body includes the condition.
func TestHTTPClient_WriteConditional_Success(t *testing.T) {
	capture := &captureBody{}
	srv := writeServerWithCode(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "1970-01-01T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("WriteConditional: unexpected error: %v", err)
	}

	// Verify the request body has the condition embedded in the tuple_keys.
	writes, ok := capture.parsed["writes"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'writes' in request body: %+v", capture.parsed)
	}
	tupleKeysRaw, ok := writes["tuple_keys"].([]any)
	if !ok || len(tupleKeysRaw) == 0 {
		t.Fatalf("expected tuple_keys in writes section: %+v", writes)
	}
	tk, ok := tupleKeysRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("tuple_keys[0] not a map: %v", tupleKeysRaw[0])
	}
	if tk["user"] != "user:alice" {
		t.Errorf("user = %v, want user:alice", tk["user"])
	}
	if tk["relation"] != "active_session" {
		t.Errorf("relation = %v, want active_session", tk["relation"])
	}
	if tk["object"] != "tenant:acme" {
		t.Errorf("object = %v, want tenant:acme", tk["object"])
	}
	cond, ok := tk["condition"].(map[string]any)
	if !ok {
		t.Fatalf("condition missing from tuple key: %+v", tk)
	}
	if cond["name"] != "token_not_revoked" {
		t.Errorf("condition.name = %v, want token_not_revoked", cond["name"])
	}
	ctx, ok := cond["context"].(map[string]any)
	if !ok {
		t.Fatalf("condition.context missing: %+v", cond)
	}
	if ctx["revoked_at"] != "1970-01-01T00:00:00Z" {
		t.Errorf("condition.context.revoked_at = %v, want 1970-01-01T00:00:00Z", ctx["revoked_at"])
	}
}

// TestHTTPClient_WriteConditional_AlreadyExists verifies that the "tuple to be
// written already existed" 400 body is treated as a no-op (nil error).
func TestHTTPClient_WriteConditional_AlreadyExists(t *testing.T) {
	// The exact substring doJSON checks for is "tuple to be written already existed".
	body := `{"code":"write_failed_due_to_invalid_input","message":"tuple to be written already existed"}`
	srv := writeServerWithCode(t, http.StatusBadRequest, body, nil)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:             "user:alice",
		Relation:         "active_session",
		Object:           "tenant:acme",
		ConditionName:    "token_not_revoked",
		ConditionContext: map[string]any{"revoked_at": "1970-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatalf("WriteConditional should return nil for already-exists, got %v", err)
	}
}

// TestHTTPClient_WriteConditional_Unauthorized verifies a 401 returns ErrUnauthorized.
func TestHTTPClient_WriteConditional_Unauthorized(t *testing.T) {
	srv := writeServerWithCode(t, http.StatusUnauthorized, `{"errors":["Unauthenticated"]}`, nil)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
	})
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized in chain, got %v", err)
	}
}

// TestHTTPClient_WriteConditional_ServerError verifies a 500 returns an error.
func TestHTTPClient_WriteConditional_ServerError(t *testing.T) {
	srv := writeServerWithCode(t, http.StatusInternalServerError, `{"errors":["internal"]}`, nil)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
	})
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

// TestHTTPClient_WriteConditional_NoCondition verifies that a ConditionalTuple
// with an empty ConditionName does NOT include a condition block in the payload.
func TestHTTPClient_WriteConditional_NoCondition(t *testing.T) {
	capture := &captureBody{}
	srv := writeServerWithCode(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:     "user:alice",
		Relation: "member",
		Object:   "tenant:acme",
		// ConditionName deliberately empty.
	})
	if err != nil {
		t.Fatalf("WriteConditional: unexpected error: %v", err)
	}

	writes, ok := capture.parsed["writes"].(map[string]any)
	if !ok {
		t.Fatalf("missing writes section: %+v", capture.parsed)
	}
	tupleKeysRaw, ok := writes["tuple_keys"].([]any)
	if !ok || len(tupleKeysRaw) == 0 {
		t.Fatalf("missing tuple_keys: %+v", writes)
	}
	tk, ok := tupleKeysRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("tuple_keys[0] not a map: %v", tupleKeysRaw[0])
	}
	if _, hasCond := tk["condition"]; hasCond {
		t.Errorf("condition block should be absent when ConditionName is empty, got: %+v", tk)
	}
}

// TestHTTPClient_WriteConditional_ConditionNoContext verifies a condition
// with no context omits the context field.
func TestHTTPClient_WriteConditional_ConditionNoContext(t *testing.T) {
	capture := &captureBody{}
	srv := writeServerWithCode(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	c := newTestHTTPClient(t, srv.URL)
	err := c.WriteConditional(context.Background(), ConditionalTuple{
		User:             "user:alice",
		Relation:         "active_session",
		Object:           "tenant:acme",
		ConditionName:    "token_not_revoked",
		ConditionContext: nil, // empty
	})
	if err != nil {
		t.Fatalf("WriteConditional: unexpected error: %v", err)
	}

	writes, ok := capture.parsed["writes"].(map[string]any)
	if !ok {
		t.Fatalf("missing writes section: %+v", capture.parsed)
	}
	tupleKeysRaw, ok := writes["tuple_keys"].([]any)
	if !ok || len(tupleKeysRaw) == 0 {
		t.Fatalf("missing tuple_keys: %+v", writes)
	}
	tk, _ := tupleKeysRaw[0].(map[string]any)
	cond, ok := tk["condition"].(map[string]any)
	if !ok {
		t.Fatalf("condition missing despite non-empty ConditionName: %+v", tk)
	}
	if _, hasCtx := cond["context"]; hasCtx {
		t.Errorf("context block should be absent when ConditionContext is nil, got: %+v", cond)
	}
}
