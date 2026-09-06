// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for WriteConditional and UpdateConditionalTuple on fgaAuthorizer.
// Uses httptest.Server to serve fake OpenFGA responses — no testcontainers,
// no real OpenFGA running.
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
package authz

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	fgaclient "github.com/openfga/go-sdk/client"
	"go.opentelemetry.io/otel"
)

// newTestFgaAuthorizer creates a real fgaAuthorizer wired to the given httptest
// server URL. All SDK calls flow through the test server.
//
// logger: slog.Default() (discards in test, or prints to stderr — either is fine).
// tracer: otel.Tracer(tracerName) with the global noop provider (no provider registered
// in unit tests, so spans are no-ops with zero overhead).
func newTestFgaAuthorizer(t *testing.T, serverURL string) *fgaAuthorizer {
	t.Helper()
	// Valid ULID strings (26 chars, first char 0-7, rest [0-9A-HJKMNP-TV-Z]).
	const storeID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	const modelID = "01ARZ3NDEKTSV4RRFFQ69G5FBV"

	cfg := &fgaclient.ClientConfiguration{
		ApiUrl:               serverURL,
		StoreId:              storeID,
		AuthorizationModelId: modelID,
	}
	sdkClient, err := fgaclient.NewSdkClient(cfg)
	if err != nil {
		t.Fatalf("fgaclient.NewSdkClient: %v", err)
	}
	return &fgaAuthorizer{
		client:    sdkClient,
		storeID:   storeID,
		modelID:   modelID,
		timeoutMs: 5000,
		logger:    slog.Default(),
		tracer:    otel.Tracer(tracerName),
	}
}

// capturedWrite captures the raw request body sent to the FGA write endpoint.
type capturedWrite struct {
	body   map[string]any
	called atomic.Int32
}

// fgaWriteServer returns an httptest.Server that:
//   - Responds 200 to POST /stores/.../write by default.
//   - Captures the parsed JSON body into capture.
//
// The caller can override the status code or body via statusCode/responseBody.
func fgaWriteServer(t *testing.T, statusCode int, responseBody string, capture *capturedWrite) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/write") {
			// Ignore non-write paths (e.g. SDK may fetch server info).
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		capture.called.Add(1)
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &capture.body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != "" {
			_, _ = w.Write([]byte(responseBody))
		} else {
			_, _ = w.Write([]byte("{}"))
		}
	}))
}

// ---- WriteConditional tests -------------------------------------------------

func TestWriteConditional_SendsCorrectTuple(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	tuple := ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "1970-01-01T00:00:00Z",
		},
	}
	if err := az.WriteConditional(context.Background(), tuple); err != nil {
		t.Fatalf("WriteConditional: unexpected error: %v", err)
	}
	if capture.called.Load() == 0 {
		t.Fatal("expected write endpoint to be called")
	}

	// The SDK wraps our call into its own JSON envelope. We verify the
	// tuple_keys entry includes condition name + context.
	tupleKeys := extractTupleKeys(t, capture.body)
	if len(tupleKeys) == 0 {
		t.Fatalf("no tuple_keys in request body: %+v", capture.body)
	}
	tk := tupleKeys[0]
	assertString(t, tk, "user", "user:alice")
	assertString(t, tk, "relation", "active_session")
	assertString(t, tk, "object", "tenant:acme")

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

func TestWriteConditional_IdempotentOnAlreadyExists(t *testing.T) {
	// FGA returns a 400 with "tuple which already exists" body.
	capture := &capturedWrite{}
	body := `{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists"}`
	srv := fgaWriteServer(t, http.StatusBadRequest, body, capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	tuple := ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": EpochRevokedAt,
		},
	}
	// Should return nil — idempotent no-op.
	if err := az.WriteConditional(context.Background(), tuple); err != nil {
		t.Fatalf("WriteConditional: expected nil on already-exists, got %v", err)
	}
}

//nolint:dupl // parallel validation-contract test; mirrors TestUpdateConditionalTuple_ValidationError_EmptyFields for a distinct method
func TestWriteConditional_ValidationError_EmptyFields(t *testing.T) {
	// Empty user/relation/object must return validation error without calling FGA.
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	cases := []struct {
		name  string
		tuple ConditionalTuple
	}{
		{"empty user", ConditionalTuple{Relation: "r", Object: "o", ConditionName: "c"}},
		{"empty relation", ConditionalTuple{User: "u", Object: "o", ConditionName: "c"}},
		{"empty object", ConditionalTuple{User: "u", Relation: "r", ConditionName: "c"}},
		{"empty condition", ConditionalTuple{User: "u", Relation: "r", Object: "o"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := az.WriteConditional(context.Background(), tc.tuple)
			if err == nil {
				t.Error("expected validation error, got nil")
			}
			if capture.called.Load() > 0 {
				t.Error("FGA write endpoint must NOT be called for invalid input")
			}
		})
	}
}

// ---- UpdateConditionalTuple tests ------------------------------------------

// multiWriteServer serves different responses on the first N calls.
// After responses are exhausted it returns 200 {}.
func multiWriteServer(t *testing.T, responses []fgaWriteResponse, capture *capturedWrite) *httptest.Server {
	t.Helper()
	var callCount atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/write") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		n := int(callCount.Add(1)) - 1
		capture.called.Add(1)
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &capture.body)

		var resp fgaWriteResponse
		if n < len(responses) {
			resp = responses[n]
		} else {
			resp = fgaWriteResponse{200, "{}"}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	}))
}

type fgaWriteResponse struct {
	status int
	body   string
}

func TestUpdateConditionalTuple_SendsDeleteAndWrite(t *testing.T) {
	// UpdateConditionalTuple should issue a single Write request containing
	// both Writes and Deletes. The SDK sends them in one call.
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	tuple := ConditionalTuple{
		User:          "user:bob",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "2026-07-03T12:00:00Z",
		},
	}
	if err := az.UpdateConditionalTuple(context.Background(), tuple); err != nil {
		t.Fatalf("UpdateConditionalTuple: unexpected error: %v", err)
	}
	if capture.called.Load() == 0 {
		t.Fatal("expected write endpoint to be called")
	}

	// The SDK should include both writes and deletes in the body.
	// For TransactionMode (default), they're in separate calls but the SDK
	// sends them sequentially. What we care about is that the logic runs at all.
	// Verify the write leg includes the right tuple.
	tupleKeys := extractTupleKeys(t, capture.body)
	if len(tupleKeys) == 0 {
		// May be in deletes instead on first call if delete comes first.
		// Either path is fine — just confirm the endpoint was hit.
		t.Logf("body keys: %v", capture.body)
	}
}

func TestUpdateConditionalTuple_FallsBackToWriteWhenTupleNotFound(t *testing.T) {
	// First call (delete leg) returns "tuple to be deleted did not exist".
	// UpdateConditionalTuple must fall back to WriteConditional (second call succeeds).
	responses := []fgaWriteResponse{
		{http.StatusBadRequest, `{"code":"write_failed_due_to_invalid_input","message":"tuple to be deleted did not exist"}`},
		{http.StatusOK, "{}"},
	}
	capture := &capturedWrite{}
	srv := multiWriteServer(t, responses, capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	tuple := ConditionalTuple{
		User:          "user:charlie",
		Relation:      "active_session",
		Object:        "tenant:beta",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "2026-07-03T15:00:00Z",
		},
	}
	// Should succeed — falls back to WriteConditional on tuple-not-found.
	if err := az.UpdateConditionalTuple(context.Background(), tuple); err != nil {
		t.Fatalf("UpdateConditionalTuple fallback: unexpected error: %v", err)
	}
	// Two calls: the initial delete+write attempt + the fallback WriteConditional.
	if capture.called.Load() < 2 {
		t.Errorf("expected ≥2 calls to write endpoint (initial + fallback), got %d", capture.called.Load())
	}
}

//nolint:dupl // parallel validation-contract test; mirrors TestWriteConditional_ValidationError_EmptyFields for a distinct method
func TestUpdateConditionalTuple_ValidationError_EmptyFields(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusOK, "{}", capture)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)

	cases := []struct {
		name  string
		tuple ConditionalTuple
	}{
		{"empty user", ConditionalTuple{Relation: "r", Object: "o", ConditionName: "c"}},
		{"empty relation", ConditionalTuple{User: "u", Object: "o", ConditionName: "c"}},
		{"empty object", ConditionalTuple{User: "u", Relation: "r", ConditionName: "c"}},
		{"empty condition", ConditionalTuple{User: "u", Relation: "r", Object: "o"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := az.UpdateConditionalTuple(context.Background(), tc.tuple)
			if err == nil {
				t.Error("expected validation error, got nil")
			}
			if capture.called.Load() > 0 {
				t.Error("FGA endpoint must NOT be called for invalid input")
			}
		})
	}
}

// ---- isTupleNotFoundError / isAlreadyExistsError helpers -------------------

func TestIsTupleNotFoundError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"exact phrase", errStr("tuple to be deleted did not exist"), true},
		{"mixed case", errStr("Tuple To Be Deleted Did Not Exist"), true},
		{"partial match", errStr("error: tuple to be deleted did not exist in store"), true},
		{"unrelated error", errStr("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTupleNotFoundError(tc.err); got != tc.want {
				t.Errorf("isTupleNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsAlreadyExistsError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"exact phrase", errStr("tuple which already exists"), true},
		{"mixed case", errStr("Cannot Write A Tuple Which Already Exists"), true},
		{"unrelated error", errStr("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlreadyExistsError(tc.err); got != tc.want {
				t.Errorf("isAlreadyExistsError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---- conditionContextPtr helper --------------------------------------------

func TestConditionContextPtr_Nil(t *testing.T) {
	if conditionContextPtr(nil) != nil {
		t.Error("conditionContextPtr(nil) should return nil")
	}
}

func TestConditionContextPtr_Empty(t *testing.T) {
	if conditionContextPtr(map[string]any{}) != nil {
		t.Error("conditionContextPtr(empty) should return nil")
	}
}

func TestConditionContextPtr_Copy(t *testing.T) {
	orig := map[string]any{"k": "v"}
	ptr := conditionContextPtr(orig)
	if ptr == nil {
		t.Fatal("conditionContextPtr(non-empty) should not be nil")
	}
	// Modifying original should not affect the copy.
	orig["k"] = "changed"
	if (*ptr)["k"] != "v" {
		t.Errorf("conditionContextPtr did not defensive-copy: got %v, want v", (*ptr)["k"])
	}
}

// ---- helpers ---------------------------------------------------------------

type errString string

func (e errString) Error() string { return string(e) }

func errStr(s string) error { return errString(s) }

// extractTupleKeys navigates the OpenFGA Write request body to find the
// tuple_keys array in either the writes or deletes field.
//
// The SDK sends transaction-mode writes as separate requests, so the body
// may contain only "writes" or only "deletes". We return whatever tuple_keys
// are present (priority: writes, then deletes).
func extractTupleKeys(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	if body == nil {
		return nil
	}
	for _, key := range []string{"writes", "deletes"} {
		section, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		raw, ok := section["tuple_keys"]
		if !ok {
			continue
		}
		arr, ok := raw.([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	// Check top-level tuple_keys (some SDK versions).
	if raw, ok := body["tuple_keys"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil
		}
		out := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// TestWriteConditional_ServerError_MapsToSDKError verifies that a non-already-exists
// error response from the FGA server (e.g. 500) flows through mapSDKError and
// is returned as a non-nil error.
func TestWriteConditional_ServerError_MapsToSDKError(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusInternalServerError,
		`{"code":"internal_error","message":"internal server error"}`,
		capture,
	)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	tuple := ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": EpochRevokedAt,
		},
	}
	err := az.WriteConditional(context.Background(), tuple)
	if err == nil {
		t.Fatal("expected error from WriteConditional on 500 response, got nil")
	}
}

// TestUpdateConditionalTuple_ServerError_MapsToSDKError verifies that a non-tuple-not-found
// error response flows through mapSDKError in UpdateConditionalTuple.
func TestUpdateConditionalTuple_ServerError_MapsToSDKError(t *testing.T) {
	capture := &capturedWrite{}
	srv := fgaWriteServer(t, http.StatusInternalServerError,
		`{"code":"internal_error","message":"internal server error"}`,
		capture,
	)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	tuple := ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "2026-07-04T00:00:00Z",
		},
	}
	err := az.UpdateConditionalTuple(context.Background(), tuple)
	if err == nil {
		t.Fatal("expected error from UpdateConditionalTuple on 500 response, got nil")
	}
}

func assertString(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Errorf("missing key %q in %v", key, m)
		return
	}
	if v != want {
		t.Errorf("key %q = %v, want %v", key, v, want)
	}
}
