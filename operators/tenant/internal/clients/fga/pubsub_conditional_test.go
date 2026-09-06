// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for publishingClient.WriteConditional — verifies delegation and
// error wrapping without touching Redis.
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
package fga

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// stubClient is a minimal Client fake for delegation tests.
// It can be pre-loaded with a per-method error.
type stubClient struct {
	writeConditionalErr   error
	writeConditionalCalls []ConditionalTuple
}

func (s *stubClient) Write(_ context.Context, _ []Tuple) error              { return nil }
func (s *stubClient) Delete(_ context.Context, _ []Tuple) error             { return nil }
func (s *stubClient) Read(_ context.Context, _ Tuple) ([]Tuple, error)      { return nil, nil }
func (s *stubClient) Check(_ context.Context, _, _, _ string) (bool, error) { return false, nil }
func (s *stubClient) Ping(_ context.Context) error                          { return nil }

func (s *stubClient) WriteConditional(_ context.Context, t ConditionalTuple) error {
	s.writeConditionalCalls = append(s.writeConditionalCalls, t)
	return s.writeConditionalErr
}

// Ensure stubClient satisfies the Client interface at compile time.
var _ Client = (*stubClient)(nil)

// TestPublishingClient_WriteConditional_Delegates verifies that
// publishingClient.WriteConditional passes the tuple through to the inner
// client unchanged and returns nil on success.
func TestPublishingClient_WriteConditional_Delegates(t *testing.T) {
	inner := &stubClient{}
	// Build a publishingClient with a fake publisher (can be noop — the
	// WriteConditional wrapper explicitly does NOT publish).
	pc := &publishingClient{Client: inner, pub: NewNoopPublisher()}

	tuple := ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
		ConditionContext: map[string]any{
			"revoked_at": "1970-01-01T00:00:00Z",
		},
	}
	if err := pc.WriteConditional(context.Background(), tuple); err != nil {
		t.Fatalf("WriteConditional: unexpected error: %v", err)
	}
	if len(inner.writeConditionalCalls) != 1 {
		t.Fatalf("expected 1 inner call, got %d", len(inner.writeConditionalCalls))
	}
	got := inner.writeConditionalCalls[0]
	if got.User != tuple.User {
		t.Errorf("User = %q, want %q", got.User, tuple.User)
	}
	if got.Object != tuple.Object {
		t.Errorf("Object = %q, want %q", got.Object, tuple.Object)
	}
}

// TestPublishingClient_WriteConditional_WrapsError verifies that an inner
// error is wrapped with the "fga: WriteConditional:" prefix.
func TestPublishingClient_WriteConditional_WrapsError(t *testing.T) {
	inner := &stubClient{
		writeConditionalErr: errors.New("FGA unavailable"),
	}
	pc := &publishingClient{Client: inner, pub: NewNoopPublisher()}

	err := pc.WriteConditional(context.Background(), ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
	})
	if err == nil {
		t.Fatal("expected wrapped error, got nil")
	}
	// Verify wrapping: the original error is still unwrappable.
	if !errors.Is(err, inner.writeConditionalErr) {
		t.Errorf("errors.Is: wrapped error should contain original, got %v", err)
	}
	// Verify the prefix is present.
	want := fmt.Sprintf("fga: WriteConditional: %v", inner.writeConditionalErr)
	if err.Error() != want {
		t.Errorf("error message = %q, want %q", err.Error(), want)
	}
}

// TestPublishingClient_WriteConditional_DoesNotPublish verifies that no
// event is published after WriteConditional — condition-bearing tuples are
// NOT membership changes and MUST NOT trigger the cache-invalidation path.
func TestPublishingClient_WriteConditional_DoesNotPublish(t *testing.T) {
	inner := &stubClient{}
	spy := &publishCountSpy{}
	pc := &publishingClient{Client: inner, pub: spy}

	err := pc.WriteConditional(context.Background(), ConditionalTuple{
		User:          "user:alice",
		Relation:      "active_session",
		Object:        "tenant:acme",
		ConditionName: "token_not_revoked",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spy.count != 0 {
		t.Errorf("WriteConditional must NOT publish to Redis; spy count = %d", spy.count)
	}
}

// publishCountSpy counts Publish calls without touching Redis.
type publishCountSpy struct {
	count int
}

func (s *publishCountSpy) Publish(_ context.Context, _ Event) {
	s.count++
}
