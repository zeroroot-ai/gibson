// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"testing"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/zeroroot-ai/gibson/internal/infra/authz"
)

// TestClassifyOutcome verifies the OTel attribute mapping covers each
// platform-clients sentinel error + the allow/deny path. Low-cardinality
// labels are critical for the histogram and counter: any new error
// shape must be classified here, not leaked as a unique string.
func TestClassifyOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		resp authz.CheckResponse
		err  error
		want string
	}{
		{"allow", authz.CheckResponse{Allowed: true}, nil, "allow"},
		{"deny", authz.CheckResponse{Allowed: false}, nil, "deny"},
		{"timeout", authz.CheckResponse{}, authz.ErrFGATimeout, "timeout"},
		{"unavailable", authz.CheckResponse{}, authz.ErrFGAUnavailable, "unavailable"},
		{"invalid", authz.CheckResponse{}, authz.ErrInvalidArgument, "invalid"},
		{"wrapped-timeout", authz.CheckResponse{}, errors.Join(authz.ErrFGATimeout, errors.New("ctx deadline")), "timeout"},
		{"unknown-error", authz.CheckResponse{}, errors.New("something else"), "error"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyOutcome(tc.resp, tc.err)
			if got != tc.want {
				t.Fatalf("classifyOutcome(%v, %v) = %q, want %q", tc.resp, tc.err, got, tc.want)
			}
		})
	}
}

// TestNewPlatformFGAClient_RequiresFields — bad opts must NOT silently
// succeed; the underlying platform-clients validator must propagate.
func TestNewPlatformFGAClient_RequiresFields(t *testing.T) {
	t.Parallel()
	_, err := NewPlatformFGAClient(authz.FGAClientOptions{})
	if err == nil {
		t.Fatal("expected error for empty options, got nil")
	}
}

// TestReadinessProbe_NilClient — defensive: probe with nil client must
// not panic and must return an error suitable for /readyz JSON.
func TestReadinessProbe_NilClient(t *testing.T) {
	t.Parallel()
	p := NewReadinessProbe(nil, "")
	if p.Name() != "fga" {
		t.Fatalf("expected default name %q, got %q", "fga", p.Name())
	}
	if err := p.Check(nil); err == nil { //nolint:staticcheck // testing nil ctx + nil client path
		t.Fatal("expected error for nil client, got nil")
	}
}

// captureFGA records the CheckRequest the adapter forwards to the inner
// platform client.
type captureFGA struct{ got authz.CheckRequest }

func (c *captureFGA) Check(_ context.Context, req authz.CheckRequest) (authz.CheckResponse, error) {
	c.got = req
	return authz.CheckResponse{Allowed: true}, nil
}
func (c *captureFGA) Close() error { return nil }

// The adapter used to build its inner CheckRequest from User/Relation/Object
// only, silently dropping ClientCheckRequest.Context. That is not a softer
// check: the active_session tuple carries a token_not_revoked condition, so
// OpenFGA rejected the whole Check as a validation error, ext-authz reported
// "FGA unavailable", and EVERY session-gated RPC 503'd tenant-wide. The
// package's other tests stub fga.FGAClient directly and therefore never
// exercised this adapter, which is how it shipped (gibson#1191).
func TestPlatformFGAAdapter_ForwardsConditionContext(t *testing.T) {
	inner := &captureFGA{}
	adapter := &platformFGAAdapter{inner: inner}

	condCtx := map[string]interface{}{"token_issued_at": "2026-08-05T12:00:00Z"}
	resp, err := adapter.Check(context.Background()).Body(fgaclient.ClientCheckRequest{
		User:     "user:alice",
		Relation: "active_session",
		Object:   "tenant:acme",
		Context:  &condCtx,
	}).Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Allowed == nil || !*resp.Allowed {
		t.Fatalf("expected allowed=true, got %v", resp.Allowed)
	}
	if got := inner.got.Context["token_issued_at"]; got != "2026-08-05T12:00:00Z" {
		t.Fatalf("condition context not forwarded: got %#v, want token_issued_at=2026-08-05T12:00:00Z", inner.got.Context)
	}
}

// A Check with no condition context must not invent one — an empty map would
// still be sent to OpenFGA and is not the same as omitting the field.
func TestPlatformFGAAdapter_NoContextStaysNil(t *testing.T) {
	inner := &captureFGA{}
	adapter := &platformFGAAdapter{inner: inner}

	if _, err := adapter.Check(context.Background()).Body(fgaclient.ClientCheckRequest{
		User:     "user:alice",
		Relation: "member",
		Object:   "tenant:acme",
	}).Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if inner.got.Context != nil {
		t.Fatalf("expected nil context, got %#v", inner.got.Context)
	}
}
