// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

package daemon

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"
)

// verifyingSetec answers VerifySandboxIdentity. The embedded interface
// panics on any other call.
type verifyingSetec struct {
	setecv1.SandboxServiceClient
	req  *setecv1.VerifySandboxIdentityRequest
	resp *setecv1.VerifySandboxIdentityResponse
	err  error
}

func (v *verifyingSetec) VerifySandboxIdentity(_ context.Context, in *setecv1.VerifySandboxIdentityRequest, _ ...grpc.CallOption) (*setecv1.VerifySandboxIdentityResponse, error) {
	v.req = in
	return v.resp, v.err
}

// The adapter sends the token, the audience and the tenant, and returns the
// sandbox id that setec verified (setec#235).
func TestSetecClient_VerifySandboxIdentity(t *testing.T) {
	rec := &verifyingSetec{resp: &setecv1.VerifySandboxIdentityResponse{SandboxId: "ns/fork-1/u1"}}
	c := &setecClient{inner: rec}
	id, err := c.VerifySandboxIdentity(context.Background(), "acme", "tok", harness.SandboxIdentityAudience)
	if err != nil || id != "ns/fork-1/u1" {
		t.Fatalf("VerifySandboxIdentity = %q, %v", id, err)
	}
	if rec.req.GetToken() != "tok" || rec.req.GetTenant() != "acme" || rec.req.GetAudience() != harness.SandboxIdentityAudience {
		t.Fatalf("request = %v", rec.req)
	}
}

// A token that setec refuses wraps ErrSandboxIdentityRefused. A setec that
// cannot answer does not, so the callback service answers Unavailable.
func TestSetecClient_VerifySandboxIdentityErrors(t *testing.T) {
	ctx := context.Background()
	for _, code := range []codes.Code{codes.Unauthenticated, codes.InvalidArgument, codes.PermissionDenied, codes.NotFound} {
		c := &setecClient{inner: &verifyingSetec{err: status.Error(code, "no")}}
		if _, err := c.VerifySandboxIdentity(ctx, "acme", "tok", "aud"); !errors.Is(err, harness.ErrSandboxIdentityRefused) {
			t.Errorf("%v: err = %v, want ErrSandboxIdentityRefused", code, err)
		}
	}
	c := &setecClient{inner: &verifyingSetec{err: status.Error(codes.Unavailable, "down")}}
	if _, err := c.VerifySandboxIdentity(ctx, "acme", "tok", "aud"); err == nil || errors.Is(err, harness.ErrSandboxIdentityRefused) {
		t.Errorf("unavailable: err = %v, want a plain error", err)
	}
	c = &setecClient{inner: &verifyingSetec{resp: &setecv1.VerifySandboxIdentityResponse{}}}
	if _, err := c.VerifySandboxIdentity(ctx, "acme", "tok", "aud"); !errors.Is(err, harness.ErrSandboxIdentityRefused) {
		t.Errorf("empty id: err = %v, want ErrSandboxIdentityRefused", err)
	}
	if _, err := c.VerifySandboxIdentity(ctx, "", "tok", "aud"); !errors.Is(err, errNoTenant) {
		t.Errorf("no tenant: err = %v, want errNoTenant", err)
	}
}
