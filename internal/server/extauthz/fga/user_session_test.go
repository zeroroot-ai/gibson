// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// userTupleStub faithfully models the USER-SCOPED active_session tuple
// (user:<id>, active_session, user:<id>): it stores whether the tuple is
// present and its revoked_at, and evaluates the token_not_revoked condition
// (token_issued_at > revoked_at) against the token_issued_at passed in the
// Check context — exactly as OpenFGA would. This lets the CheckUserSession
// absent-vs-revoked disambiguation be exercised without a live FGA.
type userTupleStub struct {
	present   bool      // is (user:X, active_session, user:X) present?
	revokedAt time.Time // revoked_at stored in that tuple
	err       error     // optional infra error
	calls     int32
}

func (m *userTupleStub) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &userTupleReq{m: m}
}

type userTupleReq struct {
	m    *userTupleStub
	body fgaclient.ClientCheckRequest
}

func (r *userTupleReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *userTupleReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *userTupleReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	atomic.AddInt32(&r.m.calls, 1)
	if r.m.err != nil {
		return nil, r.m.err
	}
	allowed := false
	if r.m.present && r.body.Context != nil {
		if raw, ok := (*r.body.Context)["token_issued_at"]; ok {
			if s, ok := raw.(string); ok {
				if iat, perr := time.Parse(time.RFC3339, s); perr == nil {
					allowed = iat.After(r.m.revokedAt)
				}
			}
		}
	}
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *userTupleReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *userTupleReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *userTupleReq) GetContext() context.Context               { return context.Background() }
func (r *userTupleReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *userTupleReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// TestCheckUserSession_ValidSession_Allow — a present tuple with revoked_at at
// the epoch and a real, current iat → ALLOW on the first Check (fast path).
func TestCheckUserSession_ValidSession_Allow(t *testing.T) {
	t.Parallel()
	stub := &userTupleStub{present: true, revokedAt: time.Unix(0, 0).UTC()}
	checker := NewChecker(stub, makeMinimalReg(t))

	ok, err := checker.CheckUserSession(context.Background(), "u-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for a valid (present, not-revoked) session")
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Errorf("expected exactly 1 FGA call on the valid fast path, got %d", got)
	}
}

// TestCheckUserSession_Revoked_Deny — a present tuple whose revoked_at is AFTER
// the token's iat → DENY. This is the exposure gibson#1244 closes: a tenant-less
// request with a revoked session must be denied.
func TestCheckUserSession_Revoked_Deny(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	stub := &userTupleStub{present: true, revokedAt: now}
	checker := NewChecker(stub, makeMinimalReg(t))

	// Token issued an hour before the revocation → must be denied.
	ok, err := checker.CheckUserSession(context.Background(), "u-1", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected DENY for a revoked session presented tenant-less (the gibson#1244 bug)")
	}
	// Real-iat check (deny) + far-future existence probe (present) = 2 calls.
	if got := atomic.LoadInt32(&stub.calls); got != 2 {
		t.Errorf("expected 2 FGA calls (real + existence probe), got %d", got)
	}
}

// TestCheckUserSession_AbsentTuple_BootstrapAllow — no user-scoped tuple exists
// (a genuinely-first sign-in not yet provisioned into any tenant) → ALLOW.
// Denying it would make sign-in unrecoverable, which is why the tenant-less
// gate is allow-on-absent (unlike the deny-on-absent tenant-scoped gate).
func TestCheckUserSession_AbsentTuple_BootstrapAllow(t *testing.T) {
	t.Parallel()
	stub := &userTupleStub{present: false}
	checker := NewChecker(stub, makeMinimalReg(t))

	ok, err := checker.CheckUserSession(context.Background(), "u-new", time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ALLOW for an absent user-scoped tuple (sign-in bootstrap)")
	}
	// Real-iat check (deny) + far-future existence probe (still absent) = 2 calls.
	if got := atomic.LoadInt32(&stub.calls); got != 2 {
		t.Errorf("expected 2 FGA calls (real + existence probe), got %d", got)
	}
}

// TestCheckUserSession_ChecksSelfReferentialObject — the user-scoped gate must
// check (user:<sub>, active_session, user:<sub>): subject AND object are the
// caller's own user object.
func TestCheckUserSession_ChecksSelfReferentialObject(t *testing.T) {
	t.Parallel()
	capFGA := &capturingFGA{allowed: true}
	checker := NewChecker(capFGA, makeMinimalReg(t))

	_, err := checker.CheckUserSession(context.Background(), "u-42", time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := capFGA.lastBody.Load()
	if body == nil {
		t.Fatal("no FGA Check call recorded")
	}
	if body.User != "user:u-42" {
		t.Errorf("User = %q, want user:u-42", body.User)
	}
	if body.Object != "user:u-42" {
		t.Errorf("Object = %q, want user:u-42 (self-referential)", body.Object)
	}
	if body.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", body.Relation)
	}
	if body.Context == nil {
		t.Fatal("condition context must carry token_issued_at")
	}
	if _, ok := (*body.Context)["token_issued_at"]; !ok {
		t.Error("condition context missing token_issued_at")
	}
}

// TestCheckUserSession_EmptySubject_Error — a missing subject is an argument
// error, never a silent allow.
func TestCheckUserSession_EmptySubject_Error(t *testing.T) {
	t.Parallel()
	checker := NewChecker(&capturingFGA{allowed: true}, makeMinimalReg(t))
	if _, err := checker.CheckUserSession(context.Background(), "", time.Now().UTC()); err == nil {
		t.Fatal("expected error for empty subject")
	}
}

// TestCheckUserSession_FGAError_Propagates — an infrastructure error surfaces
// (false, err), never a silent allow.
func TestCheckUserSession_FGAError_Propagates(t *testing.T) {
	t.Parallel()
	stub := &userTupleStub{present: true, err: errors.New("dial tcp: connection refused")}
	checker := NewChecker(stub, makeMinimalReg(t))
	ok, err := checker.CheckUserSession(context.Background(), "u-1", time.Now().UTC())
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if ok {
		t.Fatal("must not allow on infrastructure error (fail-closed)")
	}
}
