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

// capturingFGA is a minimal FGAClient stub that records the last
// ClientCheckRequest passed to Body for inspection in tests.
type capturingFGA struct {
	// allowed is the decision to return from Execute.
	allowed bool
	// err is optionally returned instead of a response.
	err error
	// lastBody is atomically written by Body so the test goroutine can
	// read it after Execute.
	lastBody atomic.Pointer[fgaclient.ClientCheckRequest]
	// calls counts Execute invocations.
	calls int32
}

func (m *capturingFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &capturingReq{m: m}
}

type capturingReq struct {
	m    *capturingFGA
	body fgaclient.ClientCheckRequest
}

func (r *capturingReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *capturingReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *capturingReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	atomic.AddInt32(&r.m.calls, 1)
	b := r.body
	r.m.lastBody.Store(&b)
	if r.m.err != nil {
		return nil, r.m.err
	}
	allowed := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *capturingReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *capturingReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *capturingReq) GetContext() context.Context               { return context.Background() }
func (r *capturingReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *capturingReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// makeMinimalReg returns a Registry with a single rule-mode member entry.
// Reused across session-gate tests that need a valid Registry.
func makeMinimalReg(t *testing.T) *Registry {
	t.Helper()
	const yaml = `entries:
  "/test.v1.S/Member":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
`
	r, err := LoadRegistry([]byte(yaml))
	if err != nil {
		t.Fatalf("makeMinimalReg: %v", err)
	}
	return r
}

// TestCheckActiveSession_Allow — token iat after revoked_at → ALLOWED.
// The FGA stub returns allowed=true, simulating a condition-evaluated allow.
func TestCheckActiveSession_Allow(t *testing.T) {
	t.Parallel()
	stub := &capturingFGA{allowed: true}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_100, 0).UTC()
	ok, err := checker.CheckActiveSession(context.Background(), "u-1", "acme", iat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow when FGA returns true, got deny")
	}
}

// TestCheckActiveSession_Deny_Revoked — token iat before revoked_at → DENIED.
// The FGA stub returns allowed=false, simulating a condition-evaluated deny.
func TestCheckActiveSession_Deny_Revoked(t *testing.T) {
	t.Parallel()
	stub := &capturingFGA{allowed: false}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_000, 0).UTC() // older than revoked_at
	ok, err := checker.CheckActiveSession(context.Background(), "u-1", "acme", iat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny when FGA returns false (revoked), got allow")
	}
}

// TestCheckActiveSession_Deny_Absent — no active_session tuple → DENIED (fail-closed).
// OpenFGA returns allowed=false for a missing tuple; FGA stub simulates this.
func TestCheckActiveSession_Deny_Absent(t *testing.T) {
	t.Parallel()
	// FGA denies when the tuple is absent — same as revoked from the protocol perspective.
	stub := &capturingFGA{allowed: false}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_200, 0).UTC()
	ok, err := checker.CheckActiveSession(context.Background(), "u-new", "acme", iat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny on absent tuple (fail-closed), got allow")
	}
}

// TestCheckActiveSession_ConditionContextPassedCorrectly — verifies that the
// RFC3339 UTC token_issued_at value is passed in the FGA condition context.
func TestCheckActiveSession_ConditionContextPassedCorrectly(t *testing.T) {
	t.Parallel()
	stub := &capturingFGA{allowed: true}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_100, 0).UTC()
	wantIAT := iat.Format(time.RFC3339) // "2023-11-14T22:08:20Z"

	_, _ = checker.CheckActiveSession(context.Background(), "u-1", "acme", iat)

	body := stub.lastBody.Load()
	if body == nil {
		t.Fatal("no FGA Check call recorded")
	}
	if body.Context == nil {
		t.Fatal("ClientCheckRequest.Context is nil; expected condition context to be set")
	}
	gotIAT, ok := (*body.Context)["token_issued_at"]
	if !ok {
		t.Fatalf("condition context missing token_issued_at key; got keys: %v", keysOf(*body.Context))
	}
	if gotIAT != wantIAT {
		t.Errorf("token_issued_at = %q, want %q", gotIAT, wantIAT)
	}
	// Verify user and object format.
	if body.User != "user:u-1" {
		t.Errorf("FGA user = %q, want %q", body.User, "user:u-1")
	}
	if body.Object != "tenant:acme" {
		t.Errorf("FGA object = %q, want %q", body.Object, "tenant:acme")
	}
	if body.Relation != "active_session" {
		t.Errorf("FGA relation = %q, want %q", body.Relation, "active_session")
	}
}

// TestCheckActiveSession_MachinePrincipal_GateSkipped — machine principals
// (agent_principal, tool_principal, plugin_principal) are not passed to
// CheckActiveSession by the ext-authz handler at all; but additionally,
// CheckActiveSession itself is never called for them. This test verifies the
// method works correctly on a non-user-prefixed subject (paranoia check —
// the real skip is enforced in envoy_extauthz.go checkSessionGate which
// only calls CheckActiveSession for oidc-user credential type).
//
// A machine subject passed to CheckActiveSession directly still gets the
// "user:" prefix stripped/added, but the FGA model returns deny because no
// active_session tuple exists for machine principals.
// NOTE: the handler-level skip is what PREVENTS this call for machine principals.
// This test documents that fact and checks the underlying check for a machine
// principal returns deny (FGA stub returns false).
//
//nolint:dupl // parallel tests with similar setup; duplication is intentional
func TestCheckActiveSession_MachinePrincipal_DeniedAtFGALayer(t *testing.T) {
	t.Parallel()
	// FGA returns false for a machine subject — no active_session tuple for them.
	stub := &capturingFGA{allowed: false}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_100, 0).UTC()
	ok, err := checker.CheckActiveSession(context.Background(), "agent_principal:acct-1", "acme", iat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for machine principal at FGA layer, got allow")
	}
}

// TestCachedChecker_CheckActiveSession_DelegatesWithoutCaching — CachedChecker
// delegates to the inner Checker and does NOT cache the result (each call
// reaches FGA to respect the per-token iat context).
func TestCachedChecker_CheckActiveSession_DelegatesWithoutCaching(t *testing.T) {
	t.Parallel()
	stub := &capturingFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeMinimalReg(t)), time.Hour, 100)

	iat := time.Unix(1_700_000_100, 0).UTC()
	for i := range 3 {
		ok, err := cc.CheckActiveSession(context.Background(), "u-1", "acme", iat)
		if err != nil || !ok {
			t.Fatalf("iteration %d: ok=%v err=%v", i, ok, err)
		}
	}
	// All 3 calls should have reached FGA — no caching.
	if got := atomic.LoadInt32(&stub.calls); got != 3 {
		t.Fatalf("expected 3 FGA calls (no caching), got %d", got)
	}
}

// TestCheckActiveSession_FGAError — FGA client returns a transport/RPC error.
// CheckActiveSession must surface it as a (false, non-nil error) so the caller
// (checkSessionGate in the server) can map it to Unavailable.
func TestCheckActiveSession_FGAError(t *testing.T) {
	t.Parallel()
	fgaErr := errors.New("dial tcp: connection refused")
	stub := &capturingFGA{err: fgaErr}
	checker := NewChecker(stub, makeMinimalReg(t))

	iat := time.Unix(1_700_000_100, 0).UTC()
	ok, err := checker.CheckActiveSession(context.Background(), "u-1", "acme", iat)
	if err == nil {
		t.Fatal("expected error when FGA client fails, got nil")
	}
	if ok {
		t.Fatal("expected deny (false) on FGA error, got allow")
	}
}

// nilAllowedFGA is an FGAClient stub that returns a response with Allowed=nil.
// OpenFGA may return Allowed=nil when the server cannot evaluate the condition
// (e.g. missing condition context keys). CheckActiveSession must treat this as
// a deny (fail-closed).
type nilAllowedFGA struct{}

func (m *nilAllowedFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &nilAllowedReq{}
}

type nilAllowedReq struct {
	body fgaclient.ClientCheckRequest
}

func (r *nilAllowedReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}
func (r *nilAllowedReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *nilAllowedReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	// Return a response with Allowed == nil (not set by the server).
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{}}, nil
}
func (r *nilAllowedReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *nilAllowedReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *nilAllowedReq) GetContext() context.Context               { return context.Background() }
func (r *nilAllowedReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *nilAllowedReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// TestCheckActiveSession_NilAllowed — FGA returns a response with Allowed=nil.
// CheckActiveSession must treat this as a deny (fail-closed) and increment the
// session gate denied counter.
func TestCheckActiveSession_NilAllowed(t *testing.T) {
	t.Parallel()
	checker := NewChecker(&nilAllowedFGA{}, makeMinimalReg(t))

	iat := time.Unix(1_700_000_100, 0).UTC()
	ok, err := checker.CheckActiveSession(context.Background(), "u-1", "acme", iat)
	if err != nil {
		t.Fatalf("unexpected error on nil-allowed response: %v", err)
	}
	if ok {
		t.Fatal("expected deny on nil Allowed field (fail-closed), got allow")
	}
}

// TestCheckActiveSession_EmptyInputs — empty subject or tenant returns an error
// immediately without calling FGA. This guard prevents a malformed FGA object
// string from being constructed.
func TestCheckActiveSession_EmptyInputs(t *testing.T) {
	t.Parallel()
	stub := &capturingFGA{allowed: true}
	checker := NewChecker(stub, makeMinimalReg(t))
	iat := time.Unix(1_700_000_100, 0).UTC()

	if _, err := checker.CheckActiveSession(context.Background(), "", "acme", iat); err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
	if _, err := checker.CheckActiveSession(context.Background(), "u-1", "", iat); err == nil {
		t.Fatal("expected error for empty tenant, got nil")
	}
	// FGA should not have been called.
	if got := atomic.LoadInt32(&stub.calls); got != 0 {
		t.Fatalf("expected 0 FGA calls on empty input, got %d", got)
	}
}

// keysOf returns the key slice of a map[string]interface{} for error messages.
func keysOf(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
