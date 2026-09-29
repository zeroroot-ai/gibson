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

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// mockFGA implements the FGAClient interface and counts Check calls.
type mockFGA struct {
	allowed bool
	err     error
	calls   int32
}

func (m *mockFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	atomic.AddInt32(&m.calls, 1)
	return &mockReq{m: m}
}

type mockReq struct{ m *mockFGA }

func (r *mockReq) Body(_ fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *mockReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *mockReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	if r.m.err != nil {
		return nil, r.m.err
	}
	allowed := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}
func (r *mockReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *mockReq) GetStoreIdOverride() *string               { return nil }
func (r *mockReq) GetContext() context.Context               { return context.Background() }
func (r *mockReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *mockReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

func makeReg(t *testing.T) *Registry {
	t.Helper()
	r, err := LoadRegistry([]byte(testYAML))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCachedChecker_HitsOnSecondCall(t *testing.T) {
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), time.Minute, 100)
	id := headers.Identity{Subject: "u-1", Tenant: "acme", CredentialType: "oidc-user"}
	if a, err := cc.Check(context.Background(), "/test.v1.S/Member", id, nil); err != nil || !a {
		t.Fatalf("call 1: a=%v err=%v", a, err)
	}
	if a, err := cc.Check(context.Background(), "/test.v1.S/Member", id, nil); err != nil || !a {
		t.Fatalf("call 2: a=%v err=%v", a, err)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("expected 1 inner call, got %d", got)
	}
}

func TestCachedChecker_TTLExpiry(t *testing.T) {
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), 10*time.Millisecond, 100)
	id := headers.Identity{Subject: "u-1", Tenant: "acme", CredentialType: "oidc-user"}
	_, _ = cc.Check(context.Background(), "/test.v1.S/Member", id, nil)
	time.Sleep(20 * time.Millisecond)
	_, _ = cc.Check(context.Background(), "/test.v1.S/Member", id, nil)
	if got := atomic.LoadInt32(&stub.calls); got != 2 {
		t.Fatalf("expected 2 inner calls, got %d", got)
	}
}

func TestCachedChecker_DistinctTenantsDoNotShare(t *testing.T) {
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), time.Minute, 100)
	_, _ = cc.Check(context.Background(), "/test.v1.S/Member", headers.Identity{Subject: "u", Tenant: "acme", CredentialType: "oidc-user"}, nil)
	_, _ = cc.Check(context.Background(), "/test.v1.S/Member", headers.Identity{Subject: "u", Tenant: "bigcorp", CredentialType: "oidc-user"}, nil)
	if got := atomic.LoadInt32(&stub.calls); got != 2 {
		t.Fatalf("expected 2 inner calls, got %d", got)
	}
}

func TestCachedChecker_DoesNotCacheErrors(t *testing.T) {
	stub := &mockFGA{err: errors.New("fga down")}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), time.Hour, 100)
	id := headers.Identity{Subject: "u", Tenant: "acme", CredentialType: "oidc-user"}
	_, err1 := cc.Check(context.Background(), "/test.v1.S/Member", id, nil)
	_, err2 := cc.Check(context.Background(), "/test.v1.S/Member", id, nil)
	if err1 == nil || err2 == nil {
		t.Fatal("expected errors")
	}
	if got := atomic.LoadInt32(&stub.calls); got != 2 {
		t.Fatalf("expected 2 inner calls, got %d", got)
	}
}

func TestCachedChecker_UnauthenticatedSkipsCacheAndFGA(t *testing.T) {
	stub := &mockFGA{allowed: false}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), time.Hour, 100)
	// CredentialType is irrelevant here — unauthenticated RPCs bypass the
	// bitfield check entirely.
	id := headers.Identity{Subject: "u", Tenant: "acme"}
	a, err := cc.Check(context.Background(), "/test.v1.S/Public", id, nil)
	if err != nil || !a {
		t.Fatalf("expected unauthenticated allow, got a=%v err=%v", a, err)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 0 {
		t.Fatalf("expected 0 inner calls, got %d", got)
	}
}

// TestCachedChecker_InvalidateSubjectClearsOnlyThatSubject: the write event
// for one user evicts that user's decisions and nobody else's.
func TestCachedChecker_InvalidateSubjectClearsOnlyThatSubject(t *testing.T) {
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeReg(t)), time.Hour, 100)
	ctx := context.Background()
	for _, subj := range []string{"100000000000000001", "100000000000000002"} {
		if _, err := cc.Check(ctx, "/test.v1.S/Member", headers.Identity{Subject: subj, Tenant: "acme", CredentialType: "oidc-user"}, nil); err != nil {
			t.Fatalf("seed %s: %v", subj, err)
		}
	}
	if cc.Len() != 2 {
		t.Fatalf("seeded %d entries, want 2", cc.Len())
	}
	if n := cc.InvalidateSubject("100000000000000001"); n != 1 {
		t.Fatalf("evicted %d, want 1", n)
	}
	if cc.Len() != 1 {
		t.Fatalf("%d entries left, want 1 (the other user untouched)", cc.Len())
	}
	// The evicted user's next check goes to FGA again; the other's is a hit.
	before := atomic.LoadInt32(&stub.calls)
	_, _ = cc.Check(ctx, "/test.v1.S/Member", headers.Identity{Subject: "100000000000000001", Tenant: "acme", CredentialType: "oidc-user"}, nil)
	_, _ = cc.Check(ctx, "/test.v1.S/Member", headers.Identity{Subject: "100000000000000002", Tenant: "acme", CredentialType: "oidc-user"}, nil)
	if got := atomic.LoadInt32(&stub.calls) - before; got != 1 {
		t.Fatalf("expected exactly one inner call after the eviction, got %d", got)
	}
}
