// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"github.com/zeroroot-ai/sdk/fork"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func newForkLedger(t *testing.T) (*RedisForkLedger, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisForkLedger(client), mr
}

// A fork claims its dispatch once. A sandbox that is not a fork of the
// grant gets ErrNotAFork.
func TestRedisForkLedger_ClaimOnce(t *testing.T) {
	l, _ := newForkLedger(t)
	ctx := context.Background()
	if _, forked, err := l.ForkedSource(ctx, "jti-1"); err != nil || forked {
		t.Fatalf("before a fork: forked = %v, err = %v", forked, err)
	}
	if err := l.RecordForks(ctx, "jti-1", "ns/src/u0", []ForkDispatch{{SandboxID: "f1", NodeID: "n2", Grant: "g1"}}, time.Hour); err != nil {
		t.Fatalf("RecordForks: %v", err)
	}
	src, forked, err := l.ForkedSource(ctx, "jti-1")
	if err != nil || !forked || src != "ns/src/u0" {
		t.Fatalf("ForkedSource = %q %v %v", src, forked, err)
	}
	if _, err := l.Claim(ctx, "jti-1", ""); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("empty fork id: err = %v, want ErrNotAFork", err)
	}
	d, err := l.Claim(ctx, "jti-1", "f1")
	if err != nil || d.NodeID != "n2" || d.Grant != "g1" {
		t.Fatalf("Claim = %+v, %v", d, err)
	}
	if _, err := l.Claim(ctx, "jti-1", "f1"); !errors.Is(err, ErrForkClaimed) {
		t.Fatalf("second claim: err = %v, want ErrForkClaimed", err)
	}
	if _, err := l.Claim(ctx, "jti-1", "f9"); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("unknown fork: err = %v, want ErrNotAFork", err)
	}
	if err := l.RecordForks(ctx, "", "src", nil, time.Hour); err == nil {
		t.Fatal("a record with no grant id must fail")
	}
}

// Redis errors return as errors, never as "no fork".
func TestRedisForkLedger_RedisDown(t *testing.T) {
	l, mr := newForkLedger(t)
	mr.Close()
	ctx := context.Background()
	if _, _, err := l.ForkedSource(ctx, "j"); err == nil {
		t.Error("ForkedSource: want an error")
	}
	if _, err := l.Claim(ctx, "j", "f"); err == nil {
		t.Error("Claim: want an error")
	}
	if err := l.RecordForks(ctx, "j", "s", nil, time.Hour); err == nil {
		t.Error("RecordForks: want an error")
	}
}

func TestSandboxHostname(t *testing.T) {
	cases := map[string]string{
		"setec-acme/Agent_Run.1/uid-9": "agent-run-1",
		"plain":                        "plain",
		"ns/___/uid":                   "setec-sandbox",
	}
	for in, want := range cases {
		if got := sandboxHostname(in); got != want {
			t.Errorf("sandboxHostname(%q) = %q, want %q", in, got, want)
		}
	}
	long := "ns/a123456789a123456789a123456789a123456789a123456789a123456789a123456789/u"
	if got := sandboxHostname(long); len(got) != 63 {
		t.Errorf("long name: len = %d, want 63", len(got))
	}
}

// fakeIdentity verifies a token by a fixed table of token to sandbox id, as
// setec does with the key of each sandbox (setec#235). A token that is not in
// the table does not verify.
type fakeIdentity struct {
	ids     map[string]string
	err     error
	tenants []string
}

func (f *fakeIdentity) VerifySandboxIdentity(_ context.Context, tenant, token, audience string) (string, error) {
	f.tenants = append(f.tenants, tenant)
	if f.err != nil {
		return "", f.err
	}
	if audience != fork.SandboxIdentityAudience {
		return "", ErrSandboxIdentityRefused
	}
	id, ok := f.ids[token]
	if !ok {
		return "", ErrSandboxIdentityRefused
	}
	return id, nil
}

// The identity tokens of the tests. Each names one sandbox.
func testIdentity() *fakeIdentity {
	return &fakeIdentity{ids: map[string]string{
		"tok-src":    "ns/src-1/u0",
		"tok-fork-1": "ns/fork-1/u1",
		"tok-fork-2": "ns/fork-2/u2",
	}}
}

// forkCtx is a call with the grant jti, the identity token and the header
// x-gibson-sandbox-id. An empty value sends no such metadata.
func forkCtx(jti, token, header string) context.Context {
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		panic(err)
	}
	ctx := withTaskGrantClaims(context.Background(), sdkcg.Claims{JTI: jti, Tenant: tenant})
	var kv []string
	if token != "" {
		kv = append(kv, fork.MetadataSandboxIdentity, token)
	}
	if header != "" {
		kv = append(kv, sandboxIDHeader, header)
	}
	if len(kv) > 0 {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(kv...))
	}
	return ctx
}

func requireForkUnclaimed(t *testing.T, name string, err error) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("%s: code = %v, want FailedPrecondition", name, st.Code())
	}
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
		}
	}
	if info == nil || info.GetReason() != reasonForkUnclaimed || info.GetDomain() != forkErrorDomain {
		t.Fatalf("%s: details = %v", name, st.Details())
	}
}

// The grant of a forked source works only in the source sandbox, as setec
// verifies it, and in a fork only for ClaimFork (D74, setec#235).
func TestCheckForkGrant(t *testing.T) {
	l, _ := newForkLedger(t)
	ctx := context.Background()
	if err := l.RecordForks(ctx, "jti-src", "ns/src-1/u0", []ForkDispatch{{SandboxID: "ns/fork-1/u1"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	guard := &forkGuard{ledger: l, identity: id}
	const method = "/gibson.harness.v1.HarnessCallbackService/CallToolProto"

	// The parent in its own sandbox is accepted, with or without the header.
	if err := checkForkGrant(forkCtx("jti-src", "tok-src", "src-1"), guard, method, nil); err != nil {
		t.Errorf("source sandbox: %v", err)
	}
	if err := checkForkGrant(forkCtx("jti-src", "tok-src", ""), guard, method, nil); err != nil {
		t.Errorf("source sandbox, no header: %v", err)
	}
	if len(id.tenants) == 0 || id.tenants[0] != "acme" {
		t.Errorf("verify tenant = %v, want the tenant of the grant", id.tenants)
	}
	if err := checkForkGrant(forkCtx("jti-other", "", "fork-1"), guard, method, nil); err != nil {
		t.Errorf("grant with no fork: %v", err)
	}
	if err := checkForkGrant(forkCtx("jti-src", "tok-fork-1", "fork-1"), guard, claimForkMethod, nil); err != nil {
		t.Errorf("ClaimFork from a fork: %v", err)
	}
	if err := checkForkGrant(context.Background(), guard, method, nil); err != nil {
		t.Errorf("no task grant: %v", err)
	}

	// A fork with its own token is not the source.
	requireForkUnclaimed(t, "fork token", checkForkGrant(forkCtx("jti-src", "tok-fork-1", "fork-1"), guard, method, nil))

	refusals := []struct {
		name  string
		ctx   context.Context
		guard *forkGuard
		code  codes.Code
	}{
		// The gap of sdk#248: a fork that sends the id of its parent in the
		// header. Its token names the fork, so the header disagrees.
		{"fork sends the parent id", forkCtx("jti-src", "tok-fork-1", "src-1"), guard, codes.PermissionDenied},
		{"fork sends the full parent id", forkCtx("jti-src", "tok-fork-1", "ns/src-1/u0"), guard, codes.PermissionDenied},
		// A header with no token proves nothing.
		{"parent id with no token", forkCtx("jti-src", "", "src-1"), guard, codes.Unauthenticated},
		{"no token", forkCtx("jti-src", "", ""), guard, codes.Unauthenticated},
		// A token that does not verify, for example a token of the source
		// that a fork found in its copy of the memory.
		{"token that does not verify", forkCtx("jti-src", "tok-stale", "src-1"), guard, codes.Unauthenticated},
		// The parent token with a header that names a fork.
		{"parent token, fork header", forkCtx("jti-src", "tok-src", "fork-1"), guard, codes.PermissionDenied},
		{"no verifier", forkCtx("jti-src", "tok-src", "src-1"), &forkGuard{ledger: l}, codes.FailedPrecondition},
		{"setec down", forkCtx("jti-src", "tok-src", "src-1"), &forkGuard{ledger: l, identity: &fakeIdentity{err: errors.New("dial")}}, codes.Unavailable},
	}
	for _, r := range refusals {
		if got := status.Code(checkForkGrant(r.ctx, r.guard, method, nil)); got != r.code {
			t.Errorf("%s: code = %v, want %v", r.name, got, r.code)
		}
	}
}

// A ledger that cannot be read refuses the call.
func TestCheckForkGrant_LedgerDown(t *testing.T) {
	l, mr := newForkLedger(t)
	mr.Close()
	err := checkForkGrant(forkCtx("jti-src", "tok-src", ""), &forkGuard{ledger: l, identity: testIdentity()}, "/m", nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// A claim between BeginFork and RecordForks gets ErrForkPending, and the
// grant already counts as forked.
func TestRedisForkLedger_PendingFork(t *testing.T) {
	l, _ := newForkLedger(t)
	ctx := context.Background()
	if err := l.BeginFork(ctx, "jti-p", "ns/src/u0", time.Hour); err != nil {
		t.Fatalf("BeginFork: %v", err)
	}
	if _, forked, _ := l.ForkedSource(ctx, "jti-p"); !forked {
		t.Fatal("a begun fork must count as forked")
	}
	if _, err := l.Claim(ctx, "jti-p", "f1"); !errors.Is(err, ErrForkPending) {
		t.Fatalf("claim before record: err = %v, want ErrForkPending", err)
	}
	if err := l.RecordForks(ctx, "jti-p", "ns/src/u0", []ForkDispatch{{SandboxID: "f1"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Claim(ctx, "jti-p", "f2"); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("after record: err = %v, want ErrNotAFork", err)
	}
	if err := l.BeginFork(ctx, "", "s", time.Hour); err == nil {
		t.Fatal("BeginFork with no grant id must fail")
	}
}

// testForkGuard is a fork guard over an empty ledger: no grant is forked.
func testForkGuard(t *testing.T) *forkGuard {
	t.Helper()
	l, _ := newForkLedger(t)
	return &forkGuard{ledger: l}
}
