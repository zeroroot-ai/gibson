// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

func forkCtx(jti, sandbox string) context.Context {
	ctx := withTaskGrantClaims(context.Background(), sdkcg.Claims{JTI: jti})
	if sandbox != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(sandboxIDHeader, sandbox))
	}
	return ctx
}

// The grant of a forked source works only in the source sandbox, and in a
// fork only for ClaimFork (D74).
func TestCheckForkGrant(t *testing.T) {
	l, _ := newForkLedger(t)
	ctx := context.Background()
	if err := l.RecordForks(ctx, "jti-src", "ns/src-1/u0", []ForkDispatch{{SandboxID: "ns/fork-1/u1"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	const method = "/gibson.harness.v1.HarnessCallbackService/CallToolProto"

	if err := checkForkGrant(forkCtx("jti-src", "src-1"), l, method, nil); err != nil {
		t.Errorf("source sandbox: %v", err)
	}
	if err := checkForkGrant(forkCtx("jti-other", "fork-1"), l, method, nil); err != nil {
		t.Errorf("grant with no fork: %v", err)
	}
	if err := checkForkGrant(forkCtx("jti-src", "fork-1"), l, claimForkMethod, nil); err != nil {
		t.Errorf("ClaimFork from a fork: %v", err)
	}
	if err := checkForkGrant(context.Background(), l, method, nil); err != nil {
		t.Errorf("no task grant: %v", err)
	}
	if err := checkForkGrant(forkCtx("jti-src", "fork-1"), nil, method, nil); err != nil {
		t.Errorf("no ledger: %v", err)
	}
	for _, sandbox := range []string{"fork-1", ""} {
		err := checkForkGrant(forkCtx("jti-src", sandbox), l, method, nil)
		st, _ := status.FromError(err)
		if st.Code() != codes.FailedPrecondition {
			t.Fatalf("sandbox %q: code = %v, want FailedPrecondition", sandbox, st.Code())
		}
		var info *errdetails.ErrorInfo
		for _, d := range st.Details() {
			if i, ok := d.(*errdetails.ErrorInfo); ok {
				info = i
			}
		}
		if info == nil || info.GetReason() != reasonForkUnclaimed || info.GetDomain() != forkErrorDomain {
			t.Fatalf("sandbox %q: details = %v", sandbox, st.Details())
		}
	}
}

// A ledger that cannot be read refuses the call.
func TestCheckForkGrant_LedgerDown(t *testing.T) {
	l, mr := newForkLedger(t)
	mr.Close()
	err := checkForkGrant(forkCtx("jti-src", "x"), l, "/m", nil)
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
