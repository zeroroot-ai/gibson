// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

func newTestRedisForkLedger(t *testing.T) (*redisForkLedger, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return newRedisForkLedger(client), mr
}

// A fork claims its dispatch once, by its hostname. A sandbox that the
// daemon did not start gets ErrNotAFork.
func TestRedisForkLedger_ClaimOnce(t *testing.T) {
	l, _ := newTestRedisForkLedger(t)
	ctx := context.Background()
	if _, forked, err := l.ForkedSource(ctx, "jti-1"); err != nil || forked {
		t.Fatalf("before a fork: forked = %v, err = %v", forked, err)
	}
	err := l.RecordForks(ctx, "jti-1", "ns/src/u0", []harness.ForkDispatch{{SandboxID: "ns/f1/u1", Tenant: "acme", NodeID: "n2"}}, time.Hour)
	if err != nil {
		t.Fatalf("RecordForks: %v", err)
	}
	src, forked, err := l.ForkedSource(ctx, "jti-1")
	if err != nil || !forked || src != "ns/src/u0" {
		t.Fatalf("ForkedSource = %q %v %v", src, forked, err)
	}
	if target, err := l.ClaimTarget(ctx, "f1"); err != nil || target.SandboxID != "ns/f1/u1" || target.Tenant != "acme" {
		t.Fatalf("ClaimTarget = %+v, %v", target, err)
	}
	if _, err := l.Claim(ctx, ""); !errors.Is(err, harness.ErrNotAFork) {
		t.Fatalf("empty fork id: err = %v, want harness.ErrNotAFork", err)
	}
	d, err := l.Claim(ctx, "f1")
	if err != nil || d.NodeID != "n2" {
		t.Fatalf("Claim = %+v, %v", d, err)
	}
	if _, err := l.Claim(ctx, "f1"); !errors.Is(err, harness.ErrForkClaimed) {
		t.Fatalf("second claim: err = %v, want harness.ErrForkClaimed", err)
	}
	if _, err := l.Claim(ctx, "f9"); !errors.Is(err, harness.ErrNotAFork) {
		t.Fatalf("unknown fork: err = %v, want harness.ErrNotAFork", err)
	}
	if _, err := l.ClaimTarget(ctx, "f9"); !errors.Is(err, harness.ErrNotAFork) {
		t.Fatalf("unknown target: err = %v, want harness.ErrNotAFork", err)
	}
	if err := l.RecordForks(ctx, "", "src", nil, time.Hour); err == nil {
		t.Fatal("a record with no grant id must fail")
	}
	if err := l.RecordStart(ctx, harness.ForkDispatch{SandboxID: "ns/x/u"}, time.Hour); err == nil {
		t.Fatal("a start with no tenant must fail")
	}
}

// Redis errors return as errors, never as "no fork".
func TestRedisForkLedger_RedisDown(t *testing.T) {
	l, mr := newTestRedisForkLedger(t)
	mr.Close()
	ctx := context.Background()
	if _, _, err := l.ForkedSource(ctx, "j"); err == nil {
		t.Error("ForkedSource: want an error")
	}
	if _, err := l.Claim(ctx, "f"); err == nil {
		t.Error("Claim: want an error")
	}
	if _, err := l.ClaimTarget(ctx, "f"); err == nil {
		t.Error("ClaimTarget: want an error")
	}
	if err := l.RecordForks(ctx, "j", "s", nil, time.Hour); err == nil {
		t.Error("RecordForks: want an error")
	}
}

// A begun fork counts as forked before its forks are recorded.
func TestRedisForkLedger_PendingFork(t *testing.T) {
	l, _ := newTestRedisForkLedger(t)
	ctx := context.Background()
	if err := l.BeginFork(ctx, "jti-p", "ns/src/u0", time.Hour); err != nil {
		t.Fatalf("BeginFork: %v", err)
	}
	if _, forked, _ := l.ForkedSource(ctx, "jti-p"); !forked {
		t.Fatal("a begun fork must count as forked")
	}
	if err := l.BeginFork(ctx, "", "s", time.Hour); err == nil {
		t.Fatal("BeginFork with no grant id must fail")
	}
}

// A seat records the fork as pending for the grant of its source. The fork
// waits until RecordForks records its dispatch, and a seat is taken once.
func TestRedisForkLedger_ForkSeat(t *testing.T) {
	l, _ := newTestRedisForkLedger(t)
	ctx := context.Background()
	seat := harness.ForkSeat{
		MissionID: "child-1", NodeID: "exploit", Tenant: "acme", AgentName: "zerocool",
		SandboxID: "ns/fork-1/u1", SourceSandboxID: "ns/src-1/u0", SourceJTI: "jti-c",
	}
	if err := l.ReserveForkSeat(ctx, seat, time.Hour); err != nil {
		t.Fatalf("ReserveForkSeat: %v", err)
	}
	if src, forked, _ := l.ForkedSource(ctx, "jti-c"); !forked || src != "ns/src-1/u0" {
		t.Fatalf("the grant of the caller must count as forked: %q %v", src, forked)
	}
	if _, err := l.Claim(ctx, "ns/fork-1/u1"); !errors.Is(err, harness.ErrForkPending) {
		t.Fatalf("claim before the dispatch: err = %v, want harness.ErrForkPending", err)
	}
	if _, err := l.Claim(ctx, "ns/fork-9/u9"); !errors.Is(err, harness.ErrNotAFork) {
		t.Fatalf("claim of another sandbox: err = %v, want harness.ErrNotAFork", err)
	}
	got, ok, err := l.TakeForkSeat(ctx, "child-1", "exploit")
	if err != nil || !ok || got != seat {
		t.Fatalf("TakeForkSeat = %+v, %v, %v", got, ok, err)
	}
	if _, ok, _ := l.TakeForkSeat(ctx, "child-1", "exploit"); ok {
		t.Fatal("a seat must be taken once")
	}
	if err := l.RecordForks(ctx, "jti-c", seat.SourceSandboxID, []harness.ForkDispatch{{SandboxID: seat.SandboxID, Tenant: "acme", NodeID: "exploit"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if d, err := l.Claim(ctx, "ns/fork-1/u1"); err != nil || d.NodeID != "exploit" {
		t.Fatalf("claim after the dispatch = %+v, %v", d, err)
	}
	if err := l.ReserveForkSeat(ctx, harness.ForkSeat{MissionID: "m"}, time.Hour); err == nil {
		t.Fatal("an incomplete seat must be refused")
	}
}
