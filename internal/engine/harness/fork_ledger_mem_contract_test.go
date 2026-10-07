// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The memory ledger keeps the contract of the Redis ledger of the daemon: a
// fork claims its dispatch once by its hostname, a sandbox the daemon did
// not start gets ErrNotAFork, and a begun fork is forked before its forks
// are recorded.
func TestMemForkLedger_ClaimOnce(t *testing.T) {
	l := newForkLedger(t)
	ctx := context.Background()
	if _, forked, err := l.ForkedSource(ctx, "jti-1"); err != nil || forked {
		t.Fatalf("before a fork: forked = %v, err = %v", forked, err)
	}
	if err := l.BeginFork(ctx, "jti-1", "ns/src/u0", time.Hour); err != nil {
		t.Fatalf("BeginFork: %v", err)
	}
	if _, forked, _ := l.ForkedSource(ctx, "jti-1"); !forked {
		t.Fatal("a begun fork must count as forked")
	}
	err := l.RecordForks(ctx, "jti-1", "ns/src/u0", []ForkDispatch{{SandboxID: "ns/f1/u1", Tenant: "acme", NodeID: "n2"}}, time.Hour)
	if err != nil {
		t.Fatalf("RecordForks: %v", err)
	}
	if src, forked, err := l.ForkedSource(ctx, "jti-1"); err != nil || !forked || src != "ns/src/u0" {
		t.Fatalf("ForkedSource = %q %v %v", src, forked, err)
	}
	if target, err := l.ClaimTarget(ctx, "f1"); err != nil || target.SandboxID != "ns/f1/u1" || target.Tenant != "acme" {
		t.Fatalf("ClaimTarget = %+v, %v", target, err)
	}
	if _, err := l.Claim(ctx, ""); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("empty fork id: err = %v, want ErrNotAFork", err)
	}
	if d, err := l.Claim(ctx, "f1"); err != nil || d.NodeID != "n2" {
		t.Fatalf("Claim = %+v, %v", d, err)
	}
	if _, err := l.Claim(ctx, "f1"); !errors.Is(err, ErrForkClaimed) {
		t.Fatalf("second claim: err = %v, want ErrForkClaimed", err)
	}
	if _, err := l.Claim(ctx, "f9"); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("unknown fork: err = %v, want ErrNotAFork", err)
	}
	if _, err := l.ClaimTarget(ctx, "f9"); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("unknown target: err = %v, want ErrNotAFork", err)
	}
	if err := l.RecordForks(ctx, "", "src", nil, time.Hour); err == nil {
		t.Fatal("a record with no grant id must fail")
	}
	if err := l.RecordStart(ctx, ForkDispatch{SandboxID: "ns/x/u"}, time.Hour); err == nil {
		t.Fatal("a start with no tenant must fail")
	}
}

// A seat records the fork as pending for the grant of its source. The fork
// waits until RecordForks records its dispatch, and a seat is taken once.
func TestMemForkLedger_ForkSeat(t *testing.T) {
	l := newForkLedger(t)
	ctx := context.Background()
	seat := ForkSeat{
		MissionID: "child-1", NodeID: "exploit", Tenant: "acme", AgentName: "zerocool",
		SandboxID: "ns/fork-1/u1", SourceSandboxID: "ns/src-1/u0", SourceJTI: "jti-c",
	}
	if err := l.ReserveForkSeat(ctx, seat, time.Hour); err != nil {
		t.Fatalf("ReserveForkSeat: %v", err)
	}
	if src, forked, _ := l.ForkedSource(ctx, "jti-c"); !forked || src != "ns/src-1/u0" {
		t.Fatalf("the grant of the caller must count as forked: %q %v", src, forked)
	}
	if _, err := l.Claim(ctx, "ns/fork-1/u1"); !errors.Is(err, ErrForkPending) {
		t.Fatalf("claim before the dispatch: err = %v, want ErrForkPending", err)
	}
	got, ok, err := l.TakeForkSeat(ctx, "child-1", "exploit")
	if err != nil || !ok || got != seat {
		t.Fatalf("TakeForkSeat = %+v, %v, %v", got, ok, err)
	}
	if _, ok, _ := l.TakeForkSeat(ctx, "child-1", "exploit"); ok {
		t.Fatal("a seat must be taken once")
	}
	if err := l.RecordForks(ctx, "jti-c", seat.SourceSandboxID, []ForkDispatch{{SandboxID: seat.SandboxID, Tenant: "acme", NodeID: "exploit"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if d, err := l.Claim(ctx, "ns/fork-1/u1"); err != nil || d.NodeID != "exploit" {
		t.Fatalf("claim after the dispatch = %+v, %v", d, err)
	}
	if err := l.ReserveForkSeat(ctx, ForkSeat{MissionID: "m"}, time.Hour); err == nil {
		t.Fatal("an incomplete seat must be refused")
	}
}

// A record lives for its ttl and no longer. A closed ledger fails each call.
func TestMemForkLedger_ExpiryAndClose(t *testing.T) {
	l := newForkLedger(t)
	ctx := context.Background()
	d := ForkDispatch{SandboxID: "ns/fork-1/u1", Tenant: "acme", NodeID: "n2"}
	if err := l.RecordStart(ctx, d, time.Hour); err != nil {
		t.Fatal(err)
	}
	l.FastForward(time.Hour - time.Second)
	if _, err := l.ClaimTarget(ctx, "fork-1"); err != nil {
		t.Fatalf("before the ttl: %v", err)
	}
	l.FastForward(2 * time.Second)
	if _, err := l.Claim(ctx, "fork-1"); !errors.Is(err, ErrNotAFork) {
		t.Fatalf("after the ttl: err = %v, want ErrNotAFork", err)
	}
	l.Close()
	if _, _, err := l.ForkedSource(ctx, "j"); !errors.Is(err, errForkLedgerDown) {
		t.Errorf("ForkedSource: err = %v", err)
	}
	if _, err := l.Claim(ctx, "f"); !errors.Is(err, errForkLedgerDown) {
		t.Errorf("Claim: err = %v", err)
	}
	if err := l.RecordForks(ctx, "j", "s", nil, time.Hour); !errors.Is(err, errForkLedgerDown) {
		t.Errorf("RecordForks: err = %v", err)
	}
}
