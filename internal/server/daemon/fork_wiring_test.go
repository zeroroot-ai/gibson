// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

// With no state client no fork can begin, and no grant counts as forked.
func TestLazyForkLedger_NoStateClient(t *testing.T) {
	z := &lazyForkLedger{daemon: &daemonImpl{}}
	ctx := context.Background()
	if err := z.BeginFork(ctx, "j", "s", time.Hour); !errors.Is(err, errNoForkStore) {
		t.Errorf("BeginFork: err = %v", err)
	}
	if err := z.RecordForks(ctx, "j", "s", nil, time.Hour); !errors.Is(err, errNoForkStore) {
		t.Errorf("RecordForks: err = %v", err)
	}
	if _, err := z.Claim(ctx, "j", "f"); !errors.Is(err, errNoForkStore) {
		t.Errorf("Claim: err = %v", err)
	}
	if _, forked, err := z.ForkedSource(ctx, "j"); forked || err != nil {
		t.Errorf("ForkedSource = %v, %v", forked, err)
	}
}

// With a state client the ledger works end to end.
func TestLazyForkLedger_UsesTheStateClient(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	z := &lazyForkLedger{daemon: &daemonImpl{stateClient: sc}}
	ctx := context.Background()
	if err := z.BeginFork(ctx, "j", "ns/src/u", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := z.RecordForks(ctx, "j", "ns/src/u", []harness.ForkDispatch{{SandboxID: "f", NodeID: "n"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if src, forked, err := z.ForkedSource(ctx, "j"); !forked || err != nil || src != "ns/src/u" {
		t.Fatalf("ForkedSource = %q %v %v", src, forked, err)
	}
	if d, err := z.Claim(ctx, "j", "f"); err != nil || d.NodeID != "n" {
		t.Fatalf("Claim = %+v %v", d, err)
	}
}
