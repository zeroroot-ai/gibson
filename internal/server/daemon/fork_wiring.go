// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// errNoForkStore refuses a fork on a daemon with no Redis state client.
var errNoForkStore = errors.New("daemon: no state store for the fork ledger")

// lazyForkLedger is the fork ledger of the daemon (ADR-0169, D74). The state
// client exists only after Start, and the callback options are assembled
// before it, so the Redis ledger is built on first use. With no state client
// no fork can begin, so no grant counts as forked.
type lazyForkLedger struct {
	daemon *daemonImpl
	mu     sync.Mutex
	l      *harness.RedisForkLedger
}

func (z *lazyForkLedger) ledger() *harness.RedisForkLedger {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.l == nil && z.daemon.stateClient != nil {
		z.l = harness.NewRedisForkLedger(z.daemon.stateClient.Client())
	}
	return z.l
}

func (z *lazyForkLedger) BeginFork(ctx context.Context, jti, source string, ttl time.Duration) error {
	l := z.ledger()
	if l == nil {
		return errNoForkStore
	}
	if err := l.BeginFork(ctx, jti, source, ttl); err != nil {
		return fmt.Errorf("fork ledger: %w", err)
	}
	return nil
}

func (z *lazyForkLedger) RecordForks(ctx context.Context, jti, source string, forks []harness.ForkDispatch, ttl time.Duration) error {
	l := z.ledger()
	if l == nil {
		return errNoForkStore
	}
	if err := l.RecordForks(ctx, jti, source, forks, ttl); err != nil {
		return fmt.Errorf("fork ledger: %w", err)
	}
	return nil
}

func (z *lazyForkLedger) ForkedSource(ctx context.Context, jti string) (source string, forked bool, err error) {
	l := z.ledger()
	if l == nil {
		return "", false, nil
	}
	source, forked, err = l.ForkedSource(ctx, jti)
	if err != nil {
		return "", false, fmt.Errorf("fork ledger: %w", err)
	}
	return source, forked, nil
}

func (z *lazyForkLedger) Claim(ctx context.Context, jti, fork string) (harness.ForkDispatch, error) {
	l := z.ledger()
	if l == nil {
		return harness.ForkDispatch{}, errNoForkStore
	}
	d, err := l.Claim(ctx, jti, fork)
	if err != nil {
		return harness.ForkDispatch{}, fmt.Errorf("fork ledger: %w", err)
	}
	return d, nil
}

func (z *lazyForkLedger) ReserveForkSeat(ctx context.Context, seat harness.ForkSeat, ttl time.Duration) error {
	l := z.ledger()
	if l == nil {
		return errNoForkStore
	}
	if err := l.ReserveForkSeat(ctx, seat, ttl); err != nil {
		return fmt.Errorf("fork ledger: %w", err)
	}
	return nil
}

func (z *lazyForkLedger) TakeForkSeat(ctx context.Context, missionID, nodeID string) (harness.ForkSeat, bool, error) {
	l := z.ledger()
	if l == nil {
		return harness.ForkSeat{}, false, nil
	}
	seat, ok, err := l.TakeForkSeat(ctx, missionID, nodeID)
	if err != nil {
		return harness.ForkSeat{}, false, fmt.Errorf("fork ledger: %w", err)
	}
	return seat, ok, nil
}

// The mission operator gives CreateMission the first node of a child that
// starts from the state of its caller (gibson#803).
var _ harness.ChildFirstNodeSource = (*missionHarnessAdapter)(nil)
