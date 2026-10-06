// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
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
	return l.BeginFork(ctx, jti, source, ttl)
}

func (z *lazyForkLedger) RecordForks(ctx context.Context, jti, source string, forks []harness.ForkDispatch, ttl time.Duration) error {
	l := z.ledger()
	if l == nil {
		return errNoForkStore
	}
	return l.RecordForks(ctx, jti, source, forks, ttl)
}

func (z *lazyForkLedger) ForkedSource(ctx context.Context, jti string) (string, bool, error) {
	l := z.ledger()
	if l == nil {
		return "", false, nil
	}
	return l.ForkedSource(ctx, jti)
}

func (z *lazyForkLedger) Claim(ctx context.Context, jti, fork string) (harness.ForkDispatch, error) {
	l := z.ledger()
	if l == nil {
		return harness.ForkDispatch{}, errNoForkStore
	}
	return l.Claim(ctx, jti, fork)
}
