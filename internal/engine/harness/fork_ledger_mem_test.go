// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memForkLedger is the ForkLedger of the harness tests. It keeps the same
// records as the Redis ledger of the daemon, keyed the same way: one record
// for each source grant, one start record for each sandbox hostname, one
// seat for each node of a child mission. FastForward moves its clock, so a
// test can let a record expire. Close makes each later call fail, as a
// Redis that is down does.
type memForkLedger struct {
	mu     sync.Mutex
	now    time.Time
	err    error
	forks  map[string]memForkRecord
	starts map[string]memStartRecord
	seats  map[string]memSeat
}

type memForkRecord struct {
	source  string
	pending bool
	expires time.Time
}

type memStartRecord struct {
	sandboxID string
	tenant    string
	dispatch  *ForkDispatch
	pending   bool
	claimed   bool
	expires   time.Time
}

type memSeat struct {
	seat    ForkSeat
	expires time.Time
}

var errForkLedgerDown = errors.New("fork ledger: closed")

func newForkLedger(t *testing.T) *memForkLedger {
	t.Helper()
	return &memForkLedger{
		now:    time.Now(),
		forks:  map[string]memForkRecord{},
		starts: map[string]memStartRecord{},
		seats:  map[string]memSeat{},
	}
}

// FastForward moves the clock of the ledger forward by d.
func (l *memForkLedger) FastForward(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = l.now.Add(d)
}

// Close makes each later call of the ledger fail.
func (l *memForkLedger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = errForkLedgerDown
}

func (l *memForkLedger) fork(jti string) (memForkRecord, bool) {
	r, ok := l.forks[jti]
	if !ok || !r.expires.After(l.now) {
		return memForkRecord{}, false
	}
	return r, true
}

func (l *memForkLedger) start(hostname string) (memStartRecord, bool) {
	r, ok := l.starts[SandboxHostname(hostname)]
	if !ok || !r.expires.After(l.now) {
		return memStartRecord{}, false
	}
	return r, true
}

func (l *memForkLedger) BeginFork(_ context.Context, sourceJTI, sourceSandboxID string, ttl time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if sourceJTI == "" || sourceSandboxID == "" {
		return errors.New("fork ledger: a fork record needs the grant id and the source sandbox")
	}
	l.forks[sourceJTI] = memForkRecord{source: sourceSandboxID, pending: true, expires: l.now.Add(ttl)}
	return nil
}

func (l *memForkLedger) RecordForks(ctx context.Context, sourceJTI, sourceSandboxID string, forks []ForkDispatch, ttl time.Duration) error {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return l.err
	}
	if sourceJTI == "" || sourceSandboxID == "" {
		l.mu.Unlock()
		return errors.New("fork ledger: a fork record needs the grant id and the source sandbox")
	}
	l.forks[sourceJTI] = memForkRecord{source: sourceSandboxID, expires: l.now.Add(ttl)}
	l.mu.Unlock()
	for _, f := range forks {
		if err := l.RecordStart(ctx, f, ttl); err != nil {
			return err
		}
	}
	return nil
}

func (l *memForkLedger) RecordStart(_ context.Context, d ForkDispatch, ttl time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if d.SandboxID == "" || d.Tenant == "" {
		return errors.New("fork ledger: a start record needs the sandbox and the tenant")
	}
	key := SandboxHostname(d.SandboxID)
	r := l.starts[key]
	dispatch := d
	r.sandboxID, r.tenant, r.dispatch, r.pending, r.expires = d.SandboxID, d.Tenant, &dispatch, false, l.now.Add(ttl)
	l.starts[key] = r
	return nil
}

func (l *memForkLedger) ClaimTarget(_ context.Context, hostname string) (ClaimTarget, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return ClaimTarget{}, l.err
	}
	if hostname == "" {
		return ClaimTarget{}, ErrNotAFork
	}
	r, ok := l.start(hostname)
	if !ok || r.sandboxID == "" || r.tenant == "" {
		return ClaimTarget{}, ErrNotAFork
	}
	return ClaimTarget{SandboxID: r.sandboxID, Tenant: r.tenant}, nil
}

func (l *memForkLedger) ForkedSource(_ context.Context, sourceJTI string) (sourceSandboxID string, forked bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return "", false, l.err
	}
	r, ok := l.fork(sourceJTI)
	if !ok {
		return "", false, nil
	}
	return r.source, true, nil
}

func (l *memForkLedger) Claim(_ context.Context, hostname string) (ForkDispatch, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return ForkDispatch{}, l.err
	}
	if hostname == "" {
		return ForkDispatch{}, ErrNotAFork
	}
	key := SandboxHostname(hostname)
	r, ok := l.start(hostname)
	if !ok {
		return ForkDispatch{}, ErrNotAFork
	}
	if r.dispatch == nil {
		if r.pending {
			return ForkDispatch{}, ErrForkPending
		}
		return ForkDispatch{}, ErrNotAFork
	}
	if r.claimed {
		return ForkDispatch{}, ErrForkClaimed
	}
	r.claimed = true
	l.starts[key] = r
	return *r.dispatch, nil
}

func (l *memForkLedger) ReserveForkSeat(_ context.Context, seat ForkSeat, ttl time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if seat.SourceJTI == "" || seat.SourceSandboxID == "" || seat.SandboxID == "" || seat.MissionID == "" || seat.NodeID == "" {
		return errors.New("fork ledger: a fork seat needs the grant id, the source, the fork, the mission and the node")
	}
	f := l.forks[seat.SourceJTI]
	f.source, f.expires = seat.SourceSandboxID, l.now.Add(ttl)
	l.forks[seat.SourceJTI] = f
	key := SandboxHostname(seat.SandboxID)
	s := l.starts[key]
	s.sandboxID, s.tenant, s.pending, s.expires = seat.SandboxID, seat.Tenant, true, l.now.Add(ttl)
	l.starts[key] = s
	l.seats[seat.MissionID+":"+seat.NodeID] = memSeat{seat: seat, expires: l.now.Add(ttl)}
	return nil
}

func (l *memForkLedger) TakeForkSeat(_ context.Context, missionID, nodeID string) (ForkSeat, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return ForkSeat{}, false, l.err
	}
	key := missionID + ":" + nodeID
	s, ok := l.seats[key]
	if !ok || !s.expires.After(l.now) {
		return ForkSeat{}, false, nil
	}
	delete(l.seats, key)
	return s.seat, true, nil
}
