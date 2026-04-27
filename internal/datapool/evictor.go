package datapool

import (
	"context"
	"time"

	"github.com/zero-day-ai/sdk/auth"
)

// clock abstracts time for testability. Production code uses realClock;
// tests use fakeClock.
type clock interface {
	Now() time.Time
	NewTicker(d time.Duration) (<-chan time.Time, func())
}

// realClock delegates to the standard time package.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// fakeClock is a controllable clock for tests.
type fakeClock struct {
	now     time.Time
	tickCh  chan time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{
		now:    start,
		tickCh: make(chan time.Time, 1),
	}
}

func (f *fakeClock) Now() time.Time { return f.now }

func (f *fakeClock) Advance(d time.Duration) {
	f.now = f.now.Add(d)
	select {
	case f.tickCh <- f.now:
	default:
	}
}

func (f *fakeClock) NewTicker(_ time.Duration) (<-chan time.Time, func()) {
	return f.tickCh, func() {}
}

// evictor runs a background goroutine that periodically scans all tenant
// entries and closes pools that have been idle longer than idleTTL.
//
// Eviction only happens when activeConns == 0 (no Conn is checked out).
// This prevents tearing down pools that are still in use.
type evictor struct {
	p                     *pool
	evictionCheckInterval time.Duration
	idleTTL               time.Duration
	clk                   clock
}

func newEvictor(p *pool, interval, idleTTL time.Duration, clk clock) *evictor {
	return &evictor{
		p:                     p,
		evictionCheckInterval: interval,
		idleTTL:               idleTTL,
		clk:                   clk,
	}
}

// run is the evictor goroutine entry point. It returns when ctx is cancelled.
func (e *evictor) run(ctx context.Context) {
	tickCh, stop := e.clk.NewTicker(e.evictionCheckInterval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickCh:
			e.sweep()
		}
	}
}

// sweep iterates all tenant entries and evicts any that are idle.
func (e *evictor) sweep() {
	now := e.clk.Now()
	e.p.tenantEntries.Range(func(key, value any) bool {
		tenant := key.(auth.TenantID)
		entry := value.(*tenantEntry)

		// Skip tenants with active checked-out Conns.
		if entry.activeConns.Load() > 0 {
			return true
		}

		lastReleased := time.Unix(0, entry.lastReleased.Load())
		if now.Sub(lastReleased) > e.idleTTL {
			e.p.evictTenant(tenant)
		}
		return true
	})
}
