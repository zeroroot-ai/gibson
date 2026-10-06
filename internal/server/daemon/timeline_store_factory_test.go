// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakePool implements timelinePoolForer for tests. When err is non-nil every
// call to For returns that error. When err is nil, For returns conn.
type fakePool struct {
	conn *datapool.Conn
	err  error
}

func (p *fakePool) For(_ context.Context, _ auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.conn, nil
}

// newMiniredisConn spins up an in-process miniredis server and returns a
// *datapool.Conn whose Redis field is a live *goredis.Client backed by it.
// The Conn's unexported release field is nil — connRelease handles nil
// gracefully. The caller owns cleanup of the returned goredis.Client and
// miniredis.Miniredis via the returned func.
func newMiniredisConn(t *testing.T) (conn *datapool.Conn, cleanup func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	conn = &datapool.Conn{Redis: rdb}
	cleanup = func() {
		_ = rdb.Close()
		mr.Close()
	}
	return conn, cleanup
}

// discardSlog returns a *slog.Logger that discards all output.
func discardSlog() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestTimelineStoreFactory_ValidTenant verifies that a well-formed tenant
// string and a healthy pool probe produce a non-nil TimelineStore backed by
// a per-op acquire closure. It then exercises Append through the store to
// confirm the per-op acquire path actually works end-to-end.
// Covers daemon.go lines 1153 (probeConn.Release), 1162-1169 (acquire closure
// + NewTimelineStore return).
func TestTimelineStoreFactory_ValidTenant(t *testing.T) {
	t.Parallel()

	conn, cleanup := newMiniredisConn(t)
	defer cleanup()

	pool := &fakePool{conn: conn}
	factory := timelineStoreFactory(pool, discardSlog())

	store, err := factory(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, store, "valid tenant + healthy pool must produce a non-nil TimelineStore")

	// Confirm the per-op acquire closure works by doing a real Append.
	ev := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	seq, err := store.Append(context.Background(), "acme", "key-1", ev)
	require.NoError(t, err, "Append via per-op acquire must succeed")
	assert.NotEmpty(t, seq, "Append must return a non-empty sequence ID")
}

// TestTimelineStoreFactory_InvalidTenant verifies that a tenant string that
// fails auth.NewTenantID (upper-case, spaces) makes the factory return an
// error, so the registry builds no serving engine (gibson#726).
// Covers the idErr != nil branch (lines 1134-1140 in original daemon.go,
// now in timeline_store_factory.go).
func TestTimelineStoreFactory_InvalidTenant(t *testing.T) {
	t.Parallel()

	conn, cleanup := newMiniredisConn(t)
	defer cleanup()

	pool := &fakePool{conn: conn}
	factory := timelineStoreFactory(pool, discardSlog())

	// Upper-case letters and spaces are rejected by NewTenantID.
	store, err := factory(context.Background(), "INVALID TENANT")
	require.Error(t, err, "an invalid tenant ID must make the factory fail")
	assert.Nil(t, store)
}

// TestTimelineStoreFactory_PoolForError verifies that a pool.For failure
// during the probe acquire makes the factory return that error (gibson#726).
// Covers the probeErr != nil branch (lines 1146-1152 in original daemon.go,
// now in timeline_store_factory.go).
func TestTimelineStoreFactory_PoolForError(t *testing.T) {
	t.Parallel()

	pool := &fakePool{err: errors.New("tenant not provisioned")}
	factory := timelineStoreFactory(pool, discardSlog())

	store, err := factory(context.Background(), "acme")
	require.ErrorContains(t, err, "tenant not provisioned")
	assert.Nil(t, store)
}

// TestAssertTimelineDurability_SkipsWhenNoRedisConfigured verifies the one
// tolerated skip: with no data-plane Redis addr there is no Redis-backed
// Timeline to guard, so the boot guard passes (engines run in-memory only).
func TestAssertTimelineDurability_SkipsWhenNoRedisConfigured(t *testing.T) {
	t.Parallel()

	err := assertTimelineDurability(context.Background(), "", "", datapool.AssertTimelineAOF, discardSlog())
	assert.NoError(t, err, "empty redis addr must be a tolerated skip, not a boot failure")
}

// TestAssertTimelineDurability_FailsClosedWhenAOFUnverifiable verifies the
// fail-fast contract (gibson#1119): when the data-plane Redis cannot
// positively confirm appendonly=yes — here miniredis, which does not
// implement CONFIG — the guard returns an error so daemon Start aborts.
func TestAssertTimelineDurability_FailsClosedWhenAOFUnverifiable(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	gErr := assertTimelineDurability(context.Background(), mr.Addr(), "", datapool.AssertTimelineAOF, discardSlog())
	require.Error(t, gErr, "unverifiable AOF must fail the boot guard")
	assert.Contains(t, gErr.Error(), "gibson#1119", "boot-abort error must name the guard")
}

// TestAssertTimelineDurability_FailsClosedWhenRedisUnreachable verifies the
// guard also fails closed when the configured Redis cannot be dialed at all.
func TestAssertTimelineDurability_FailsClosedWhenRedisUnreachable(t *testing.T) {
	t.Parallel()

	// Grab a port that is guaranteed dead: start miniredis, note the addr,
	// stop it.
	mr, err := miniredis.Run()
	require.NoError(t, err)
	addr := mr.Addr()
	mr.Close()

	gErr := assertTimelineDurability(context.Background(), addr, "", datapool.AssertTimelineAOF, discardSlog())
	require.Error(t, gErr, "unreachable redis must fail the boot guard")
	assert.Contains(t, gErr.Error(), "timeline durability boot guard")
}

// TestAssertTimelineDurability_PassesWhenAOFConfirmed verifies the guard
// passes (and Start proceeds to wire the Timeline store factory) when the
// AOF probe confirms appendonly=yes. The probe is stubbed because miniredis
// cannot answer CONFIG GET; the real probe's yes/no/error decision table is
// covered by the assertAOFEnabled tests in internal/infra/datapool.
func TestAssertTimelineDurability_PassesWhenAOFConfirmed(t *testing.T) {
	t.Parallel()

	confirmed := func(ctx context.Context, addr, password string) error { return nil }
	err := assertTimelineDurability(context.Background(), "redis:6379", "", confirmed, discardSlog())
	assert.NoError(t, err, "confirmed AOF must pass the boot guard")
}

// flakyPool answers the probe and fails each later acquire.
type flakyPool struct {
	conn  *datapool.Conn
	calls int
}

func (p *flakyPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	p.calls++
	if p.calls == 1 {
		return p.conn, nil
	}
	return nil, errors.New("the pool is gone")
}

// TestTimelineStoreFactory_AcquireErrorIsReturned: an operation whose
// per-op acquire fails returns the pool error.
func TestTimelineStoreFactory_AcquireErrorIsReturned(t *testing.T) {
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	store, err := timelineStoreFactory(&flakyPool{conn: conn}, discardSlog())(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, store)
	_, err = store.Append(context.Background(), "acme", "key-1", brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
	require.ErrorContains(t, err, "the pool is gone")
}
