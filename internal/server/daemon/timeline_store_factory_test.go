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
// + NewRedisTimelineStore return).
func TestTimelineStoreFactory_ValidTenant(t *testing.T) {
	t.Parallel()

	conn, cleanup := newMiniredisConn(t)
	defer cleanup()

	pool := &fakePool{conn: conn}
	factory := timelineStoreFactory(pool, discardSlog())

	store := factory(context.Background(), "acme")
	require.NotNil(t, store, "valid tenant + healthy pool must produce a non-nil TimelineStore")

	// Confirm the per-op acquire closure works by doing a real Append.
	ev := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	seq, err := store.Append(context.Background(), "acme", ev)
	require.NoError(t, err, "Append via per-op acquire must succeed")
	assert.NotEmpty(t, seq, "Append must return a non-empty sequence ID")
}

// TestTimelineStoreFactory_InvalidTenant verifies that a tenant string that
// fails auth.NewTenantID (upper-case, spaces) causes the factory to return nil
// so the brain engine falls back to in-memory mode.
// Covers the idErr != nil branch (lines 1134-1140 in original daemon.go,
// now in timeline_store_factory.go).
func TestTimelineStoreFactory_InvalidTenant(t *testing.T) {
	t.Parallel()

	conn, cleanup := newMiniredisConn(t)
	defer cleanup()

	pool := &fakePool{conn: conn}
	factory := timelineStoreFactory(pool, discardSlog())

	// Upper-case letters and spaces are rejected by NewTenantID.
	store := factory(context.Background(), "INVALID TENANT")
	assert.Nil(t, store, "invalid tenant ID must cause the factory to return nil")
}

// TestTimelineStoreFactory_PoolForError verifies that a pool.For failure
// during the probe acquire causes the factory to return nil so the brain
// engine falls back to in-memory mode.
// Covers the probeErr != nil branch (lines 1146-1152 in original daemon.go,
// now in timeline_store_factory.go).
func TestTimelineStoreFactory_PoolForError(t *testing.T) {
	t.Parallel()

	pool := &fakePool{err: errors.New("tenant not provisioned")}
	factory := timelineStoreFactory(pool, discardSlog())

	store := factory(context.Background(), "acme")
	assert.Nil(t, store, "pool.For probe error must cause the factory to return nil")
}
