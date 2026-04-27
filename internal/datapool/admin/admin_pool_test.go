package admin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/datapool/admin"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeAuthorizer implements authz.Authorizer for testing.
type fakeAuthorizer struct {
	mu       sync.Mutex
	checks   []fakeCheckCall
	allowed  bool
	checkErr error
}

type fakeCheckCall struct {
	user, relation, object string
}

func (f *fakeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.mu.Lock()
	f.checks = append(f.checks, fakeCheckCall{user, relation, object})
	f.mu.Unlock()
	return f.allowed, f.checkErr
}
func (f *fakeAuthorizer) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (f *fakeAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (f *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (f *fakeAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) StoreID() string { return "fake-store" }
func (f *fakeAuthorizer) ModelID() string { return "fake-model" }
func (f *fakeAuthorizer) Close() error    { return nil }

// fakeAuditEmitter records EmitAdminAcquire calls.
type fakeAuditEmitter struct {
	mu     sync.Mutex
	events []auditEvent
}

type auditEvent struct {
	subject, rpcMethod string
}

func (e *fakeAuditEmitter) EmitAdminAcquire(_ context.Context, subject, rpcMethod string) {
	e.mu.Lock()
	e.events = append(e.events, auditEvent{subject, rpcMethod})
	e.mu.Unlock()
}

func (e *fakeAuditEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

func (e *fakeAuditEmitter) last() auditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) == 0 {
		return auditEvent{}
	}
	return e.events[len(e.events)-1]
}

// fakePool implements datapool.Pool for testing.
type fakePool struct {
	mu    sync.Mutex
	conns map[auth.TenantID]*datapool.Conn
	errs  map[auth.TenantID]error
}

func (fp *fakePool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if err, ok := fp.errs[tenant]; ok {
		return nil, err
	}
	if conn, ok := fp.conns[tenant]; ok {
		return conn, nil
	}
	return nil, &datapool.NotProvisionedError{Tenant: tenant.String()}
}

func (fp *fakePool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, errors.New("not implemented in fakePool")
}

func (fp *fakePool) SetAdminPool(_ datapool.AdminAcquirer) {}

func (fp *fakePool) Close() error { return nil }

// fakeTenantLister is a test TenantLister with a fixed list.
type fakeTenantLister struct {
	tenants []auth.TenantID
	err     error
}

func (f *fakeTenantLister) ListTenants(_ context.Context) ([]auth.TenantID, error) {
	return f.tenants, f.err
}

// newTestAdminPool builds an AdminPool wired with fakes (no real DB connections).
func newTestAdminPool(t *testing.T, fga *fakeAuthorizer, emit *fakeAuditEmitter, pool datapool.Pool) *admin.AdminPool {
	t.Helper()
	ap, err := admin.New(
		admin.AdminPoolConfig{}, // empty config: no real DB connections
		pool,
		fga,
		emit,
		nil, // use default logger
	)
	require.NoError(t, err)
	return ap
}

// ---------------------------------------------------------------------------
// Tests: identity checks
// ---------------------------------------------------------------------------

func TestAcquire_DeniedWhenIdentityAbsent(t *testing.T) {
	fga := &fakeAuthorizer{allowed: false}
	emitter := &fakeAuditEmitter{}
	pool := &fakePool{}

	ap := newTestAdminPool(t, fga, emitter, pool)

	// Context with no Identity set → should fail before FGA check.
	_, err := ap.Acquire(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity not available")

	// No audit event should have been emitted.
	assert.Equal(t, 0, emitter.count())
	// FGA should not have been called.
	fga.mu.Lock()
	assert.Empty(t, fga.checks)
	fga.mu.Unlock()
}

func TestAcquire_DeniedWhenFGADenies(t *testing.T) {
	fga := &fakeAuthorizer{allowed: false}
	emitter := &fakeAuditEmitter{}
	pool := &fakePool{}

	ap := newTestAdminPool(t, fga, emitter, pool)

	identity := auth.Identity{
		Subject: "user-alice",
		Issuer:  auth.IssuerZitadel,
	}
	ctx := auth.WithIdentity(context.Background(), identity)

	_, err := ap.Acquire(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, admin.ErrUnauthorizedAdmin)

	// Audit event must NOT be emitted on denial.
	assert.Equal(t, 0, emitter.count())

	// FGA was consulted exactly once with correct arguments.
	fga.mu.Lock()
	require.Len(t, fga.checks, 1)
	assert.Equal(t, "user:user-alice", fga.checks[0].user)
	assert.Equal(t, "platform_operator", fga.checks[0].relation)
	assert.Equal(t, "system_tenant:_system", fga.checks[0].object)
	fga.mu.Unlock()
}

func TestAcquire_DeniedWhenFGAErrors(t *testing.T) {
	fgaErr := errors.New("FGA service unavailable")
	fga := &fakeAuthorizer{allowed: false, checkErr: fgaErr}
	emitter := &fakeAuditEmitter{}
	pool := &fakePool{}

	ap := newTestAdminPool(t, fga, emitter, pool)

	identity := auth.Identity{Subject: "user-bob", Issuer: auth.IssuerZitadel}
	ctx := auth.WithIdentity(context.Background(), identity)

	_, err := ap.Acquire(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FGA check failed")

	assert.Equal(t, 0, emitter.count())
}

func TestAcquire_AllowedEmitsAuditAndReturnsConn(t *testing.T) {
	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	pool := &fakePool{}

	ap := newTestAdminPool(t, fga, emitter, pool)

	identity := auth.Identity{Subject: "platform-svc", Issuer: auth.IssuerZitadel}
	ctx := auth.WithIdentity(context.Background(), identity)

	conn, err := ap.Acquire(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Release()

	// Audit event was emitted.
	assert.Equal(t, 1, emitter.count())
	ev := emitter.last()
	assert.Equal(t, "platform-svc", ev.subject)
	// No gRPC method in context → recorded as empty.
	assert.Equal(t, "", ev.rpcMethod)

	// Subject is recorded on the conn.
	assert.Equal(t, "platform-svc", conn.Subject)
}

func TestAcquire_IdempotentRelease(t *testing.T) {
	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	pool := &fakePool{}

	ap := newTestAdminPool(t, fga, emitter, pool)

	identity := auth.Identity{Subject: "platform-svc", Issuer: auth.IssuerZitadel}
	ctx := auth.WithIdentity(context.Background(), identity)

	conn, err := ap.Acquire(ctx)
	require.NoError(t, err)

	// Double release should not panic.
	conn.Release()
	conn.Release()
}

// ---------------------------------------------------------------------------
// Tests: ForEachTenant
// ---------------------------------------------------------------------------

func mustTenant(t *testing.T, s string) auth.TenantID {
	t.Helper()
	tid, err := auth.NewTenantID(s)
	require.NoError(t, err)
	return tid
}

func acquireAdminConn(t *testing.T, ap *admin.AdminPool, subject string) *datapool.AdminConn {
	t.Helper()
	identity := auth.Identity{Subject: subject, Issuer: auth.IssuerZitadel}
	ctx := auth.WithIdentity(context.Background(), identity)
	conn, err := ap.Acquire(ctx)
	require.NoError(t, err)
	return conn
}

func TestForEachTenant_HappyPathThreeTenants(t *testing.T) {
	t1 := mustTenant(t, "acme")
	t2 := mustTenant(t, "bigcorp")
	t3 := mustTenant(t, "startup")

	emptyConn := &datapool.Conn{}
	fp := &fakePool{
		conns: map[auth.TenantID]*datapool.Conn{
			t1: emptyConn,
			t2: emptyConn,
			t3: emptyConn,
		},
	}

	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	ap := newTestAdminPool(t, fga, emitter, fp)

	adminConn := acquireAdminConn(t, ap, "platform-svc")
	defer adminConn.Release()

	ctx := context.Background()
	lister := &fakeTenantLister{tenants: []auth.TenantID{t1, t2, t3}}

	var visited []auth.TenantID
	var mu sync.Mutex
	err := admin.ForEachTenant(ctx, adminConn, lister, fp, func(tenant auth.TenantID, _ *datapool.Conn) error {
		mu.Lock()
		visited = append(visited, tenant)
		mu.Unlock()
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []auth.TenantID{t1, t2, t3}, visited)
}

func TestForEachTenant_StopsOnErrStopIteration(t *testing.T) {
	t1 := mustTenant(t, "acme")
	t2 := mustTenant(t, "bigcorp")
	t3 := mustTenant(t, "startup")

	emptyConn := &datapool.Conn{}
	fp := &fakePool{
		conns: map[auth.TenantID]*datapool.Conn{
			t1: emptyConn,
			t2: emptyConn,
			t3: emptyConn,
		},
	}

	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	ap := newTestAdminPool(t, fga, emitter, fp)

	adminConn := acquireAdminConn(t, ap, "platform-svc")
	defer adminConn.Release()

	lister := &fakeTenantLister{tenants: []auth.TenantID{t1, t2, t3}}
	ctx := context.Background()

	var visited []auth.TenantID
	err := admin.ForEachTenant(ctx, adminConn, lister, fp, func(tenant auth.TenantID, _ *datapool.Conn) error {
		visited = append(visited, tenant)
		if tenant == t1 {
			return admin.ErrStopIteration
		}
		return nil
	})
	// ErrStopIteration returns nil, not an error.
	require.NoError(t, err)
	assert.Len(t, visited, 1)
	assert.Equal(t, t1, visited[0])
}

func TestForEachTenant_AccumulatesErrorsAndContinues(t *testing.T) {
	t1 := mustTenant(t, "acme")
	t2 := mustTenant(t, "bigcorp")
	t3 := mustTenant(t, "startup")

	emptyConn := &datapool.Conn{}
	fp := &fakePool{
		conns: map[auth.TenantID]*datapool.Conn{
			t1: emptyConn,
			t2: emptyConn,
			t3: emptyConn,
		},
	}

	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	ap := newTestAdminPool(t, fga, emitter, fp)

	adminConn := acquireAdminConn(t, ap, "platform-svc")
	defer adminConn.Release()

	lister := &fakeTenantLister{tenants: []auth.TenantID{t1, t2, t3}}
	ctx := context.Background()

	sentinelErr := errors.New("fn failed")
	var visited []auth.TenantID
	err := admin.ForEachTenant(ctx, adminConn, lister, fp, func(tenant auth.TenantID, _ *datapool.Conn) error {
		visited = append(visited, tenant)
		if tenant == t2 {
			return sentinelErr
		}
		return nil
	})
	// err is non-nil because t2 errored.
	require.Error(t, err)
	// But all three tenants were still visited.
	assert.Len(t, visited, 3)
}

func TestForEachTenant_ListerError(t *testing.T) {
	fp := &fakePool{}
	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	ap := newTestAdminPool(t, fga, emitter, fp)

	adminConn := acquireAdminConn(t, ap, "platform-svc")
	defer adminConn.Release()

	lister := &fakeTenantLister{err: errors.New("k8s API unavailable")}
	ctx := context.Background()

	err := admin.ForEachTenant(ctx, adminConn, lister, fp, func(_ auth.TenantID, _ *datapool.Conn) error {
		t.Fatal("fn should not be called when listing fails")
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing tenants")
}

func TestForEachTenant_ContextCancellationHaltsIteration(t *testing.T) {
	t1 := mustTenant(t, "acme")
	t2 := mustTenant(t, "bigcorp")

	emptyConn := &datapool.Conn{}
	fp := &fakePool{
		conns: map[auth.TenantID]*datapool.Conn{
			t1: emptyConn,
			t2: emptyConn,
		},
	}

	fga := &fakeAuthorizer{allowed: true}
	emitter := &fakeAuditEmitter{}
	ap := newTestAdminPool(t, fga, emitter, fp)

	adminConn := acquireAdminConn(t, ap, "platform-svc")
	defer adminConn.Release()

	cancelCtx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()

	innerCtx, innerCancel := context.WithCancel(cancelCtx)
	defer innerCancel()

	lister := &fakeTenantLister{tenants: []auth.TenantID{t1, t2}}

	var visited []auth.TenantID
	_ = admin.ForEachTenant(innerCtx, adminConn, lister, fp, func(tenant auth.TenantID, _ *datapool.Conn) error {
		visited = append(visited, tenant)
		innerCancel() // cancel after first tenant is processed
		return nil
	})
	// The test primarily checks that t2 was NOT visited after cancellation.
	// (After visiting t1 and cancelling, the loop should exit.)
	assert.Len(t, visited, 1)
}

func TestNew_RequiresNonNilDeps(t *testing.T) {
	fp := &fakePool{}
	fga := &fakeAuthorizer{}
	emitter := &fakeAuditEmitter{}

	_, err := admin.New(admin.AdminPoolConfig{}, nil, fga, emitter, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenantPool must not be nil")

	_, err = admin.New(admin.AdminPoolConfig{}, fp, nil, emitter, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fgaClient must not be nil")

	_, err = admin.New(admin.AdminPoolConfig{}, fp, fga, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auditEmitter must not be nil")
}
