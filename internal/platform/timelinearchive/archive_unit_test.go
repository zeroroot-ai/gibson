// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package timelinearchive

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/sdk/auth"
)

// memTenant is one tenant database in memory. It answers the statements of
// the archive the way Postgres does, so the three-step export and the prune
// run against it without a container.
type memTenant struct {
	mu       sync.Mutex
	events   []ExportedEvent
	position bool // the timeline_export row exists
	exported StreamID
	pending  *[2]StreamID
	// fail names a statement fragment whose run fails.
	fail string
	// txErr is the error of InTx.
	txErr    error
	released int
}

func (m *memTenant) SQL() datapool.SQL { return memSQL{m: m} }

func (m *memTenant) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	if m.txErr != nil {
		return m.txErr
	}
	return fn(memSQL{m: m})
}

func (m *memTenant) Release() { m.released++ }

type memSQL struct{ m *memTenant }

type memRow struct {
	vals []any
	err  error
}

func (r memRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.vals[i]))
	}
	return nil
}

type memRows struct {
	rows [][]any
	i    int
}

func (r *memRows) Next() bool { r.i++; return r.i <= len(r.rows) }
func (r *memRows) Scan(dest ...any) error {
	return memRow{vals: r.rows[r.i-1]}.Scan(dest...)
}
func (r *memRows) Err() error { return nil }
func (r *memRows) Close()     {}

func idLess(a, b StreamID) bool { return a.Ms < b.Ms || (a.Ms == b.Ms && a.Seq < b.Seq) }

func (s memSQL) failing(stmt string) bool { return s.m.fail != "" && strings.Contains(stmt, s.m.fail) }

func (s memSQL) Exec(_ context.Context, stmt string, args ...any) (int64, error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if s.failing(stmt) {
		return 0, errors.New("statement refused")
	}
	switch {
	case strings.Contains(stmt, "INSERT INTO timeline_export"):
		s.m.position = true
		return 1, nil
	case strings.Contains(stmt, "SET    pending_first_ms = $1"):
		s.m.pending = &[2]StreamID{{Ms: args[0].(int64), Seq: args[1].(int64)}, {Ms: args[2].(int64), Seq: args[3].(int64)}}
		return 1, nil
	case strings.Contains(stmt, "SET    exported_ms = $3"):
		s.m.exported = StreamID{Ms: args[2].(int64), Seq: args[3].(int64)}
		s.m.pending = nil
		return 1, nil
	case strings.Contains(stmt, "DELETE FROM timeline_events"):
		cutoff := args[0].(time.Time)
		upTo := StreamID{Ms: args[1].(int64), Seq: args[2].(int64)}
		var kept []ExportedEvent
		var n int64
		for _, ev := range s.m.events {
			id := StreamID{Ms: ev.StreamMs, Seq: ev.StreamSeq}
			if ev.RecordedAt.Before(cutoff) && !idLess(upTo, id) {
				n++
				continue
			}
			kept = append(kept, ev)
		}
		s.m.events = kept
		return n, nil
	}
	return 0, errors.New("memTenant: unknown statement " + stmt)
}

func (s memSQL) QueryRow(_ context.Context, stmt string, _ ...any) datapool.Row {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if s.failing(stmt) {
		return memRow{err: errors.New("statement refused")}
	}
	if !s.m.position {
		return memRow{err: datapool.ErrNoRows}
	}
	if strings.Contains(stmt, "pending_first_ms") {
		var p [4]sql.NullInt64
		if s.m.pending != nil {
			p = [4]sql.NullInt64{
				{Int64: s.m.pending[0].Ms, Valid: true}, {Int64: s.m.pending[0].Seq, Valid: true},
				{Int64: s.m.pending[1].Ms, Valid: true}, {Int64: s.m.pending[1].Seq, Valid: true},
			}
		}
		return memRow{vals: []any{s.m.exported.Ms, s.m.exported.Seq, p[0], p[1], p[2], p[3]}}
	}
	return memRow{vals: []any{s.m.exported.Ms, s.m.exported.Seq}}
}

func (s memSQL) Query(_ context.Context, stmt string, args ...any) (datapool.Rows, error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if s.failing(stmt) {
		return nil, errors.New("statement refused")
	}
	out := &memRows{}
	switch {
	case strings.Contains(stmt, "LIMIT  $3"):
		after := StreamID{Ms: args[0].(int64), Seq: args[1].(int64)}
		limit := args[2].(int)
		for _, ev := range s.m.events {
			id := StreamID{Ms: ev.StreamMs, Seq: ev.StreamSeq}
			if idLess(after, id) && len(out.rows) < limit {
				out.rows = append(out.rows, []any{ev.StreamMs, ev.StreamSeq})
			}
		}
	case strings.Contains(stmt, "event::text"):
		first := StreamID{Ms: args[0].(int64), Seq: args[1].(int64)}
		last := StreamID{Ms: args[2].(int64), Seq: args[3].(int64)}
		for _, ev := range s.m.events {
			id := StreamID{Ms: ev.StreamMs, Seq: ev.StreamSeq}
			if !idLess(id, first) && !idLess(last, id) {
				out.rows = append(out.rows, []any{ev.StreamMs, ev.StreamSeq, ev.Kind, string(ev.Event), ev.RecordedAt})
			}
		}
	default:
		return nil, errors.New("memTenant: unknown query " + stmt)
	}
	return out, nil
}

type memPool struct {
	tenants map[string]*memTenant
	err     error
	onFor   func()
}

func (p memPool) For(_ context.Context, tenant auth.TenantID) (TenantDB, error) {
	if p.onFor != nil {
		p.onFor()
	}
	if p.err != nil {
		return nil, p.err
	}
	return p.tenants[tenant.String()], nil
}

type memPeriods struct {
	months int
	err    error
}

func (p memPeriods) Period(context.Context, string) (audit.RetentionPeriod, error) {
	return audit.RetentionPeriod{EffectiveMonths: p.months}, p.err
}

type memStore struct {
	mu   sync.Mutex
	keys []string
	body map[string][]byte
	lock audit.ObjectLock
	err  error
}

func (s *memStore) PutLocked(_ context.Context, key string, body []byte, lock audit.ObjectLock) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.body == nil {
		s.body = map[string][]byte{}
	}
	s.keys = append(s.keys, key)
	s.body[key] = body
	s.lock = lock
	return nil
}

var testNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func eventsAt(ms int64, recorded time.Time, n int) []ExportedEvent {
	out := make([]ExportedEvent, 0, n)
	for i := range n {
		out = append(out, ExportedEvent{StreamMs: ms, StreamSeq: int64(i), Kind: "k", Event: []byte(`{"n":1}`), RecordedAt: recorded})
	}
	return out
}

// platformWithTenants is a platform database that lists the tenants.
func platformWithTenants(t *testing.T, ids ...string) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rows := sqlmock.NewRows([]string{"tenant_id"})
	for _, id := range ids {
		rows.AddRow(id)
	}
	mock.ExpectQuery("SELECT tenant_id FROM tenant_secrets_broker_config").WillReturnRows(rows)
	return db, mock
}

func newTestArchive(t *testing.T, db *sql.DB, pool TenantPool, periods PeriodSource, store audit.ObjectStore) *Archive {
	t.Helper()
	var policy audit.ExportPolicy
	if store != nil {
		policy = audit.ExportPolicy{LockMode: audit.LockModeGovernance, LockDays: 400}
	}
	a, err := New(db, pool, periods, store, policy, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return testNow }
	a.batch = 2
	return a
}

// One run exports the rows of a tenant in batches, under a lock, and then
// removes the exported rows that are older than the period. A tenant with an
// invalid id is skipped.
func TestRunOnce_ExportsThenPrunes(t *testing.T) {
	old := testNow.AddDate(0, -14, 0)
	tenant := &memTenant{events: append(eventsAt(1, old, 3), eventsAt(2, testNow, 1)...)}
	db, _ := platformWithTenants(t, "acme", "NOT A TENANT")
	store := &memStore{}
	a := newTestArchive(t, db, memPool{tenants: map[string]*memTenant{"acme": tenant}}, memPeriods{months: 13}, store)

	exported, removed, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if exported != 4 || removed != 3 {
		t.Fatalf("exported %d, removed %d; want 4 and 3", exported, removed)
	}
	if len(store.keys) != 2 || store.keys[0] != ObjectKey("acme", StreamID{Ms: 1}, StreamID{Ms: 1, Seq: 1}) {
		t.Fatalf("keys = %v; want two batches of two", store.keys)
	}
	if store.lock.Mode != audit.LockModeGovernance || !store.lock.RetainUntil.Equal(testNow.AddDate(0, 0, 400)) {
		t.Fatalf("lock = %+v", store.lock)
	}
	if got := strings.Count(string(store.body[store.keys[0]]), "\n"); got != 2 {
		t.Fatalf("the first object holds %d lines, want 2", got)
	}
	if tenant.exported != (StreamID{Ms: 2}) || tenant.pending != nil || len(tenant.events) != 1 {
		t.Fatalf("tenant after the run: exported %v, pending %v, %d rows", tenant.exported, tenant.pending, len(tenant.events))
	}
	if tenant.released != 1 {
		t.Fatalf("the tenant connection was released %d times, want 1", tenant.released)
	}
}

// A range that is pending from an earlier run is written again under the
// same name. A pending range with no row is an error.
func TestExportOnce_PendingRange(t *testing.T) {
	ctx := context.Background()
	tenant := &memTenant{events: eventsAt(1, testNow, 2), position: true, pending: &[2]StreamID{{Ms: 1}, {Ms: 1, Seq: 1}}}
	store := &memStore{}
	a := newTestArchive(t, platformDB(t), memPool{}, memPeriods{months: 13}, store)
	n, err := a.exportOnce(ctx, "acme", tenant)
	if err != nil || n != 2 {
		t.Fatalf("exportOnce = %d, %v; want the pending range", n, err)
	}
	if len(store.keys) != 1 || store.keys[0] != ObjectKey("acme", StreamID{Ms: 1}, StreamID{Ms: 1, Seq: 1}) {
		t.Fatalf("keys = %v", store.keys)
	}

	empty := &memTenant{position: true, pending: &[2]StreamID{{Ms: 9}, {Ms: 9}}}
	if _, err := a.exportOnce(ctx, "acme", empty); err == nil || !strings.Contains(err.Error(), "holds no row") {
		t.Fatalf("a pending range with no row: %v", err)
	}
}

// With no store, nothing is exported and so nothing is removed. A tenant
// that exported nothing keeps each row.
func TestArchiveTenant_NoStoreRemovesNothing(t *testing.T) {
	tenant := &memTenant{events: eventsAt(1, testNow.AddDate(-2, 0, 0), 2)}
	a := newTestArchive(t, platformDB(t), memPool{tenants: map[string]*memTenant{"acme": tenant}}, memPeriods{months: 13}, nil)
	exported, removed, err := a.ArchiveTenant(context.Background(), mustTenant(t, "acme"))
	if err != nil || exported != 0 || removed != 0 {
		t.Fatalf("ArchiveTenant = %d, %d, %v", exported, removed, err)
	}
	if len(tenant.events) != 2 {
		t.Fatal("a row that was not exported must stay")
	}
}

// The prune keeps the floor of the period, and reports each failure.
func TestPrune_Errors(t *testing.T) {
	ctx := context.Background()
	exportedAll := func() *memTenant {
		return &memTenant{events: eventsAt(1, testNow.AddDate(-5, 0, 0), 1), position: true, exported: StreamID{Ms: 1}}
	}
	a := newTestArchive(t, platformDB(t), memPool{}, memPeriods{months: 1}, nil)
	tenant := exportedAll()
	tenant.events[0].RecordedAt = testNow.AddDate(0, -12, 0) // under the 13-month floor
	if n, err := a.prune(ctx, "acme", tenant); err != nil || n != 0 {
		t.Fatalf("a row under the floor: removed %d, %v", n, err)
	}

	a = newTestArchive(t, platformDB(t), memPool{}, memPeriods{err: errors.New("no period")}, nil)
	if _, err := a.prune(ctx, "acme", exportedAll()); err == nil {
		t.Fatal("a period error must be returned")
	}
	a = newTestArchive(t, platformDB(t), memPool{}, memPeriods{months: 13}, nil)
	tenant = exportedAll()
	tenant.fail = "DELETE"
	if _, err := a.prune(ctx, "acme", tenant); err == nil {
		t.Fatal("a failed delete must be returned")
	}
	tenant = exportedAll()
	tenant.fail = "SELECT exported_ms, exported_seq FROM"
	if _, err := a.prune(ctx, "acme", tenant); err == nil {
		t.Fatal("a failed position read must be returned")
	}
}

// Each failure of an export step is returned, and a failure of one tenant
// does not stop the next.
func TestRunOnce_Errors(t *testing.T) {
	ctx := context.Background()
	store := &memStore{}
	for name, tenant := range map[string]*memTenant{
		"the transaction":    {txErr: errors.New("tx")},
		"the position read":  {fail: "pending_first_ms"},
		"the range query":    {events: eventsAt(1, testNow, 1), fail: "LIMIT  $3"},
		"the pending write":  {events: eventsAt(1, testNow, 1), fail: "SET    pending_first_ms"},
		"the row read":       {events: eventsAt(1, testNow, 1), fail: "event::text"},
		"the position write": {events: eventsAt(1, testNow, 1), fail: "SET    exported_ms"},
	} {
		a := newTestArchive(t, platformDB(t), memPool{}, memPeriods{months: 13}, store)
		if _, err := a.exportOnce(ctx, "acme", tenant); err == nil {
			t.Errorf("%s fails and the export must return the error", name)
		}
	}

	refusing := &memStore{err: errors.New("bucket down")}
	a := newTestArchive(t, platformDB(t), memPool{}, memPeriods{months: 13}, refusing)
	if _, err := a.exportOnce(ctx, "acme", &memTenant{events: eventsAt(1, testNow, 1)}); err == nil {
		t.Error("a refused write must return the error")
	}

	// One tenant cannot be opened, the other runs.
	db, _ := platformWithTenants(t, "acme", "beta")
	ok := &memTenant{events: eventsAt(1, testNow, 1)}
	pool := memPool{tenants: map[string]*memTenant{"beta": ok}, err: nil}
	a = newTestArchive(t, db, flakyPool{pool: pool, failFor: "acme"}, memPeriods{months: 13}, store)
	exported, _, err := a.RunOnce(ctx)
	if err == nil || exported != 1 {
		t.Fatalf("RunOnce with one bad tenant = %d, %v; want the good tenant exported and the error", exported, err)
	}

	// The platform database cannot list the tenants.
	bad, mock, _ := sqlmock.New()
	t.Cleanup(func() { _ = bad.Close() })
	mock.ExpectQuery("SELECT tenant_id").WillReturnError(errors.New("down"))
	a = newTestArchive(t, bad, memPool{}, memPeriods{months: 13}, store)
	if _, _, err := a.RunOnce(ctx); err == nil {
		t.Fatal("a failed tenant list must return the error")
	}
	mock.ExpectQuery("SELECT tenant_id").WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").RowError(0, errors.New("broken")))
	if _, _, err := a.RunOnce(ctx); err == nil {
		t.Fatal("a broken row must return the error")
	}
}

type flakyPool struct {
	pool    memPool
	failFor string
}

func (p flakyPool) For(ctx context.Context, tenant auth.TenantID) (TenantDB, error) {
	if tenant.String() == p.failFor {
		return nil, errors.New("pool down")
	}
	return p.pool.For(ctx, tenant)
}

// Run archives at once, then at each interval, until ctx ends.
func TestRun_StopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { _ = db.Close() })
	for range 3 {
		mock.ExpectQuery("SELECT tenant_id").WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme"))
	}
	runs := 0
	pool := memPool{tenants: map[string]*memTenant{"acme": {events: eventsAt(1, testNow, 1)}}, onFor: func() {
		runs++
		if runs == 2 {
			cancel()
		}
	}}
	a := newTestArchive(t, db, pool, memPeriods{months: 13}, &memStore{})
	done := make(chan struct{})
	go func() { a.Run(ctx, time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after the context ended")
	}
	if runs < 2 {
		t.Fatalf("Run archived %d times, want at least 2", runs)
	}
}

// ObjectKey sorts by stream id and escapes the tenant.
func TestObjectKey(t *testing.T) {
	key := ObjectKey("a/b", StreamID{Ms: 1, Seq: 2}, StreamID{Ms: 3, Seq: 4})
	if !strings.HasSuffix(key, "/timeline/00000000000000000001-00000000000000000002_00000000000000000003-00000000000000000004.ndjson") ||
		strings.Contains(key, "a/b") {
		t.Fatalf("key = %q", key)
	}
	if (StreamID{Ms: 1, Seq: 2}).String() != "1-2" {
		t.Fatal("StreamID.String")
	}
}

func platformDB(t *testing.T) *sql.DB {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustTenant(t *testing.T, id string) auth.TenantID {
	t.Helper()
	tenant, err := auth.NewTenantID(id)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

// New refuses a missing dependency, and Run with no interval takes the
// default and logs a failed run.
func TestNew_AndRun_Defaults(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	if _, err := New(nil, memPool{}, memPeriods{}, nil, audit.ExportPolicy{}, logger); err == nil {
		t.Fatal("a nil platform database must be refused")
	}
	if _, err := New(platformDB(t), memPool{}, memPeriods{}, nil, audit.ExportPolicy{}, nil); err == nil {
		t.Fatal("a nil logger must be refused")
	}
	bad, mock, _ := sqlmock.New()
	t.Cleanup(func() { _ = bad.Close() })
	mock.ExpectQuery("SELECT tenant_id").WillReturnError(errors.New("down"))
	a := newTestArchive(t, bad, memPool{}, memPeriods{months: 13}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.Run(ctx, 0) // one failed run, then the ended context
}

// A tenant that cannot be scanned, a position that cannot be created, and a
// tenant whose export fails each return their error.
func TestArchive_MoreErrors(t *testing.T) {
	ctx := context.Background()
	bad, mock, _ := sqlmock.New()
	t.Cleanup(func() { _ = bad.Close() })
	mock.ExpectQuery("SELECT tenant_id").WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))
	a := newTestArchive(t, bad, memPool{}, memPeriods{months: 13}, nil)
	if _, err := a.tenants(ctx); err == nil {
		t.Fatal("a tenant id that cannot be scanned must return the error")
	}

	store := &memStore{}
	tenant := &memTenant{events: eventsAt(1, testNow, 1), fail: "INSERT INTO timeline_export"}
	a = newTestArchive(t, platformDB(t), memPool{tenants: map[string]*memTenant{"acme": tenant}}, memPeriods{months: 13}, store)
	if _, err := a.exportOnce(ctx, "acme", tenant); err == nil {
		t.Fatal("a position that cannot be created must return the error")
	}
	if _, _, err := a.ArchiveTenant(ctx, mustTenant(t, "acme")); err == nil {
		t.Fatal("a failed export must return the error of the tenant")
	}
}
