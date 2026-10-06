// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for the audit export. Hermetic: go-sqlmock stands in for Postgres,
// and a map stands in for the bucket. export_integration_test.go runs the
// export against a real Postgres and a real MinIO.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memStore keeps each object in memory, with its lock.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	locks   map[string]ObjectLock
	puts    int
	err     error
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, locks: map[string]ObjectLock{}}
}

func (m *memStore) PutLocked(_ context.Context, key string, body []byte, lock ObjectLock) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.err != nil {
		return m.err
	}
	m.objects[key] = append([]byte(nil), body...)
	m.locks[key] = lock
	return nil
}

var testPolicy = ExportPolicy{LockMode: LockModeGovernance, LockDays: 400}

// testChain returns n records of a tenant, chained from the genesis hash.
func testChain(tenant string, n int) []ExportedRecord {
	prev := chainGenesis()
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	out := make([]ExportedRecord, 0, n)
	for i := 1; i <= n; i++ {
		r := ExportedRecord{
			ID: int64(100 + i), TenantID: tenant, ChainSeq: int64(i),
			ActorID: "user-1", ActorType: "user", Action: "grant_added",
			Metadata: []byte(`{}`), CreatedAt: at.Add(time.Duration(i) * time.Second), PrevHash: prev,
		}
		r.EntryHash = computeEntryHash(r.chainRow())
		prev = r.EntryHash
		out = append(out, r)
	}
	return out
}

func recordRows(records []ExportedRecord) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{
		"id", "chain_seq", "actor_id", "actor_type", "action", "target_type", "target_id",
		"decision", "metadata", "created_at", "prev_hash", "entry_hash",
	})
	for _, r := range records {
		rows.AddRow(r.ID, r.ChainSeq, r.ActorID, r.ActorType, r.Action, r.TargetType, r.TargetID,
			r.Decision, r.Metadata, r.CreatedAt, r.PrevHash, r.EntryHash)
	}
	return rows
}

func newTestExporter(t *testing.T, store ObjectStore) (*Exporter, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	e, err := NewExporter(db, store, testPolicy, silentLogger())
	require.NoError(t, err)
	e.now = func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }
	return e, mock
}

// expectClaim sets the statements of claimRange for a tenant with no
// pending range, and a next range lo..hi.
func expectClaim(mock sqlmock.Sqlmock, exported int64, lo, hi any) {
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_export_cursor").WithArgs("acme").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FOR UPDATE").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"exported_seq", "pending_first", "pending_last"}).AddRow(exported, nil, nil))
	mock.ExpectQuery("next_range").WithArgs("acme", exported, DefaultExportBatch).
		WillReturnRows(sqlmock.NewRows([]string{"min", "max"}).AddRow(lo, hi))
}

func TestExportTenantOnce_WritesARangeAndAdvances(t *testing.T) {
	store := newMemStore()
	e, mock := newTestExporter(t, store)
	chain := testChain("acme", 3)

	expectClaim(mock, 0, int64(1), int64(3))
	mock.ExpectExec("SET pending_first").WithArgs("acme", int64(1), int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery("chain_seq BETWEEN").WithArgs("acme", int64(1), int64(3)).WillReturnRows(recordRows(chain))
	mock.ExpectExec("SET    exported_seq").WithArgs("acme", int64(1), int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))

	before := testutil.ToFloat64(auditExportedRecordsTotal)
	n, err := e.ExportTenantOnce(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	assert.InDelta(t, 3, testutil.ToFloat64(auditExportedRecordsTotal)-before, 0.001)
	require.NoError(t, mock.ExpectationsWereMet())

	key := ExportObjectKey("acme", 1, 3)
	require.Contains(t, store.objects, key)
	assert.Equal(t, LockModeGovernance, store.locks[key].Mode)
	assert.Equal(t, time.Date(2027, 11, 10, 0, 0, 0, 0, time.UTC), store.locks[key].RetainUntil, "400 days after now")

	// The object alone verifies as a run of the chain.
	got := decodeObject(t, store.objects[key])
	require.NoError(t, checkExportRange(got, 1, 3))
	assert.Equal(t, chain[2].EntryHash, got[2].EntryHash)
}

// TestExportTenantOnce_WritesThePendingRangeAgain: after a restart the
// exporter writes the stored range, under the same name, and chooses no new
// range.
func TestExportTenantOnce_WritesThePendingRangeAgain(t *testing.T) {
	store := newMemStore()
	e, mock := newTestExporter(t, store)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_export_cursor").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FOR UPDATE").
		WillReturnRows(sqlmock.NewRows([]string{"exported_seq", "pending_first", "pending_last"}).AddRow(int64(0), int64(1), int64(2)))
	mock.ExpectRollback()
	mock.ExpectQuery("chain_seq BETWEEN").WithArgs("acme", int64(1), int64(2)).WillReturnRows(recordRows(testChain("acme", 2)))
	mock.ExpectExec("SET    exported_seq").WithArgs("acme", int64(1), int64(2)).WillReturnResult(sqlmock.NewResult(0, 1))

	n, err := e.ExportTenantOnce(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.Contains(t, store.objects, ExportObjectKey("acme", 1, 2))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportTenantOnce_NothingToExport(t *testing.T) {
	store := newMemStore()
	e, mock := newTestExporter(t, store)
	expectClaim(mock, 5, nil, nil)
	mock.ExpectRollback()

	n, err := e.ExportTenantOnce(context.Background(), "acme")
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Zero(t, store.puts)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestExportTenantOnce_AFailedWriteKeepsThePosition: the position does not
// move when the bucket refuses the write. The range stays pending.
func TestExportTenantOnce_AFailedWriteKeepsThePosition(t *testing.T) {
	store := newMemStore()
	store.err = errors.New("access denied")
	e, mock := newTestExporter(t, store)

	expectClaim(mock, 0, int64(1), int64(1))
	mock.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery("chain_seq BETWEEN").WillReturnRows(recordRows(testChain("acme", 1)))

	_, err := e.ExportTenantOnce(context.Background(), "acme")
	require.ErrorContains(t, err, "access denied")
	require.NoError(t, mock.ExpectationsWereMet(), "no UPDATE of exported_seq")
}

// TestExportTenantOnce_RefusesABrokenChain: a range with an altered row
// never reaches the bucket.
func TestExportTenantOnce_RefusesABrokenChain(t *testing.T) {
	store := newMemStore()
	e, mock := newTestExporter(t, store)
	chain := testChain("acme", 2)
	chain[1].Action = "altered"

	expectClaim(mock, 0, int64(1), int64(2))
	mock.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery("chain_seq BETWEEN").WillReturnRows(recordRows(chain))

	_, err := e.ExportTenantOnce(context.Background(), "acme")
	require.ErrorContains(t, err, "entry_hash at position 2")
	assert.Zero(t, store.puts)
}

func TestExportTenantOnce_DatabaseFailures(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(m sqlmock.Sqlmock){
		"begin": func(m sqlmock.Sqlmock) { m.ExpectBegin().WillReturnError(assert.AnError) },
		"create position": func(m sqlmock.Sqlmock) {
			m.ExpectBegin()
			m.ExpectExec("INSERT INTO audit_export_cursor").WillReturnError(assert.AnError)
			m.ExpectRollback()
		},
		"read position": func(m sqlmock.Sqlmock) {
			m.ExpectBegin()
			m.ExpectExec("INSERT INTO audit_export_cursor").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectQuery("FOR UPDATE").WillReturnError(assert.AnError)
			m.ExpectRollback()
		},
		"next range": func(m sqlmock.Sqlmock) {
			m.ExpectBegin()
			m.ExpectExec("INSERT INTO audit_export_cursor").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectQuery("FOR UPDATE").
				WillReturnRows(sqlmock.NewRows([]string{"exported_seq", "pending_first", "pending_last"}).AddRow(int64(0), nil, nil))
			m.ExpectQuery("next_range").WillReturnError(assert.AnError)
			m.ExpectRollback()
		},
		"store pending": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnError(assert.AnError)
			m.ExpectRollback()
		},
		"commit": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectCommit().WillReturnError(assert.AnError)
		},
		"read range": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectCommit()
			m.ExpectQuery("chain_seq BETWEEN").WillReturnError(assert.AnError)
		},
		"scan range": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectCommit()
			m.ExpectQuery("chain_seq BETWEEN").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
		},
		"range rows": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectCommit()
			m.ExpectQuery("chain_seq BETWEEN").WillReturnRows(recordRows(testChain("acme", 1)).RowError(0, assert.AnError))
		},
		"advance": func(m sqlmock.Sqlmock) {
			expectClaim(m, 0, int64(1), int64(1))
			m.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
			m.ExpectCommit()
			m.ExpectQuery("chain_seq BETWEEN").WillReturnRows(recordRows(testChain("acme", 1)))
			m.ExpectExec("SET    exported_seq").WillReturnError(assert.AnError)
		},
	}
	for name, expect := range cases {
		t.Run(name, func(t *testing.T) {
			e, mock := newTestExporter(t, newMemStore())
			expect(mock)
			_, err := e.ExportTenantOnce(ctx, "acme")
			require.Error(t, err)
		})
	}
	t.Run("empty tenant", func(t *testing.T) {
		e, _ := newTestExporter(t, newMemStore())
		_, err := e.ExportTenantOnce(ctx, "")
		require.Error(t, err)
	})
}

// TestExport_GoesOnAfterOneTenantFails: one tenant that fails does not stop
// the export of the next tenant.
func TestExport_GoesOnAfterOneTenantFails(t *testing.T) {
	store := newMemStore()
	e, mock := newTestExporter(t, store)

	mock.ExpectQuery("SELECT DISTINCT tenant_id").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").AddRow("beta"))
	mock.ExpectBegin().WillReturnError(assert.AnError) // acme fails
	// beta: one range, then nothing.
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_export_cursor").WithArgs("beta").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FOR UPDATE").
		WillReturnRows(sqlmock.NewRows([]string{"exported_seq", "pending_first", "pending_last"}).AddRow(int64(0), nil, nil))
	mock.ExpectQuery("next_range").WillReturnRows(sqlmock.NewRows([]string{"min", "max"}).AddRow(int64(1), int64(1)))
	mock.ExpectExec("SET pending_first").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery("chain_seq BETWEEN").WillReturnRows(recordRows(testChain("beta", 1)))
	mock.ExpectExec("SET    exported_seq").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_export_cursor").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FOR UPDATE").
		WillReturnRows(sqlmock.NewRows([]string{"exported_seq", "pending_first", "pending_last"}).AddRow(int64(1), nil, nil))
	mock.ExpectQuery("next_range").WillReturnRows(sqlmock.NewRows([]string{"min", "max"}).AddRow(nil, nil))
	mock.ExpectRollback()

	before := testutil.ToFloat64(auditExportErrorsTotal)
	n, err := e.Export(context.Background())
	require.Error(t, err)
	assert.Equal(t, int64(1), n)
	assert.InDelta(t, 1, testutil.ToFloat64(auditExportErrorsTotal)-before, 0.001)
	assert.Contains(t, store.objects, ExportObjectKey("beta", 1, 1))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExport_ListFailures(t *testing.T) {
	e, mock := newTestExporter(t, newMemStore())
	mock.ExpectQuery("SELECT DISTINCT tenant_id").WillReturnError(assert.AnError)
	_, err := e.Export(context.Background())
	require.ErrorIs(t, err, assert.AnError)

	mock.ExpectQuery("SELECT DISTINCT tenant_id").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))
	_, err = e.Export(context.Background())
	require.Error(t, err)
}

func TestExportLag(t *testing.T) {
	e, mock := newTestExporter(t, newMemStore())
	mock.ExpectQuery("MIN\\(l.created_at\\)").WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(nil))
	require.NoError(t, e.MeasureLag(context.Background()))
	assert.Zero(t, testutil.ToFloat64(auditExportLagSeconds))

	mock.ExpectQuery("MIN\\(l.created_at\\)").
		WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(e.now().Add(-90 * time.Second)))
	require.NoError(t, e.MeasureLag(context.Background()))
	assert.InDelta(t, 90, testutil.ToFloat64(auditExportLagSeconds), 0.001)

	mock.ExpectQuery("MIN\\(l.created_at\\)").WillReturnError(assert.AnError)
	require.Error(t, e.MeasureLag(context.Background()))
}

// TestRunAndMeasureExportLag_StopWithTheContext: each loop runs one time
// and returns when its context ends.
func TestRunAndMeasureExportLag_StopWithTheContext(t *testing.T) {
	runUntilMet := func(t *testing.T, mock sqlmock.Sqlmock, loop func(ctx context.Context)) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { loop(ctx); close(done) }()
		require.Eventually(t, func() bool { return mock.ExpectationsWereMet() == nil }, 5*time.Second, 10*time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the loop did not stop with its context")
		}
	}

	e, mock := newTestExporter(t, newMemStore())
	mock.ExpectQuery("SELECT DISTINCT tenant_id").WillReturnError(assert.AnError)
	mock.ExpectQuery("MIN\\(l.created_at\\)").WillReturnError(assert.AnError)
	runUntilMet(t, mock, func(ctx context.Context) { e.Run(ctx, 0) })

	db, lagMock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	lagMock.ExpectQuery("MIN\\(l.created_at\\)").WillReturnError(assert.AnError)
	runUntilMet(t, lagMock, func(ctx context.Context) { MeasureExportLag(ctx, db, 0, silentLogger()) })

	db2, lagMock2, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db2.Close() })
	lagMock2.ExpectQuery("MIN\\(l.created_at\\)").WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(nil))
	runUntilMet(t, lagMock2, func(ctx context.Context) { MeasureExportLag(ctx, db2, time.Hour, silentLogger()) })
}

func TestCheckExportRange(t *testing.T) {
	chain := testChain("acme", 3)
	require.NoError(t, checkExportRange(chain, 1, 3))

	require.ErrorContains(t, checkExportRange(chain[:2], 1, 3), "hold 2 records")

	gap := []ExportedRecord{chain[0], chain[2], chain[2]}
	require.ErrorContains(t, checkExportRange(gap, 1, 3), "position 2 is missing")

	unlinked := append([]ExportedRecord(nil), chain...)
	unlinked[1].PrevHash = make([]byte, chainHashLen)
	require.ErrorContains(t, checkExportRange(unlinked, 1, 3), "prev_hash at position 2")
}

func TestExportObjectKey(t *testing.T) {
	assert.Equal(t, "audit/acme/00000000000000000001-00000000000000000010.ndjson", ExportObjectKey("acme", 1, 10))
	assert.Equal(t, "audit/a%2Fb/00000000000000000001-00000000000000000001.ndjson", ExportObjectKey("a/b", 1, 1),
		"a tenant id never adds a path segment")
}

func TestNewExporter_RefusesBadInput(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = NewExporter(nil, newMemStore(), testPolicy, silentLogger())
	require.Error(t, err)
	_, err = NewExporter(db, nil, testPolicy, silentLogger())
	require.Error(t, err)
	_, err = NewExporter(db, newMemStore(), testPolicy, nil)
	require.Error(t, err)
	_, err = NewExporter(db, newMemStore(), ExportPolicy{LockMode: "NONE", LockDays: 1}, silentLogger())
	require.Error(t, err)
	_, err = NewExporter(db, newMemStore(), ExportPolicy{LockMode: LockModeCompliance}, silentLogger())
	require.Error(t, err)
}

func setExportEnv(t *testing.T) {
	t.Helper()
	t.Setenv(ExportEndpointEnv, "https://s3.us-east-1.amazonaws.com")
	t.Setenv(ExportBucketEnv, "durable")
	t.Setenv(ExportRegionEnv, "")
	t.Setenv(ExportAccessKeyEnv, "AKIAEXAMPLE")
	t.Setenv(ExportSecretKeyEnv, "example")
	t.Setenv(ExportLockModeEnv, "governance")
	t.Setenv(ExportLockDaysEnv, "400")
}

func TestExportConfigFromEnv(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		setExportEnv(t)
		cfg, err := ExportConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "durable", cfg.Bucket)
		assert.Equal(t, "us-east-1", cfg.Region)
		assert.Equal(t, ExportPolicy{LockMode: LockModeGovernance, LockDays: 400}, cfg.Policy)
		store, err := NewS3Store(cfg)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})
	t.Run("no bucket", func(t *testing.T) {
		setExportEnv(t)
		t.Setenv(ExportBucketEnv, "")
		_, err := ExportConfigFromEnv()
		require.ErrorIs(t, err, ErrExportNotConfigured)
	})
	for name, tc := range map[string][2]string{
		"no endpoint":     {ExportEndpointEnv, ""},
		"bad endpoint":    {ExportEndpointEnv, "s3.example.com"},
		"ftp endpoint":    {ExportEndpointEnv, "ftp://s3.example.com"},
		"no access key":   {ExportAccessKeyEnv, ""},
		"no secret key":   {ExportSecretKeyEnv, ""},
		"days not number": {ExportLockDaysEnv, "a year"},
		"zero days":       {ExportLockDaysEnv, "0"},
		"bad mode":        {ExportLockModeEnv, "legal-hold"},
	} {
		t.Run(name, func(t *testing.T) {
			setExportEnv(t)
			t.Setenv(tc[0], tc[1])
			_, err := ExportConfigFromEnv()
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrExportNotConfigured)
		})
	}
}

func TestNewS3Store_RefusesAnIncompleteConfig(t *testing.T) {
	_, err := NewS3Store(ExportConfig{Bucket: "b"})
	require.Error(t, err)
	_, err = NewS3Store(ExportConfig{Endpoint: &url.URL{Scheme: "https", Host: "s3.example.com"}})
	require.Error(t, err)
}

// decodeObject reads the records of one exported object.
func decodeObject(t *testing.T, body []byte) []ExportedRecord {
	t.Helper()
	var out []ExportedRecord
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var r ExportedRecord
		require.NoError(t, json.Unmarshal(sc.Bytes(), &r))
		out = append(out, r)
	}
	require.NoError(t, sc.Err())
	return out
}
