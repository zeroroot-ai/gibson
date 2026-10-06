// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — export.go
//
// The exporter writes each audit record to the audit/ prefix of the durable
// bucket (ADR-0113, gibson#764). On prem, the bucket is the S3-compatible
// store of the customer.
//
// The exporter reads the hash chain of each tenant in chain order. It writes
// one object for each range of positions:
//
//	audit/<tenant>/<first chain_seq>-<last chain_seq>.ndjson
//
// Each line of the object is one record with its chain values, so a reader
// can verify the chain from the object alone. Each object carries the object
// lock that the bucket policy requires.
//
// audit_export_cursor holds the position of each tenant. Before a write the
// exporter stores the range as pending. After a restart it writes that same
// range again under the same name, so a record is never in the bucket under
// two names, and no record is lost. Retention removes only rows that the
// export wrote (retention.go).
package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// ExportPrefix is the key prefix of each exported object. The bucket
	// lifecycle rule and the bucket policy name this prefix.
	ExportPrefix = "audit/"

	// DefaultExportInterval is the time between two export runs.
	DefaultExportInterval = time.Minute

	// DefaultExportBatch is the most records in one exported object.
	DefaultExportBatch = 1000
)

// Object lock modes of an exported object.
const (
	LockModeGovernance = "GOVERNANCE"
	LockModeCompliance = "COMPLIANCE"
)

var (
	auditExportedRecordsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_audit_exported_records_total",
		Help: "Total number of audit records written to the durable bucket.",
	})
	auditExportErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_audit_export_errors_total",
		Help: "Total number of audit export runs that failed for a tenant.",
	})
	// auditExportLagSeconds is the age of the oldest record that is not in
	// the bucket. The alert on the export reads it.
	auditExportLagSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gibson_audit_export_lag_seconds",
		Help: "Age in seconds of the oldest audit record that is not in the durable bucket. Zero when each record is exported.",
	})
)

// ObjectStore writes one object with an object lock. The S3 store
// (export_s3.go) is the production implementation.
type ObjectStore interface {
	PutLocked(ctx context.Context, key string, body []byte, lock ObjectLock) error
}

// ObjectLock is the lock of one exported object.
type ObjectLock struct {
	// Mode is LockModeGovernance or LockModeCompliance.
	Mode string
	// RetainUntil is the end of the lock.
	RetainUntil time.Time
}

// ExportPolicy is the lock that each exported object gets. The bucket policy
// refuses a write with another mode or a shorter period.
type ExportPolicy struct {
	// LockMode is LockModeGovernance or LockModeCompliance.
	LockMode string
	// LockDays is the lock period in days.
	LockDays int
}

// Validate refuses an unknown mode and a period under one day.
func (p ExportPolicy) Validate() error {
	if p.LockMode != LockModeGovernance && p.LockMode != LockModeCompliance {
		return fmt.Errorf("audit export: lock mode %q is not %s or %s", p.LockMode, LockModeGovernance, LockModeCompliance)
	}
	if p.LockDays < 1 {
		return fmt.Errorf("audit export: lock period %d days is under one day", p.LockDays)
	}
	return nil
}

// ExportedRecord is one line of an exported object. It holds each field
// that the chain hash covers, so a reader can verify the chain without
// Postgres.
type ExportedRecord struct {
	ID         int64     `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ChainSeq   int64     `json:"chain_seq"`
	ActorID    string    `json:"actor_id"`
	ActorType  string    `json:"actor_type"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Decision   string    `json:"decision"`
	Metadata   []byte    `json:"metadata"`
	CreatedAt  time.Time `json:"created_at"`
	PrevHash   []byte    `json:"prev_hash"`
	EntryHash  []byte    `json:"entry_hash"`
}

func (r ExportedRecord) chainRow() chainRow {
	return chainRow{
		Seq:        r.ChainSeq,
		TenantID:   r.TenantID,
		ActorID:    r.ActorID,
		ActorType:  r.ActorType,
		Action:     r.Action,
		TargetType: r.TargetType,
		TargetID:   r.TargetID,
		Decision:   r.Decision,
		Metadata:   r.Metadata,
		CreatedAt:  r.CreatedAt,
		PrevHash:   r.PrevHash,
	}
}

// checkExportRange proves that records are a run of the chain: positions
// first..last with no gap, each prev_hash links to the entry before it, and
// each entry_hash matches its fields. The exporter refuses to put a broken
// run into the bucket.
func checkExportRange(records []ExportedRecord, first, last int64) error {
	if int64(len(records)) != last-first+1 {
		return fmt.Errorf("audit export: positions %d..%d hold %d records, want %d", first, last, len(records), last-first+1)
	}
	for i, r := range records {
		if r.ChainSeq != first+int64(i) {
			return fmt.Errorf("audit export: position %d is missing", first+int64(i))
		}
		if i > 0 && !bytes.Equal(r.PrevHash, records[i-1].EntryHash) {
			return fmt.Errorf("audit export: prev_hash at position %d does not match the entry before it", r.ChainSeq)
		}
		if !bytes.Equal(computeEntryHash(r.chainRow()), r.EntryHash) {
			return fmt.Errorf("audit export: entry_hash at position %d does not match its fields", r.ChainSeq)
		}
	}
	return nil
}

// ExportObjectKey returns the object name of one range of a tenant. The
// name depends on the tenant and the range only, so a range written again
// lands under the same name.
func ExportObjectKey(tenantID string, first, last int64) string {
	return fmt.Sprintf("%s%s/%020d-%020d.ndjson", ExportPrefix, url.PathEscape(tenantID), first, last)
}

// Exporter writes the audit records of each tenant to the durable bucket.
type Exporter struct {
	db     *sql.DB
	store  ObjectStore
	policy ExportPolicy
	batch  int
	logger *slog.Logger
	now    func() time.Time
}

// NewExporter constructs an Exporter. Each argument is required.
func NewExporter(db *sql.DB, store ObjectStore, policy ExportPolicy, logger *slog.Logger) (*Exporter, error) {
	if db == nil {
		return nil, errors.New("audit.NewExporter: db must not be nil")
	}
	if store == nil {
		return nil, errors.New("audit.NewExporter: store must not be nil")
	}
	if logger == nil {
		return nil, errors.New("audit.NewExporter: logger must not be nil")
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("audit.NewExporter: %w", err)
	}
	return &Exporter{
		db:     db,
		store:  store,
		policy: policy,
		batch:  DefaultExportBatch,
		logger: logger.With("component", "audit.export"),
		now:    time.Now,
	}, nil
}

// Run exports now, and then one time for each interval, until ctx is
// cancelled. A run that fails is logged and counted. The next run tries
// again from the stored position.
func (e *Exporter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultExportInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if n, err := e.Export(ctx); err != nil {
			e.logger.ErrorContext(ctx, "audit: export run failed", slog.String("error", err.Error()))
		} else if n > 0 {
			e.logger.DebugContext(ctx, "audit: export wrote records", slog.Int64("records", n))
		}
		if err := e.MeasureLag(ctx); err != nil {
			e.logger.ErrorContext(ctx, "audit: export lag measure failed", slog.String("error", err.Error()))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// Export writes each record that is not in the bucket, for each tenant, and
// returns the number of records that it wrote. When one tenant fails,
// Export goes on with the next tenant and returns the joined errors.
func (e *Exporter) Export(ctx context.Context) (int64, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT DISTINCT tenant_id FROM audit_log WHERE chain_seq IS NOT NULL ORDER BY tenant_id`)
	if err != nil {
		auditExportErrorsTotal.Inc()
		return 0, fmt.Errorf("audit.Exporter.Export: list tenants: %w", err)
	}
	tenants, err := scanStrings(rows)
	if err != nil {
		auditExportErrorsTotal.Inc()
		return 0, fmt.Errorf("audit.Exporter.Export: list tenants: %w", err)
	}

	var (
		total int64
		errs  []error
	)
	for _, tenant := range tenants {
		for {
			n, err := e.ExportTenantOnce(ctx, tenant)
			if err != nil {
				auditExportErrorsTotal.Inc()
				errs = append(errs, err)
				break
			}
			total += n
			if n == 0 {
				break
			}
		}
	}
	return total, errors.Join(errs...)
}

// ExportTenantOnce writes one range of a tenant to the bucket, and returns
// the number of records in it. It returns zero when the tenant has nothing
// to export.
//
// Three steps, so that a restart at any point loses nothing and names
// nothing twice:
//  1. In one transaction, choose the range and store it as pending. A range
//     that is already pending is chosen again, unchanged.
//  2. Write the range to its object name.
//  3. Move exported_seq to the end of the range and clear pending.
func (e *Exporter) ExportTenantOnce(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, errors.New("audit.Exporter.ExportTenantOnce: tenantID must not be empty")
	}
	first, last, ok, err := e.claimRange(ctx, tenantID)
	if err != nil || !ok {
		return 0, err
	}

	records, err := e.readRange(ctx, tenantID, first, last)
	if err != nil {
		return 0, err
	}
	if err := checkExportRange(records, first, last); err != nil {
		return 0, fmt.Errorf("audit.Exporter: tenant %q: %w", tenantID, err)
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for i := range records {
		if err := enc.Encode(records[i]); err != nil {
			return 0, fmt.Errorf("audit.Exporter: encode position %d of tenant %q: %w", records[i].ChainSeq, tenantID, err)
		}
	}
	lock := ObjectLock{
		Mode:        e.policy.LockMode,
		RetainUntil: e.now().UTC().AddDate(0, 0, e.policy.LockDays),
	}
	key := ExportObjectKey(tenantID, first, last)
	if err := e.store.PutLocked(ctx, key, body.Bytes(), lock); err != nil {
		return 0, fmt.Errorf("audit.Exporter: write %s: %w", key, err)
	}

	if _, err := e.db.ExecContext(ctx, `
UPDATE audit_export_cursor
SET    exported_seq = $3, pending_first = NULL, pending_last = NULL, updated_at = now()
WHERE  tenant_id = $1 AND pending_first = $2 AND pending_last = $3`, tenantID, first, last); err != nil {
		return 0, fmt.Errorf("audit.Exporter: advance the position of tenant %q: %w", tenantID, err)
	}
	auditExportedRecordsTotal.Add(float64(len(records)))
	return int64(len(records)), nil
}

// claimRange returns the range to write for the tenant, and stores it as
// pending. ok is false when the tenant has nothing to export.
func (e *Exporter) claimRange(ctx context.Context, tenantID string) (first, last int64, ok bool, err error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: begin for tenant %q: %w", tenantID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_export_cursor (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: create the position of tenant %q: %w", tenantID, err)
	}
	var (
		exported                  int64
		pendingFirst, pendingLast sql.NullInt64
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT exported_seq, pending_first, pending_last FROM audit_export_cursor WHERE tenant_id = $1 FOR UPDATE`,
		tenantID).Scan(&exported, &pendingFirst, &pendingLast); err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: read the position of tenant %q: %w", tenantID, err)
	}
	if pendingFirst.Valid && pendingLast.Valid {
		// A write of this range started before and did not finish. Write
		// the same range again, under the same name.
		return pendingFirst.Int64, pendingLast.Int64, true, nil
	}

	var lo, hi sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
SELECT MIN(chain_seq), MAX(chain_seq)
FROM  (SELECT chain_seq FROM audit_log
       WHERE tenant_id = $1 AND chain_seq > $2
       ORDER BY chain_seq LIMIT $3) AS next_range`,
		tenantID, exported, e.batch).Scan(&lo, &hi); err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: find the next range of tenant %q: %w", tenantID, err)
	}
	if !lo.Valid || !hi.Valid {
		return 0, 0, false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE audit_export_cursor SET pending_first = $2, pending_last = $3, updated_at = now() WHERE tenant_id = $1`,
		tenantID, lo.Int64, hi.Int64); err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: store the pending range of tenant %q: %w", tenantID, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, false, fmt.Errorf("audit.Exporter: commit the pending range of tenant %q: %w", tenantID, err)
	}
	committed = true
	return lo.Int64, hi.Int64, true, nil
}

// readRange reads positions first..last of the tenant, in chain order.
func (e *Exporter) readRange(ctx context.Context, tenantID string, first, last int64) ([]ExportedRecord, error) {
	rows, err := e.db.QueryContext(ctx, `
SELECT id, chain_seq, actor_id, actor_type, action,
       COALESCE(target_type, ''), COALESCE(target_id, ''), COALESCE(decision, ''),
       metadata, created_at, prev_hash, entry_hash
FROM   audit_log
WHERE  tenant_id = $1 AND chain_seq BETWEEN $2 AND $3
ORDER  BY chain_seq`, tenantID, first, last)
	if err != nil {
		return nil, fmt.Errorf("audit.Exporter: read positions %d..%d of tenant %q: %w", first, last, tenantID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []ExportedRecord
	for rows.Next() {
		r := ExportedRecord{TenantID: tenantID}
		if err := rows.Scan(&r.ID, &r.ChainSeq, &r.ActorID, &r.ActorType, &r.Action,
			&r.TargetType, &r.TargetID, &r.Decision, &r.Metadata, &r.CreatedAt, &r.PrevHash, &r.EntryHash); err != nil {
			return nil, fmt.Errorf("audit.Exporter: scan a record of tenant %q: %w", tenantID, err)
		}
		r.CreatedAt = r.CreatedAt.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit.Exporter: read positions %d..%d of tenant %q: %w", first, last, tenantID, err)
	}
	return out, nil
}

// MeasureLag sets gibson_audit_export_lag_seconds to the age of the oldest
// record that is not in the bucket, or to zero.
func (e *Exporter) MeasureLag(ctx context.Context) error {
	lag, err := exportLag(ctx, e.db, e.now())
	if err != nil {
		return err
	}
	auditExportLagSeconds.Set(lag.Seconds())
	return nil
}

// MeasureExportLag sets gibson_audit_export_lag_seconds now, and then one
// time for each interval, until ctx is cancelled. The daemon runs it when
// no bucket is configured, so the lag alert still sees the records that wait.
func MeasureExportLag(ctx context.Context, db *sql.DB, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DefaultExportInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		lag, err := exportLag(ctx, db, time.Now())
		if err != nil {
			logger.ErrorContext(ctx, "audit: export lag measure failed", slog.String("error", err.Error()))
		} else {
			auditExportLagSeconds.Set(lag.Seconds())
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// exportLag returns the age of the oldest chained record above the export
// position of its tenant.
func exportLag(ctx context.Context, db *sql.DB, now time.Time) (time.Duration, error) {
	var oldest sql.NullTime
	if err := db.QueryRowContext(ctx, `
SELECT MIN(l.created_at)
FROM   audit_log l
LEFT JOIN audit_export_cursor c ON c.tenant_id = l.tenant_id
WHERE  l.chain_seq IS NOT NULL AND l.chain_seq > COALESCE(c.exported_seq, 0)`).Scan(&oldest); err != nil {
		return 0, fmt.Errorf("audit: measure the export lag: %w", err)
	}
	if !oldest.Valid {
		return 0, nil
	}
	return max(now.Sub(oldest.Time), 0), nil
}

// scanStrings reads one string column and closes rows.
func scanStrings(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, strings.TrimSpace(s))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}
