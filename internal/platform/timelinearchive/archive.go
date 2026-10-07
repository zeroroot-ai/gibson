// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package timelinearchive exports the Timeline history of each tenant to the
// durable bucket, and removes old rows from Postgres (ADR-0163 decision 4,
// owner decision D31, gibson#992).
//
// Retention follows the audit log. The history of a tenant is the table
// timeline_events in the Postgres database of the tenant (migration 013). The
// export writes each row, in stream order, to the audit/ prefix of the durable
// bucket (ADR-0113). The prefix has the object lock and the lifecycle rule of
// the audit log, so the bucket keeps the Timeline as long as the audit log:
//
//	audit/<tenant>/timeline/<first stream id>_<last stream id>.ndjson
//
// The table timeline_export (migration 014) holds the position of the export.
// Before a write the export stores the range as pending. After a restart it
// writes that same range again under the same name, so a row is never in the
// bucket under two names, and no row is lost.
//
// Retention removes a row only when the export wrote it and it is older than
// the period. The period is the audit retention period of the tenant: the
// longer of the period of the install (GIBSON_AUDIT_RETENTION_MONTHS) and the
// period that a tenant admin set (TenantService.SetAuditRetention). No value
// can make it shorter than 13 months.
package timelinearchive

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// DefaultInterval is the time between two runs of the export and the
	// retention.
	DefaultInterval = 10 * time.Minute

	// DefaultBatch is the most rows in one exported object.
	DefaultBatch = 1000
)

var (
	exportedRowsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_timeline_exported_events_total",
		Help: "Total number of Timeline history rows written to the durable bucket.",
	})
	removedRowsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_timeline_retention_removed_events_total",
		Help: "Total number of exported Timeline history rows that retention removed from Postgres.",
	})
	runErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_timeline_export_errors_total",
		Help: "Total number of Timeline export or retention runs that failed for a tenant.",
	})
)

// TenantDB is the part of a tenant connection that the archive uses.
// *datapool.Conn satisfies it.
type TenantDB interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

// TenantPool opens the connection of one tenant.
type TenantPool interface {
	For(ctx context.Context, tenant auth.TenantID) (TenantDB, error)
}

// PeriodSource gives the audit retention period of a tenant.
// *audit.RetentionSettings satisfies it.
type PeriodSource interface {
	Period(ctx context.Context, tenantID string) (audit.RetentionPeriod, error)
}

// StreamID is the identity and the order of one Timeline event: the two parts
// of the Redis stream id "<ms>-<seq>".
type StreamID struct {
	Ms  int64
	Seq int64
}

func (s StreamID) String() string { return fmt.Sprintf("%d-%d", s.Ms, s.Seq) }

// beforeAll is before each stream id. Redis assigns no negative part.
var beforeAll = StreamID{Ms: -1, Seq: -1}

// ExportedEvent is one line of an exported object.
type ExportedEvent struct {
	TenantID   string          `json:"tenant_id"`
	StreamMs   int64           `json:"stream_ms"`
	StreamSeq  int64           `json:"stream_seq"`
	Kind       string          `json:"kind"`
	Event      json.RawMessage `json:"event"`
	RecordedAt time.Time       `json:"recorded_at"`
}

// ObjectKey returns the object name of one range of a tenant. The name
// depends on the tenant and the range only, so a range written again lands
// under the same name.
func ObjectKey(tenantID string, first, last StreamID) string {
	return fmt.Sprintf("%s%s/timeline/%020d-%020d_%020d-%020d.ndjson",
		audit.ExportPrefix, url.PathEscape(tenantID), first.Ms, first.Seq, last.Ms, last.Seq)
}

// Archive exports and prunes the Timeline history of each tenant.
type Archive struct {
	platform *sql.DB
	pool     TenantPool
	periods  PeriodSource
	store    audit.ObjectStore
	policy   audit.ExportPolicy
	batch    int
	logger   *slog.Logger
	now      func() time.Time
}

// New constructs an Archive. platform is the platform database, which lists
// the tenants. periods gives the retention period of each tenant. store is
// the durable bucket. With a nil store the archive does not export, and so
// retention removes no row.
func New(platform *sql.DB, pool TenantPool, periods PeriodSource, store audit.ObjectStore, policy audit.ExportPolicy, logger *slog.Logger) (*Archive, error) {
	if platform == nil {
		return nil, errors.New("timelinearchive.New: the platform database must not be nil")
	}
	if pool == nil {
		return nil, errors.New("timelinearchive.New: the tenant pool must not be nil")
	}
	if logger == nil {
		return nil, errors.New("timelinearchive.New: logger must not be nil")
	}
	if periods == nil {
		return nil, errors.New("timelinearchive.New: the period source must not be nil")
	}
	if store != nil {
		if err := policy.Validate(); err != nil {
			return nil, fmt.Errorf("timelinearchive.New: %w", err)
		}
	}
	return &Archive{
		platform: platform,
		pool:     pool,
		periods:  periods,
		store:    store,
		policy:   policy,
		batch:    DefaultBatch,
		logger:   logger.With("component", "timeline.archive"),
		now:      time.Now,
	}, nil
}

// Run archives each tenant now, and then one time for each interval, until
// ctx is cancelled. A run that fails is logged and counted. The next run tries
// again from the stored position.
func (a *Archive) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		exported, removed, err := a.RunOnce(ctx)
		if err != nil {
			a.logger.ErrorContext(ctx, "timeline: archive run failed", slog.String("error", err.Error()))
		}
		if exported > 0 || removed > 0 {
			a.logger.InfoContext(ctx, "timeline: archive run done",
				slog.Int64("exported", exported), slog.Int64("removed", removed))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// RunOnce exports and then prunes each tenant. When one tenant fails, it goes
// on with the next tenant and returns the joined errors.
func (a *Archive) RunOnce(ctx context.Context) (exported, removed int64, err error) {
	tenants, err := a.tenants(ctx)
	if err != nil {
		runErrorsTotal.Inc()
		return 0, 0, err
	}
	var errs []error
	for _, tenant := range tenants {
		e, r, tErr := a.ArchiveTenant(ctx, tenant)
		exported += e
		removed += r
		if tErr != nil {
			runErrorsTotal.Inc()
			errs = append(errs, tErr)
		}
	}
	return exported, removed, errors.Join(errs...)
}

// tenants lists each tenant with a provisioned data plane: the tenants that
// have a secrets broker config, the same test that datapool uses.
func (a *Archive) tenants(ctx context.Context) ([]auth.TenantID, error) {
	rows, err := a.platform.QueryContext(ctx, `SELECT tenant_id FROM tenant_secrets_broker_config ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("timelinearchive: list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []auth.TenantID
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("timelinearchive: scan a tenant: %w", err)
		}
		id, err := auth.NewTenantID(raw)
		if err != nil {
			a.logger.WarnContext(ctx, "timeline: skip a tenant with an invalid id", slog.String("tenant", raw))
			continue
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("timelinearchive: list tenants: %w", err)
	}
	return out, nil
}

// ArchiveTenant exports each row of the tenant that is not in the bucket, and
// then removes the exported rows that are older than the period.
func (a *Archive) ArchiveTenant(ctx context.Context, tenant auth.TenantID) (exported, removed int64, err error) {
	db, err := a.pool.For(ctx, tenant)
	if err != nil {
		return 0, 0, fmt.Errorf("timelinearchive: open tenant %q: %w", tenant, err)
	}
	defer db.Release()

	if a.store != nil {
		for {
			n, err := a.exportOnce(ctx, tenant.String(), db)
			if err != nil {
				return exported, 0, err
			}
			exported += n
			if n == 0 {
				break
			}
		}
	}
	removed, err = a.prune(ctx, tenant.String(), db)
	return exported, removed, err
}

// exportOnce writes one range of the tenant to the bucket, and returns the
// number of rows in it. It returns zero when the tenant has nothing to export.
//
// Three steps, so that a restart at any point loses nothing and names nothing
// twice:
//  1. In one transaction, choose the range and store it as pending. A range
//     that is already pending is chosen again, unchanged.
//  2. Write the range to its object name.
//  3. Move the position to the end of the range and clear pending.
func (a *Archive) exportOnce(ctx context.Context, tenant string, db TenantDB) (int64, error) {
	first, last, ok, err := a.claimRange(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: %w", tenant, err)
	}
	if !ok {
		return 0, nil
	}
	events, err := readRange(ctx, db.SQL(), tenant, first, last)
	if err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: %w", tenant, err)
	}
	if len(events) == 0 {
		return 0, fmt.Errorf("timelinearchive: tenant %q: the pending range %s..%s holds no row", tenant, first, last)
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for i := range events {
		if err := enc.Encode(events[i]); err != nil {
			return 0, fmt.Errorf("timelinearchive: tenant %q: encode %d-%d: %w", tenant, events[i].StreamMs, events[i].StreamSeq, err)
		}
	}
	lock := audit.ObjectLock{
		Mode:        a.policy.LockMode,
		RetainUntil: a.now().UTC().AddDate(0, 0, a.policy.LockDays),
	}
	key := ObjectKey(tenant, first, last)
	if err := a.store.PutLocked(ctx, key, body.Bytes(), lock); err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: write %s: %w", tenant, key, err)
	}
	if _, err := db.SQL().Exec(ctx, `
UPDATE timeline_export
SET    exported_ms = $3, exported_seq = $4,
       pending_first_ms = NULL, pending_first_seq = NULL,
       pending_last_ms = NULL, pending_last_seq = NULL, updated_at = now()
WHERE  pending_first_ms = $1 AND pending_first_seq = $2
  AND  pending_last_ms = $3 AND pending_last_seq = $4`,
		first.Ms, first.Seq, last.Ms, last.Seq); err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: advance the position: %w", tenant, err)
	}
	exportedRowsTotal.Add(float64(len(events)))
	return int64(len(events)), nil
}

// claimRange returns the range to write, and stores it as pending. ok is
// false when the tenant has nothing to export.
func (a *Archive) claimRange(ctx context.Context, db TenantDB) (first, last StreamID, ok bool, err error) {
	err = db.InTx(ctx, func(tx datapool.SQL) error {
		if _, err := tx.Exec(ctx, `INSERT INTO timeline_export (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING`); err != nil {
			return fmt.Errorf("create the position: %w", err)
		}
		var (
			exported            StreamID
			pFirstMs, pFirstSeq sql.NullInt64
			pLastMs, pLastSeq   sql.NullInt64
		)
		if err := tx.QueryRow(ctx, `
SELECT exported_ms, exported_seq, pending_first_ms, pending_first_seq, pending_last_ms, pending_last_seq
FROM   timeline_export WHERE id FOR UPDATE`).Scan(
			&exported.Ms, &exported.Seq, &pFirstMs, &pFirstSeq, &pLastMs, &pLastSeq); err != nil {
			return fmt.Errorf("read the position: %w", err)
		}
		if pFirstMs.Valid && pFirstSeq.Valid && pLastMs.Valid && pLastSeq.Valid {
			// A write of this range started before and did not finish.
			// Write the same range again, under the same name.
			first = StreamID{Ms: pFirstMs.Int64, Seq: pFirstSeq.Int64}
			last = StreamID{Ms: pLastMs.Int64, Seq: pLastSeq.Int64}
			ok = true
			return nil
		}
		rows, err := tx.Query(ctx, `
SELECT stream_ms, stream_seq FROM timeline_events
WHERE  (stream_ms, stream_seq) > ($1, $2)
ORDER  BY stream_ms, stream_seq
LIMIT  $3`, exported.Ms, exported.Seq, a.batch)
		if err != nil {
			return fmt.Errorf("find the next range: %w", err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var id StreamID
			if err := rows.Scan(&id.Ms, &id.Seq); err != nil {
				return fmt.Errorf("scan the next range: %w", err)
			}
			if n == 0 {
				first = id
			}
			last = id
			n++
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("find the next range: %w", err)
		}
		rows.Close()
		if n == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `
UPDATE timeline_export
SET    pending_first_ms = $1, pending_first_seq = $2,
       pending_last_ms = $3, pending_last_seq = $4, updated_at = now()
WHERE  id`, first.Ms, first.Seq, last.Ms, last.Seq); err != nil {
			return fmt.Errorf("store the pending range: %w", err)
		}
		ok = true
		return nil
	})
	if err != nil {
		return StreamID{}, StreamID{}, false, fmt.Errorf("claim a range: %w", err)
	}
	return first, last, ok, nil
}

// readRange reads the rows first..last, in stream order.
func readRange(ctx context.Context, db datapool.SQL, tenant string, first, last StreamID) ([]ExportedEvent, error) {
	rows, err := db.Query(ctx, `
SELECT stream_ms, stream_seq, kind, event::text, recorded_at
FROM   timeline_events
WHERE  (stream_ms, stream_seq) >= ($1, $2) AND (stream_ms, stream_seq) <= ($3, $4)
ORDER  BY stream_ms, stream_seq`, first.Ms, first.Seq, last.Ms, last.Seq)
	if err != nil {
		return nil, fmt.Errorf("read %s..%s: %w", first, last, err)
	}
	defer rows.Close()
	var out []ExportedEvent
	for rows.Next() {
		ev := ExportedEvent{TenantID: tenant}
		var raw string
		if err := rows.Scan(&ev.StreamMs, &ev.StreamSeq, &ev.Kind, &raw, &ev.RecordedAt); err != nil {
			return nil, fmt.Errorf("scan a row: %w", err)
		}
		ev.Event = json.RawMessage(raw)
		ev.RecordedAt = ev.RecordedAt.UTC()
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s..%s: %w", first, last, err)
	}
	return out, nil
}

// prune removes the rows that the export wrote and that are older than the
// period of the tenant, and returns the number of rows that it removed.
func (a *Archive) prune(ctx context.Context, tenant string, db TenantDB) (int64, error) {
	exported, err := exportedPosition(ctx, db.SQL())
	if err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: %w", tenant, err)
	}
	if exported == beforeAll {
		return 0, nil
	}
	period, err := a.periods.Period(ctx, tenant)
	if err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: %w", tenant, err)
	}
	// The period source never answers under 13 months. The floor here
	// keeps that true for any source.
	months := max(period.EffectiveMonths, audit.MinRetentionMonths)
	cutoff := a.now().UTC().AddDate(0, -months, 0)
	n, err := db.SQL().Exec(ctx, `
DELETE FROM timeline_events
WHERE  recorded_at < $1
  AND  (stream_ms, stream_seq) <= ($2, $3)`, cutoff, exported.Ms, exported.Seq)
	if err != nil {
		return 0, fmt.Errorf("timelinearchive: tenant %q: remove old rows: %w", tenant, err)
	}
	removedRowsTotal.Add(float64(n))
	return n, nil
}

// exportedPosition returns the stream id of the last row in the bucket. A
// tenant with no export row has exported nothing.
func exportedPosition(ctx context.Context, db datapool.SQL) (StreamID, error) {
	var exported StreamID
	err := db.QueryRow(ctx, `SELECT exported_ms, exported_seq FROM timeline_export WHERE id`).
		Scan(&exported.Ms, &exported.Seq)
	if errors.Is(err, datapool.ErrNoRows) {
		return beforeAll, nil
	}
	if err != nil {
		return StreamID{}, fmt.Errorf("read the export position: %w", err)
	}
	return exported, nil
}
