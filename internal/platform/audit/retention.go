// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — retention.go
//
// Retention removes audit records that are older than the retention period.
//
// The default period is 13 months. An operator can set a longer period for
// the install. No config can set a period under 13 months.
//
// Retention removes the oldest rows of a tenant's hash chain, and only a
// run of rows from the start of the chain. In the same transaction it writes
// the chain anchor: the position of the oldest row that remains, and the
// hash that this row points at. The writer and the verifier start from the
// anchor, so the chain still verifies after each run.
//
// Retention never removes a row that the export did not write to the
// durable bucket (export.go). A row with no chain position is never
// exported, so retention keeps it.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// MinRetentionMonths is the shortest retention period, and the default.
	MinRetentionMonths = 13

	// RetentionMonthsEnv names the variable that sets the period of the
	// install, in months.
	RetentionMonthsEnv = "GIBSON_AUDIT_RETENTION_MONTHS"

	// DefaultRetentionInterval is the time between two retention runs.
	DefaultRetentionInterval = 24 * time.Hour
)

// ErrRetentionTooShort is returned for a retention period under
// MinRetentionMonths.
var ErrRetentionTooShort = errors.New("audit: the retention period is shorter than 13 months")

var auditRetentionErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_audit_retention_errors_total",
	Help: "Total number of audit retention runs that failed for a tenant.",
})

// ValidateRetentionMonths refuses a period under MinRetentionMonths.
func ValidateRetentionMonths(months int) error {
	if months < MinRetentionMonths {
		return fmt.Errorf("%w: got %d months", ErrRetentionTooShort, months)
	}
	return nil
}

// RetentionMonthsFromEnv reads the period of the install from
// GIBSON_AUDIT_RETENTION_MONTHS. An empty variable gives MinRetentionMonths.
// A value that is not a number, or a period under MinRetentionMonths, is an
// error, so the daemon does not start with a period that the owner decision
// does not permit.
func RetentionMonthsFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv(RetentionMonthsEnv))
	if raw == "" {
		return MinRetentionMonths, nil
	}
	months, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number of months: %w", RetentionMonthsEnv, raw, err)
	}
	if err := ValidateRetentionMonths(months); err != nil {
		return 0, fmt.Errorf("%s: %w", RetentionMonthsEnv, err)
	}
	return months, nil
}

// ErrRetentionUnderInstall is returned when a tenant asks for a period
// shorter than the period of the install.
var ErrRetentionUnderInstall = errors.New("audit: the retention period of a tenant is shorter than the period of the install")

// queryRower is the one method of *sql.DB and *sql.Tx that periodOfTenant
// uses.
type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// tenantPeriodQuery reads the period that a tenant admin set.
const tenantPeriodQuery = `SELECT months FROM audit_retention_tenant WHERE tenant_id = $1`

// periodOfTenant returns the retention period of a tenant: the longer of the
// install period and the period that a tenant admin set (gibson#676).
func periodOfTenant(ctx context.Context, q queryRower, installMonths int, tenantID string) (int, error) {
	var months int
	switch err := q.QueryRowContext(ctx, tenantPeriodQuery, tenantID).Scan(&months); {
	case errors.Is(err, sql.ErrNoRows):
		return installMonths, nil
	case err != nil:
		return 0, fmt.Errorf("read the retention period of tenant %q: %w", tenantID, err)
	}
	return max(months, installMonths), nil
}

// RetentionSettings reads and sets the retention period of one tenant. A
// tenant admin can set a period longer than the period of the install. The
// settings refuse a shorter period.
type RetentionSettings struct {
	db            *sql.DB
	installMonths int
}

// RetentionPeriod is the retention period of one tenant.
type RetentionPeriod struct {
	// InstallMonths is the period of the install.
	InstallMonths int
	// TenantMonths is the period that a tenant admin set. Zero means that
	// the tenant uses the period of the install.
	TenantMonths int
	// EffectiveMonths is the period that retention uses: the longer of the
	// two.
	EffectiveMonths int
}

// NewRetentionSettings constructs RetentionSettings. installMonths is the
// period of the install, and it must not be under MinRetentionMonths.
func NewRetentionSettings(db *sql.DB, installMonths int) (*RetentionSettings, error) {
	if db == nil {
		return nil, errors.New("audit.NewRetentionSettings: db must not be nil")
	}
	if err := ValidateRetentionMonths(installMonths); err != nil {
		return nil, fmt.Errorf("audit.NewRetentionSettings: %w", err)
	}
	return &RetentionSettings{db: db, installMonths: installMonths}, nil
}

// Period returns the retention period of a tenant.
func (s *RetentionSettings) Period(ctx context.Context, tenantID string) (RetentionPeriod, error) {
	if tenantID == "" {
		return RetentionPeriod{}, errors.New("audit.RetentionSettings.Period: tenantID must not be empty")
	}
	var tenantMonths int
	switch err := s.db.QueryRowContext(ctx, tenantPeriodQuery, tenantID).Scan(&tenantMonths); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return RetentionPeriod{}, fmt.Errorf("audit.RetentionSettings.Period: tenant %q: %w", tenantID, err)
	}
	return RetentionPeriod{
		InstallMonths:   s.installMonths,
		TenantMonths:    tenantMonths,
		EffectiveMonths: max(tenantMonths, s.installMonths),
	}, nil
}

// SetTenantMonths sets the retention period of a tenant. Zero removes the
// setting, and the tenant then uses the period of the install. A period
// under the period of the install is refused with ErrRetentionUnderInstall.
func (s *RetentionSettings) SetTenantMonths(ctx context.Context, tenantID string, months int, updatedBy string) error {
	if tenantID == "" {
		return errors.New("audit.RetentionSettings.SetTenantMonths: tenantID must not be empty")
	}
	if months == 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_retention_tenant WHERE tenant_id = $1`, tenantID); err != nil {
			return fmt.Errorf("audit.RetentionSettings.SetTenantMonths: clear tenant %q: %w", tenantID, err)
		}
		return nil
	}
	if months < s.installMonths {
		return fmt.Errorf("%w: got %d months, the install keeps %d", ErrRetentionUnderInstall, months, s.installMonths)
	}
	if updatedBy == "" {
		return errors.New("audit.RetentionSettings.SetTenantMonths: updatedBy must not be empty")
	}
	const upsert = `
INSERT INTO audit_retention_tenant (tenant_id, months, updated_by, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (tenant_id) DO UPDATE
SET months = EXCLUDED.months, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`
	if _, err := s.db.ExecContext(ctx, upsert, tenantID, months, updatedBy); err != nil {
		return fmt.Errorf("audit.RetentionSettings.SetTenantMonths: tenant %q: %w", tenantID, err)
	}
	return nil
}

// Retention removes audit_log rows that are older than the retention period.
type Retention struct {
	db     *sql.DB
	months int
	logger *slog.Logger
	now    func() time.Time
}

// NewRetention constructs a Retention. months is the period of the install,
// and it must not be under MinRetentionMonths.
func NewRetention(db *sql.DB, months int, logger *slog.Logger) (*Retention, error) {
	if db == nil {
		return nil, errors.New("audit.NewRetention: db must not be nil")
	}
	if logger == nil {
		return nil, errors.New("audit.NewRetention: logger must not be nil")
	}
	if err := ValidateRetentionMonths(months); err != nil {
		return nil, fmt.Errorf("audit.NewRetention: %w", err)
	}
	return &Retention{
		db:     db,
		months: months,
		logger: logger.With("component", "audit.retention"),
		now:    time.Now,
	}, nil
}

// Run prunes each tenant now, and then one time for each interval, until
// ctx is cancelled. A run that fails is logged and counted. The next run
// tries again.
func (r *Retention) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRetentionInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if removed, err := r.Prune(ctx); err != nil {
			r.logger.ErrorContext(ctx, "audit: retention run failed", slog.String("error", err.Error()))
		} else if removed > 0 {
			r.logger.InfoContext(ctx, "audit: retention removed old records", slog.Int64("rows", removed))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// Prune removes the rows of each tenant that are older than the retention
// period. It returns the number of rows that it removed. When
// one tenant fails, Prune goes on with the next tenant and returns the
// joined errors.
func (r *Retention) Prune(ctx context.Context) (int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM audit_log ORDER BY tenant_id`)
	if err != nil {
		auditRetentionErrorsTotal.Inc()
		return 0, fmt.Errorf("audit.Retention.Prune: list tenants: %w", err)
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			_ = rows.Close()
			auditRetentionErrorsTotal.Inc()
			return 0, fmt.Errorf("audit.Retention.Prune: scan tenant: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Close(); err != nil {
		auditRetentionErrorsTotal.Inc()
		return 0, fmt.Errorf("audit.Retention.Prune: close tenant list: %w", err)
	}
	if err := rows.Err(); err != nil {
		auditRetentionErrorsTotal.Inc()
		return 0, fmt.Errorf("audit.Retention.Prune: list tenants: %w", err)
	}

	var (
		total int64
		errs  []error
	)
	for _, tenant := range tenants {
		removed, err := r.PruneTenant(ctx, tenant)
		if err != nil {
			auditRetentionErrorsTotal.Inc()
			errs = append(errs, err)
			continue
		}
		total += removed
	}
	return total, errors.Join(errs...)
}

// PruneTenant removes the rows of one tenant that are older than the
// retention period, and returns the number of rows that it removed.
//
// It holds the chain lock of the tenant, so no writer extends the chain
// during the run. From the chain it removes only a run of rows from the
// start: each row before the oldest row that is inside the period. A row
// inside the period is never removed. It then moves the chain anchor to the
// oldest row that remains.
func (r *Retention) PruneTenant(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, errors.New("audit.Retention.PruneTenant: tenantID must not be empty")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("audit.Retention.PruneTenant: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, tenantAdvisoryKey(tenantID)); err != nil {
		return 0, fmt.Errorf("audit.Retention.PruneTenant: lock chain for tenant %q: %w", tenantID, err)
	}

	months, err := periodOfTenant(ctx, tx, r.months, tenantID)
	if err != nil {
		return 0, fmt.Errorf("audit.Retention.PruneTenant: %w", err)
	}
	now := r.now().UTC()
	cutoff := now.AddDate(0, -months, 0)

	// The last chained row that retention removes: the row with the highest
	// position among the rows before the oldest row inside the period. With
	// no row inside the period, it is the chain head. A row that the export
	// did not write to the durable bucket stays (ADR-0113, gibson#764): the
	// position never passes exported_seq of the tenant.
	const lastOldQuery = `
SELECT chain_seq, entry_hash
FROM   audit_log
WHERE  tenant_id = $1
  AND  chain_seq IS NOT NULL
  AND  chain_seq < COALESCE(
         (SELECT MIN(chain_seq) FROM audit_log
          WHERE tenant_id = $1 AND chain_seq IS NOT NULL AND created_at >= $2),
         9223372036854775807)
  AND  chain_seq <= COALESCE(
         (SELECT exported_seq FROM audit_export_cursor WHERE tenant_id = $1), 0)
ORDER  BY chain_seq DESC
LIMIT  1`

	var (
		lastSeq  int64
		lastHash []byte
		removed  int64
	)
	switch scanErr := tx.QueryRowContext(ctx, lastOldQuery, tenantID, cutoff).Scan(&lastSeq, &lastHash); {
	case errors.Is(scanErr, sql.ErrNoRows):
		// No chained row is old enough.
	case scanErr != nil:
		return 0, fmt.Errorf("audit.Retention.PruneTenant: find the rows to remove for tenant %q: %w", tenantID, scanErr)
	default:
		if len(lastHash) != chainHashLen {
			return 0, fmt.Errorf(
				"audit.Retention.PruneTenant: row %d of tenant %q has a %d-byte entry_hash, refusing to anchor a corrupt chain",
				lastSeq, tenantID, len(lastHash))
		}
		const anchor = `
INSERT INTO audit_chain_anchor (tenant_id, first_seq, prev_hash, pruned_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id) DO UPDATE
SET first_seq = EXCLUDED.first_seq, prev_hash = EXCLUDED.prev_hash, pruned_at = EXCLUDED.pruned_at`
		if _, err := tx.ExecContext(ctx, anchor, tenantID, lastSeq+1, lastHash, now); err != nil {
			return 0, fmt.Errorf("audit.Retention.PruneTenant: write chain anchor for tenant %q: %w", tenantID, err)
		}
		res, err := tx.ExecContext(ctx,
			`DELETE FROM audit_log WHERE tenant_id = $1 AND chain_seq IS NOT NULL AND chain_seq <= $2`,
			tenantID, lastSeq)
		if err != nil {
			return 0, fmt.Errorf("audit.Retention.PruneTenant: remove chained rows of tenant %q: %w", tenantID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("audit.Retention.PruneTenant: count removed rows of tenant %q: %w", tenantID, err)
		}
		removed += n
	}

	// A row from before the chain migration has no position, so the export
	// never writes it, and retention keeps it. An install made after
	// migration 022 has no such row.

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit.Retention.PruneTenant: commit for tenant %q: %w", tenantID, err)
	}
	committed = true
	return removed, nil
}
