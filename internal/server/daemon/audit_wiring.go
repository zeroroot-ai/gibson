// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// auditSink is the one method of api.DaemonServer the audit wiring needs.
type auditSink interface {
	WithAuditLogger(*audit.AuditLogger) *api.DaemonServer
}

// wireDaemonAudit builds the daemon's one audit logger and hands it to the
// daemon service. The audit log is a required record for the tenant-admin
// RPCs that change who can sign in: ResetUserMFA refuses to run without it
// (hosted#206). The same logger serves the component service.
//
// The logger hands each record to a writer on the platform database.
// Postgres audit_log is the durable copy, and the Redis stream is the live
// tail for the console.
//
// It also starts the export of each record to the durable bucket, and audit
// retention on the platform database. The period comes
// from GIBSON_AUDIT_RETENTION_MONTHS. A period under 13 months is an error,
// and the daemon does not start.
//
// The state client is required: it carries the live tail, and the daemon
// does not start without it.
func wireDaemonAudit(
	ctx context.Context,
	sc *state.StateClient,
	db *sql.DB,
	logger *slog.Logger,
	svc auditSink,
) (*audit.AuditLogger, error) {
	if db == nil {
		return nil, errors.New("audit wiring: the platform database is required, it holds the audit log")
	}
	months, err := audit.RetentionMonthsFromEnv()
	if err != nil {
		return nil, fmt.Errorf("audit wiring: %w", err)
	}
	retention, err := audit.NewRetention(db, months, logger)
	if err != nil {
		return nil, fmt.Errorf("audit wiring: %w", err)
	}
	go retention.Run(ctx, audit.DefaultRetentionInterval)
	logger.InfoContext(ctx, "audit retention started", slog.Int("months", months))

	if err := startAuditExport(ctx, db, logger); err != nil {
		return nil, fmt.Errorf("audit wiring: %w", err)
	}

	if sc == nil {
		return nil, errors.New("audit wiring: the state client is required, it carries the live tail of the audit log")
	}
	al := audit.NewAuditLogger(ctx, sc, newStartedAuditWriter(ctx, db, logger), logger)
	svc.WithAuditLogger(al)
	logger.InfoContext(ctx, "audit logger wired into DaemonServer")
	return al, nil
}

// newStartedAuditWriter returns a running writer for the Postgres audit_log
// table. It stops when ctx ends, after it wrote its queue.
func newStartedAuditWriter(ctx context.Context, db *sql.DB, logger *slog.Logger) *audit.Writer {
	w := audit.NewWriter(db, logger)
	w.Start(ctx)
	return w
}

// startAuditExport starts the export of the audit log to the durable bucket
// (ADR-0113, gibson#764). A bad export config is an error, and the daemon
// does not start. With no bucket configured, the daemon starts, logs an
// error, and measures the export lag: no record is exported, retention
// removes no record, and the lag alert fires.
func startAuditExport(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	cfg, err := audit.ExportConfigFromEnv()
	if errors.Is(err, audit.ErrExportNotConfigured) {
		logger.ErrorContext(ctx, "audit export: no durable bucket is configured; records stay in Postgres and retention removes none",
			slog.String("variable", audit.ExportBucketEnv))
		go audit.MeasureExportLag(ctx, db, audit.DefaultExportInterval, logger)
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit export config: %w", err)
	}
	store, err := audit.NewS3Store(cfg)
	if err != nil {
		return fmt.Errorf("audit export store: %w", err)
	}
	exporter, err := audit.NewExporter(db, store, cfg.Policy, logger)
	if err != nil {
		return fmt.Errorf("audit exporter: %w", err)
	}
	go exporter.Run(ctx, audit.DefaultExportInterval)
	logger.InfoContext(ctx, "audit export started",
		slog.String("bucket", cfg.Bucket), slog.String("lock_mode", cfg.Policy.LockMode), slog.Int("lock_days", cfg.Policy.LockDays))
	return nil
}
