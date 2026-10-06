// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/timelinearchive"
	"github.com/zeroroot-ai/sdk/auth"
)

// archivePool opens a tenant connection for the Timeline archive. It reads
// the data-plane pool at each call, because the pool starts after the gRPC
// server is built.
type archivePool struct {
	lazy lazyTimelinePool
}

func (p archivePool) For(ctx context.Context, tenant auth.TenantID) (timelinearchive.TenantDB, error) {
	conn, err := p.lazy.For(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// startTimelineArchive starts the export and the retention of the Timeline
// history of each tenant (ADR-0163 decision 4, gibson#992). Retention follows
// the audit log: the same durable bucket, the same object lock, and the same
// period, the audit retention period of the tenant (the install period from
// GIBSON_AUDIT_RETENTION_MONTHS, or the longer period a tenant admin set). A
// bad config is an error, and the daemon does not start. With no bucket
// configured, nothing is exported, so retention removes no row.
func startTimelineArchive(ctx context.Context, db *sql.DB, pool func() timelinePoolForer, logger *slog.Logger) error {
	if db == nil {
		return errors.New("timeline archive: the platform database is required, it lists the tenants")
	}
	months, err := audit.RetentionMonthsFromEnv()
	if err != nil {
		return fmt.Errorf("timeline archive: %w", err)
	}
	var (
		store  audit.ObjectStore
		policy audit.ExportPolicy
	)
	cfg, err := audit.ExportConfigFromEnv()
	switch {
	case errors.Is(err, audit.ErrExportNotConfigured):
		logger.ErrorContext(ctx, "timeline archive: no durable bucket is configured; the Timeline history stays in Postgres and retention removes none",
			slog.String("variable", audit.ExportBucketEnv))
	case err != nil:
		return fmt.Errorf("timeline archive config: %w", err)
	default:
		s3, err := audit.NewS3Store(cfg)
		if err != nil {
			return fmt.Errorf("timeline archive store: %w", err)
		}
		store, policy = s3, cfg.Policy
	}
	periods, err := audit.NewRetentionSettings(db, months)
	if err != nil {
		return fmt.Errorf("timeline archive: %w", err)
	}
	archive, err := timelinearchive.New(db, archivePool{lazy: lazyTimelinePool{pool: pool}}, periods, store, policy, logger)
	if err != nil {
		return fmt.Errorf("timeline archive: %w", err)
	}
	go archive.Run(ctx, timelinearchive.DefaultInterval)
	logger.InfoContext(ctx, "timeline archive started", slog.Int("install_months", months), slog.Bool("export", store != nil))
	return nil
}
