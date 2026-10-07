// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/sdk/auth"
)

// The archive pool opens a tenant through the lazy data-plane pool, and
// reports the pool that is not there yet.
func TestArchivePool_ReportsNoPool(t *testing.T) {
	p := archivePool{lazy: lazyTimelinePool{pool: func() timelinePoolForer { return nil }}}
	if _, err := p.For(context.Background(), archiveTenant(t, "acme")); !errors.Is(err, errNoDataPool) {
		t.Fatalf("For with no pool: %v", err)
	}
}

// The archive starts with the retention period of the install and the
// bucket of the audit export. A bad value stops the daemon.
func TestStartTimelineArchive(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	pool := func() timelinePoolForer { return nil }
	newDB := func(t *testing.T) *sqlmockDB {
		t.Helper()
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		mock.MatchExpectationsInOrder(false)
		return &sqlmockDB{DB: db, mock: mock}
	}
	t.Setenv(audit.RetentionMonthsEnv, "")
	t.Setenv(audit.ExportBucketEnv, "")

	t.Run("the platform database is required", func(t *testing.T) {
		err := startTimelineArchive(context.Background(), nil, pool, logger)
		if err == nil || !strings.Contains(err.Error(), "platform database") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a bad retention period is refused", func(t *testing.T) {
		t.Setenv(audit.RetentionMonthsEnv, "x")
		if err := startTimelineArchive(context.Background(), newDB(t).DB, pool, logger); err == nil {
			t.Fatal("a period that is not a number must stop the daemon")
		}
	})
	t.Run("a bad export config is refused", func(t *testing.T) {
		t.Setenv(audit.ExportBucketEnv, "bucket")
		t.Setenv(audit.ExportEndpointEnv, "")
		err := startTimelineArchive(context.Background(), newDB(t).DB, pool, logger)
		if err == nil || !strings.Contains(err.Error(), "timeline archive config") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a bucket starts the archive with the export", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		t.Setenv(audit.ExportBucketEnv, "bucket")
		t.Setenv(audit.ExportEndpointEnv, "http://127.0.0.1:1")
		t.Setenv(audit.ExportAccessKeyEnv, "k")
		t.Setenv(audit.ExportSecretKeyEnv, "s")
		t.Setenv(audit.ExportLockModeEnv, "governance")
		t.Setenv(audit.ExportLockDaysEnv, "400")
		db := newDB(t)
		db.mock.ExpectQuery("SELECT tenant_id").WillReturnError(errors.New("not in this test"))
		if err := startTimelineArchive(ctx, db.DB, pool, logger); err != nil {
			t.Fatalf("startTimelineArchive: %v", err)
		}
	})
	t.Run("no bucket starts the archive with no export", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		db := newDB(t)
		db.mock.ExpectQuery("SELECT tenant_id").WillReturnError(errors.New("not in this test"))
		if err := startTimelineArchive(ctx, db.DB, pool, logger); err != nil {
			t.Fatalf("startTimelineArchive: %v", err)
		}
	})
}

type sqlmockDB struct {
	DB   *sql.DB
	mock sqlmock.Sqlmock
}

func archiveTenant(t *testing.T, id string) auth.TenantID {
	t.Helper()
	tenant, err := auth.NewTenantID(id)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}
