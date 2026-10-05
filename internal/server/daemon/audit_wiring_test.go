// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

type recordingAuditSink struct{ got *audit.AuditLogger }

func (r *recordingAuditSink) WithAuditLogger(al *audit.AuditLogger) *api.DaemonServer {
	r.got = al
	return nil
}

// auditWiringDB returns a database handle for the wiring tests. Retention
// runs one time at start, and the mock refuses its query. The wiring logs
// that failure and goes on, which is the rule for a failed retention run.
func auditWiringDB(t *testing.T) *sql.DB {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestWireDaemonAudit_HandsOneLoggerToTheService: with a state client the
// service receives the logger that is returned, so the daemon and component
// services share one writer (hosted#206).
func TestWireDaemonAudit_HandsOneLoggerToTheService(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatalf("state client: %v", err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sink := &recordingAuditSink{}
	al, err := wireDaemonAudit(ctx, sc, auditWiringDB(t), slog.Default(), sink)
	if err != nil {
		t.Fatalf("wireDaemonAudit: %v", err)
	}
	if al == nil {
		t.Fatal("expected a logger with a state client")
	}
	if sink.got != al {
		t.Fatalf("the service must receive the same logger that is returned")
	}
}

// TestWireDaemonAudit_NoStateClientWiresNothing: no state client, no stream;
// the service is left without a logger so the RPCs that need one refuse.
func TestWireDaemonAudit_NoStateClientWiresNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sink := &recordingAuditSink{}
	al, err := wireDaemonAudit(ctx, nil, auditWiringDB(t), slog.Default(), sink)
	if err != nil {
		t.Fatalf("wireDaemonAudit: %v", err)
	}
	if al != nil {
		t.Fatal("expected no logger without a state client")
	}
	if sink.got != nil {
		t.Fatal("the service must not receive a logger without a state client")
	}
}

// TestWireDaemonAudit_RequiresThePlatformDatabase: Postgres holds the audit
// log, so the wiring refuses to run without it.
func TestWireDaemonAudit_RequiresThePlatformDatabase(t *testing.T) {
	if _, err := wireDaemonAudit(context.Background(), nil, nil, slog.Default(), &recordingAuditSink{}); err == nil {
		t.Fatal("expected an error with no platform database")
	}
}

// TestWireDaemonAudit_RefusesAShortRetentionPeriod: a period under 13 months
// stops the start of the daemon.
func TestWireDaemonAudit_RefusesAShortRetentionPeriod(t *testing.T) {
	t.Setenv(audit.RetentionMonthsEnv, "6")
	_, err := wireDaemonAudit(context.Background(), nil, auditWiringDB(t), slog.Default(), &recordingAuditSink{})
	if !errors.Is(err, audit.ErrRetentionTooShort) {
		t.Fatalf("err = %v, want ErrRetentionTooShort", err)
	}
}
