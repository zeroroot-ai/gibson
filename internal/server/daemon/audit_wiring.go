// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
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
// (hosted#206). The same logger serves the component service, so the stream
// has one writer per process.
//
// Until this existed the daemon built an audit logger for the component
// service only and never called WithAuditLogger, so every MFA reset skipped
// its record in production while the unit tests, which set the field
// themselves, stayed green.
//
// A daemon with no state client has no audit stream, and returns nil: the
// service then refuses the RPCs that need the record instead of pretending.
func wireDaemonAudit(ctx context.Context, sc *state.StateClient, logger *slog.Logger, svc auditSink) *audit.AuditLogger {
	if sc == nil {
		logger.WarnContext(ctx, "no state client: the audit log is not wired, and the RPCs that require a record refuse")
		return nil
	}
	al := audit.NewAuditLogger(ctx, sc, logger)
	svc.WithAuditLogger(al)
	logger.InfoContext(ctx, "audit logger wired into DaemonServer")
	return al
}
