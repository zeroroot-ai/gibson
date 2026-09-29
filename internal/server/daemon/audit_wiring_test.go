// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

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
	al := wireDaemonAudit(ctx, sc, slog.Default(), sink)
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
	sink := &recordingAuditSink{}
	if al := wireDaemonAudit(context.Background(), nil, slog.Default(), sink); al != nil {
		t.Fatal("expected no logger without a state client")
	}
	if sink.got != nil {
		t.Fatal("the service must not receive a logger without a state client")
	}
}
