// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/sdk/auth"
)

type refusingDurable struct{ audittest.Recorder }

func (*refusingDurable) WriteSync(context.Context, audit.Event) error {
	return errors.New("audit database down")
}

func auditLogger(t *testing.T, durable audit.DurableWriter) *audit.AuditLogger {
	t.Helper()
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
	return audit.NewAuditLogger(ctx, sc, durable, slog.New(slog.DiscardHandler))
}

func actorCtx(t *testing.T) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithIdentity(auth.ContextWithTenantString(context.Background(), "acme"),
		auth.Identity{Subject: "agent_principal:1", Tenant: tid, CredentialType: auth.CredentialCapabilityGrant})
}

func TestAuditRecorder_WritesIntentAndResult(t *testing.T) {
	rec := &audittest.Recorder{}
	a := AuditRecorder{Log: auditLogger(t, rec)}
	call := CallRecord{Connector: "gitlab", Tool: "get_project", WorkID: "w1", MissionID: "m1"}

	if err := a.Intent(actorCtx(t), call); err != nil {
		t.Fatalf("Intent: %v", err)
	}
	if err := a.Result(actorCtx(t), call, nil); err != nil {
		t.Fatalf("Result: %v", err)
	}
	if err := a.Result(actorCtx(t), call, ErrBlocked); err != nil {
		t.Fatalf("Result with an error: %v", err)
	}
	events := rec.Events()
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	var m struct {
		Result  string         `json:"result"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(events[2].Metadata, &m); err != nil {
		t.Fatal(err)
	}
	if m.Result != "failure" || m.Details["error"] != "blocked" || m.Details["mission_id"] != "m1" || m.Details["work_id"] != "w1" {
		t.Errorf("last record = %+v", m)
	}
}

func TestAuditRecorder_Refusals(t *testing.T) {
	call := CallRecord{Connector: "gitlab", Tool: "x"}
	if err := (AuditRecorder{}).Intent(context.Background(), call); err == nil {
		t.Error("no logger: Intent must fail")
	}
	if err := (AuditRecorder{}).Result(context.Background(), call, nil); err == nil {
		t.Error("no logger: Result must fail")
	}
	a := AuditRecorder{Log: auditLogger(t, &refusingDurable{})}
	if err := a.Intent(actorCtx(t), call); err == nil {
		t.Error("a durable write that fails: Intent must fail")
	}
	if err := a.Result(actorCtx(t), call, nil); err == nil {
		t.Error("a durable write that fails: Result must fail")
	}
	// No actor on the context is a refusal too.
	if err := (AuditRecorder{Log: auditLogger(t, &audittest.Recorder{})}).Intent(context.Background(), call); err == nil {
		t.Error("a context with no actor: Intent must fail")
	}
}

func TestErrorClass(t *testing.T) {
	for err, want := range map[error]string{ErrUnauthorized: "unauthorized", ErrBlocked: "blocked", errors.New("x"): "failed"} {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q, want %q", err, got, want)
		}
	}
}
