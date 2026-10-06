// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

var errAuditDown = errors.New("audit store down")

// A state change whose audit record cannot be written does not happen, and
// the caller gets Unavailable (gibson#676).
func TestCreateAgentIdentity_NoRecordNoIdentity(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.CreateAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.CreateAgentIdentityRequest{Name: "my-agent", Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if len(fakeidp.deleteCalls) != 1 {
		t.Errorf("the service account was not rolled back: %d delete calls", len(fakeidp.deleteCalls))
	}
}

func TestRevokeAgentIdentity_NoRecordNoRevoke(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithAuthorizer(az).
		WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.RevokeAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.RevokeAgentIdentityRequest{PrincipalId: "agent_principal:some-uuid"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("the identity was revoked with no record: %d delete calls", len(fakeidp.deleteCalls))
	}
}

func TestRewindMission_NoRecordNoRun(t *testing.T) {
	started := false
	srv := NewDaemonServer(&mockDaemon{
		rewindMissionFn: func(context.Context, RewindRequest) (string, error) {
			started = true
			return "m-2", nil
		},
	}, nil, nil)
	srv.WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.RewindMission(missionViewerCtx(), &daemonpb.RewindMissionRequest{MissionId: "m-1", CheckpointId: "scan"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if started {
		t.Error("a run started with no record")
	}
}

// failingDurable is a durable audit writer that refuses each write.
type failingDurable struct{}

func (failingDurable) Log(audit.Event)                              {}
func (failingDurable) WriteSync(context.Context, audit.Event) error { return errAuditDown }

// auditLoggerOver is an AuditLogger over miniredis whose durable writer is d.
func auditLoggerOver(t *testing.T, d audit.DurableWriter) *audit.AuditLogger {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return audit.NewAuditLogger(ctx, sc, d, slog.Default())
}

// Each provider change writes its record first. With no durable record the
// store is not called, and a store failure gets a failure record.
func TestProviderChanges_WriteTheirRecordFirst(t *testing.T) {
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")
	input := &tenantv1.ProviderConfigInput{Name: "p1", Type: "openai", DefaultModel: "gpt-4o-mini", Credentials: map[string]string{"api_key": "k"}}

	rec := &audittest.Recorder{}
	store := &mockProviderStore{createOut: fakeProviderRecord("p1"), getOut: fakeProviderRecord("p1")}
	srv := serverWithStore(t, store)
	srv.auditLogger = auditLoggerOver(t, rec)
	if _, err := srv.CreateProvider(ctx, &tenantv1.CreateProviderRequest{Input: input}); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if _, err := srv.DeleteProvider(ctx, &tenantv1.DeleteProviderRequest{Name: "p1"}); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := srv.SetDefaultProvider(ctx, &tenantv1.SetDefaultProviderRequest{Name: "p1"}); err != nil {
		t.Fatalf("SetDefaultProvider: %v", err)
	}
	if n := len(rec.Events()); n != 3 {
		t.Errorf("durable records = %d, want 3", n)
	}

	downStore := &mockProviderStore{}
	down := serverWithStore(t, downStore)
	down.auditLogger = auditLoggerOver(t, failingDurable{})
	for name, call := range map[string]func() error{
		"create": func() error {
			_, err := down.CreateProvider(ctx, &tenantv1.CreateProviderRequest{Input: input})
			return err
		},
		"update": func() error {
			_, err := down.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{Name: "p1", Input: input})
			return err
		},
		"delete": func() error {
			_, err := down.DeleteProvider(ctx, &tenantv1.DeleteProviderRequest{Name: "p1"})
			return err
		},
		"set default": func() error {
			_, err := down.SetDefaultProvider(ctx, &tenantv1.SetDefaultProviderRequest{Name: "p1"})
			return err
		},
	} {
		if status.Code(call()) != codes.Unavailable {
			t.Errorf("%s with no record: want Unavailable", name)
		}
	}
	if downStore.capturedCreateInput != nil || downStore.capturedDeleteName != "" || downStore.capturedDefaultName != "" || downStore.capturedUpdateName != "" {
		t.Error("the store was called with no audit record")
	}

	failing := serverWithStore(t, &mockProviderStore{
		createErr: errAuditDown, deleteErr: errAuditDown, updateErr: errAuditDown, setDefErr: errAuditDown,
	})
	failing.auditLogger = auditLoggerOver(t, &audittest.Recorder{})
	_, _ = failing.CreateProvider(ctx, &tenantv1.CreateProviderRequest{Input: input})
	_, _ = failing.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{Name: "p1", Input: input})
	_, _ = failing.DeleteProvider(ctx, &tenantv1.DeleteProviderRequest{Name: "p1"})
	_, _ = failing.SetDefaultProvider(ctx, &tenantv1.SetDefaultProviderRequest{Name: "p1"})
}

// operatorCtx is the identity of the tenant-operator on the SPIFFE path.
func operatorCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "spiffe://zeroroot.ai/platform/tenant-operator", Issuer: "spiffe"})
}

// stepEvent is one record that the tenant-operator writes before a saga step.
func stepEvent() *daemonoperatorv1.AuditEventMessage {
	return &daemonoperatorv1.AuditEventMessage{
		Type:       "operator.saga_step",
		TenantId:   "acme",
		TargetType: "tenant",
		TargetId:   "acme",
		Fields:     map[string]string{"step": "InitRedisKeyspace"},
	}
}

// An operator event that cannot be written durably is Unavailable.
func TestEmitAuditEvent_NoRecordIsUnavailable(t *testing.T) {
	srv := blankServer()
	srv.auditLogger = auditLoggerOver(t, failingDurable{})
	_, err := srv.EmitAuditEvent(operatorCtx(), &daemonoperatorv1.EmitAuditEventRequest{Event: stepEvent()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
}

// The record of an operator change belongs to the tenant of the target, and
// its actor is the identity of the caller (gibson#583).
func TestEmitAuditEvent_RecordsTheCallerForTheTenant(t *testing.T) {
	rec := &audittest.Recorder{}
	srv := blankServer()
	srv.auditLogger = auditLoggerOver(t, rec)
	if _, err := srv.EmitAuditEvent(operatorCtx(), &daemonoperatorv1.EmitAuditEventRequest{Event: stepEvent()}); err != nil {
		t.Fatalf("EmitAuditEvent: %v", err)
	}
	failed := stepEvent()
	failed.Result = "failure"
	failed.Reason = "redis down"
	if _, err := srv.EmitAuditEvent(operatorCtx(), &daemonoperatorv1.EmitAuditEventRequest{Event: failed}); err != nil {
		t.Fatalf("EmitAuditEvent (failure): %v", err)
	}
	got := rec.Events()
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}
	for _, ev := range got {
		if ev.TenantID != "acme" || ev.ActorID != "spiffe://zeroroot.ai/platform/tenant-operator" ||
			ev.Action != "operator.saga_step" || ev.TargetType != "tenant" || ev.TargetID != "acme" {
			t.Errorf("record = %+v", ev)
		}
	}
	if !strings.Contains(string(got[0].Metadata), `"result":"success"`) ||
		!strings.Contains(string(got[1].Metadata), `"result":"failure"`) ||
		!strings.Contains(string(got[1].Metadata), `"reason":"redis down"`) {
		t.Errorf("metadata = %s / %s", got[0].Metadata, got[1].Metadata)
	}
}

// A user or an agent cannot write an operator record, and a record with no
// tenant or no target is refused.
func TestEmitAuditEvent_RefusesUsersAndIncompleteEvents(t *testing.T) {
	srv := blankServer()
	srv.auditLogger = auditLoggerOver(t, &audittest.Recorder{})
	userCtx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "user-1", Issuer: "zitadel"})
	if _, err := srv.EmitAuditEvent(userCtx, &daemonoperatorv1.EmitAuditEventRequest{Event: stepEvent()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("user: code = %v, want PermissionDenied", status.Code(err))
	}
	for name, mutate := range map[string]func(*daemonoperatorv1.AuditEventMessage){
		"no tenant":  func(e *daemonoperatorv1.AuditEventMessage) { e.TenantId = "" },
		"no target":  func(e *daemonoperatorv1.AuditEventMessage) { e.TargetId = "" },
		"bad result": func(e *daemonoperatorv1.AuditEventMessage) { e.Result = "success" },
		"no type":    func(e *daemonoperatorv1.AuditEventMessage) { e.Type = "" },
	} {
		ev := stepEvent()
		mutate(ev)
		if _, err := srv.EmitAuditEvent(operatorCtx(), &daemonoperatorv1.EmitAuditEventRequest{Event: ev}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, status.Code(err))
		}
	}
}

// An approval with no durable record returns the registration to the queue,
// and a rejection with no record fails the call.
func TestRegistrationDecisions_NoRecord(t *testing.T) {
	h, aw := newApprovalHarness(t)
	reg, err := h.srv.Register(context.Background(), registerRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	aw.syncErr = errAuditDown
	_, err = h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("approve code = %v, want Unavailable", status.Code(err))
	}
	if len(h.store.releaseCalls) != 1 || len(h.idp.reactivated) != 0 {
		t.Fatalf("release calls %v, reactivated %v: want the claim back and no owner", h.store.releaseCalls, h.idp.reactivated)
	}
	_, err = h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{RegistrationId: reg.GetRegistrationId(), Reason: "x"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("reject code = %v, want Unavailable", status.Code(err))
	}
}

// A failed approval after its record gets a second record with deny.
func TestAdminApproveRegistration_FailureIsRecorded(t *testing.T) {
	h, aw := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.idp.reactivateErr = errAuditDown
	_, _ = h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()})
	var deny bool
	for _, ev := range aw.events {
		if ev.Action == "signup_registration.approved" && ev.Decision == "deny" {
			deny = true
		}
	}
	if !deny {
		t.Errorf("events = %+v, want a deny record of the failed approval", aw.events)
	}
}
