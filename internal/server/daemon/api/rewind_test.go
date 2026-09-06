// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — rewind_test.go covers the ResumeMission rewind path
// (target_checkpoint_id): the daemon-side RewindMission round trip, the
// mission#admin FGA gate, and the missing-target error mapping.
//
// The checkpoint-browser RPC tests that used to live alongside these in
// mission_handlers_test.go left with the handlers (gibson#1321, sdk#426);
// the retirement itself is asserted in checkpoint_rpcs_retired_test.go.
//
// Spec: mission-checkpointing R6.3-R6.6, R16.
package api

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const testViewerSubject = "u-viewer"

// missionViewerCtx returns a context carrying an authenticated identity for
// tenant "acme".
func missionViewerCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject: testViewerSubject,
		Tenant:  auth.MustNewTenantID("acme"),
	})
}

// missionViewerAuthz grants testViewerSubject the mission#viewer relation on
// each of the given mission IDs and nothing else.
func missionViewerAuthz(missionIDs ...string) *fakeAuthorizer {
	a := newFakeAuthorizer()
	for _, id := range missionIDs {
		a.allow("user:"+testViewerSubject, "viewer", "mission:"+id)
	}
	return a
}

// GHSA-v8j9: rewind is a WRITE path, so a nil (unconfigured) authorizer must
// fail closed with Unavailable — never fall through to allow.
func TestRequireMissionAdminForRewind_NilAuthorizerFailsClosed(t *testing.T) {
	srv := &DaemonServer{logger: testSlogLogger, authorizer: nil}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	err := srv.requireMissionAdminForRewind(ctx, "mission-1")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("nil authorizer must fail closed with Unavailable, got %v (code %s)", err, status.Code(err))
	}
}

func TestResumeMission_RewindGoesThroughDaemonRewindMission(t *testing.T) {
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-target"})
	// requireMissionAdminForRewind (server.go) checks
	// (user:<sub>, admin, mission:<id>) directly. In production the FGA model
	// cascades admin from tenant#admin; the fakeAuthorizer here does not
	// model that cascade, so the test seeds the resolved tuple explicitly.
	a := newFakeAuthorizer().
		allow("user:u-bob", "member", "tenant:acme").
		allow("user:u-bob", "admin", "tenant:acme").
		allow("user:u-bob", "admin", "mission:mission-1")
	w := newFakeAuditWriter()
	srv := &DaemonServer{
		daemon:                 d,
		logger:                 testSlogLogger,
		authorizer:             a,
		tenantAdminAuditWriter: w,
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-target",
	}, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := d.rewindRecorded()
	if len(calls) != 1 {
		t.Fatalf("expected 1 RewindMission call, got %d", len(calls))
	}
	if calls[0].TargetID != "cp-target" {
		t.Errorf("expected RewindMission target=cp-target, got %q", calls[0].TargetID)
	}

	events := w.recorded()
	foundRewind := false
	for _, e := range events {
		if e.Action == "mission.rewind.completed" {
			foundRewind = true
			if !bytes.Contains(e.Metadata, []byte("cp-target")) {
				t.Errorf("rewind audit metadata should contain target id: %s", e.Metadata)
			}
		}
	}
	if !foundRewind {
		t.Errorf("expected mission.rewind.completed audit event")
	}
}

func TestResumeMission_RewindRequiresAdmin(t *testing.T) {
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-target"})
	// Member only — admin denied.
	a := newFakeAuthorizer().allow("user:u-bob", "member", "tenant:acme")
	srv := &DaemonServer{daemon: d, logger: testSlogLogger, authorizer: a}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-target",
	}, stream)
	if err == nil {
		t.Fatal("expected PermissionDenied for non-admin caller")
	}
	if grpcCode(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v (err=%v)", grpcCode(err), err)
	}
	if len(d.rewindRecorded()) != 0 {
		t.Errorf("expected no RewindMission calls when permission denied")
	}
}

func TestResumeMission_RewindNotFoundTarget(t *testing.T) {
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-1"})
	// The caller is a legitimate mission admin — this test exercises the
	// missing-checkpoint path, not the authz gate.
	a := missionViewerAuthz("mission-1").
		allow("user:"+testViewerSubject, "admin", "mission:mission-1")
	srv := &DaemonServer{daemon: d, logger: testSlogLogger, authorizer: a}
	ctx := missionViewerCtx()
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-missing",
	}, stream)
	if grpcCode(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v (err=%v)", grpcCode(err), err)
	}
}

// rewindAdminServer wires a DaemonServer whose caller u-bob is a mission
// admin on mission-1, with an audit writer attached.
func rewindAdminServer(d *fakeDaemon) (*DaemonServer, *fakeAuditWriter, context.Context) {
	a := newFakeAuthorizer().
		allow("user:u-bob", "member", "tenant:acme").
		allow("user:u-bob", "admin", "tenant:acme").
		allow("user:u-bob", "admin", "mission:mission-1")
	w := newFakeAuditWriter()
	srv := &DaemonServer{
		daemon:                 d,
		logger:                 testSlogLogger,
		authorizer:             a,
		tenantAdminAuditWriter: w,
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	return srv, w, ctx
}

func TestResumeMission_RewindCancelsInFlightAtMostOnceTool(t *testing.T) {
	// The target checkpoint captured a tool in flight under AT_MOST_ONCE:
	// the dispatcher must decide skip_failed, emit the per-tool audit hint
	// through serverRewindEmitter, and let the resume proceed.
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{
		CheckpointID:        "cp-target",
		InFlightNodeID:      "node-scan",
		InFlightIdempotency: "AT_MOST_ONCE",
	})
	srv, w, ctx := rewindAdminServer(d)
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-target",
	}, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.rewindRecorded()) != 1 {
		t.Fatalf("expected 1 RewindMission call, got %d", len(d.rewindRecorded()))
	}

	var hint *audit.Event
	for _, e := range w.recorded() {
		if e.Action == "mission.rewind.tool_cancelled" {
			ev := e
			hint = &ev
		}
	}
	if hint == nil {
		t.Fatal("expected a mission.rewind.tool_cancelled audit hint for the in-flight tool")
	}
	if !bytes.Contains(hint.Metadata, []byte("node-scan")) {
		t.Errorf("audit hint should name the in-flight node: %s", hint.Metadata)
	}
	if !bytes.Contains(hint.Metadata, []byte("skip_failed")) {
		t.Errorf("AT_MOST_ONCE must dispatch as skip_failed: %s", hint.Metadata)
	}
}

func TestResumeMission_RewindExactlyOnceWithoutTokenFailsClosed(t *testing.T) {
	// EXACTLY_ONCE with no resumption token cannot be resumed safely: the
	// dispatcher demands FailMission and the RPC returns FailedPrecondition.
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{
		CheckpointID:        "cp-target",
		InFlightNodeID:      "node-payment",
		InFlightIdempotency: "EXACTLY_ONCE",
	})
	srv, _, ctx := rewindAdminServer(d)
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-target",
	}, stream)
	if grpcCode(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (err=%v)", grpcCode(err), err)
	}
}

// mockServerStreamForResume satisfies grpc.ServerStreamingServer[ResumeMissionResponse].
type mockServerStreamForResume struct {
	ctx    context.Context
	events []*daemonpb.ResumeMissionResponse
}

func (m *mockServerStreamForResume) Send(e *daemonpb.ResumeMissionResponse) error {
	m.events = append(m.events, e)
	return nil
}
func (m *mockServerStreamForResume) Context() context.Context       { return m.ctx }
func (m *mockServerStreamForResume) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockServerStreamForResume) SendHeader(_ metadata.MD) error { return nil }
func (m *mockServerStreamForResume) SetTrailer(_ metadata.MD)       {}
func (m *mockServerStreamForResume) SendMsg(_ interface{}) error    { return nil }
func (m *mockServerStreamForResume) RecvMsg(_ interface{}) error    { return nil }
