// Package api — mission_handlers_test.go covers the four
// mission-checkpointing RPC handlers (W4 task 18):
//
//   - ListCheckpoints   pagination, ordering, FGA gate
//   - GetCheckpoint     payload + redaction + audit emission
//   - DiffCheckpoints   byte-level walk + size limit
//   - ResumeMission     rewind path + admin FGA gate + audit emission
//
// Spec: mission-checkpointing R13/R14/R15/R16, week-4-handlers-ui-e2e §1.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ----- ListCheckpoints --------------------------------------------------------

func TestListCheckpoints_Pagination(t *testing.T) {
	d := newFakeDaemon()
	for i := 0; i < 75; i++ {
		d.withCheckpoint("mission-1", CheckpointData{
			CheckpointID: idForI(i),
			CreatedAt:    int64(1000 + i),
			Version:      i,
		})
	}
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	resp, err := srv.ListCheckpoints(ctx, &daemonpb.ListCheckpointsRequest{
		MissionId: "mission-1",
		PageSize:  50,
	})
	if err != nil {
		t.Fatalf("page 1: unexpected error: %v", err)
	}
	if len(resp.Checkpoints) != 50 {
		t.Errorf("page 1: expected 50 checkpoints, got %d", len(resp.Checkpoints))
	}
	if resp.NextPageToken == "" {
		t.Errorf("page 1: expected next_page_token to be non-empty")
	}
	if resp.TotalCount != 75 {
		t.Errorf("page 1: expected total_count=75, got %d", resp.TotalCount)
	}

	resp2, err := srv.ListCheckpoints(ctx, &daemonpb.ListCheckpointsRequest{
		MissionId: "mission-1",
		PageSize:  50,
		PageToken: resp.NextPageToken,
	})
	if err != nil {
		t.Fatalf("page 2: unexpected error: %v", err)
	}
	if len(resp2.Checkpoints) != 25 {
		t.Errorf("page 2: expected 25 checkpoints, got %d", len(resp2.Checkpoints))
	}
	if resp2.NextPageToken != "" {
		t.Errorf("page 2: expected empty next_page_token, got %q", resp2.NextPageToken)
	}
}

func TestListCheckpoints_RejectsEmptyMissionID(t *testing.T) {
	srv := &DaemonServer{daemon: newFakeDaemon(), logger: testSlogLogger}
	_, err := srv.ListCheckpoints(context.Background(), &daemonpb.ListCheckpointsRequest{})
	if err == nil {
		t.Fatal("expected error for empty mission_id")
	}
	if grpcCode(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", grpcCode(err))
	}
}

func TestListCheckpoints_FGAMember(t *testing.T) {
	// Authorizer wired but the caller is NOT a member of the tenant.
	a := newFakeAuthorizer() // no allow() calls — Check returns false
	srv := &DaemonServer{
		daemon:     newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-1"}),
		logger:     testSlogLogger,
		authorizer: a,
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	_, err := srv.ListCheckpoints(ctx, &daemonpb.ListCheckpointsRequest{MissionId: "mission-1"})
	if err == nil {
		t.Fatal("expected PermissionDenied for non-member")
	}
	if grpcCode(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", grpcCode(err))
	}
}

func TestListCheckpoints_SelfHeal_MissingBelongsTuple(t *testing.T) {
	// Caller is a tenant member but the mission has no belongs_to FGA tuple.
	// requireMissionViewer should self-heal by writing the tuple and allow.
	a := newFakeAuthorizer().
		allow("user:u-alice", "member", "tenant:acme")
	// Note: "viewer" on "mission:mission-1" is NOT pre-seeded — simulating
	// a mission created before CreateMission's belongs_to write was required.
	srv := &DaemonServer{
		daemon:     newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-1"}),
		logger:     testSlogLogger,
		authorizer: a,
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-alice",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	resp, err := srv.ListCheckpoints(ctx, &daemonpb.ListCheckpointsRequest{MissionId: "mission-1"})
	if err != nil {
		t.Fatalf("expected heal to allow access, got error: %v", err)
	}
	if len(resp.Checkpoints) != 1 {
		t.Errorf("expected 1 checkpoint after heal, got %d", len(resp.Checkpoints))
	}
}

// ----- GetCheckpoint ----------------------------------------------------------

func TestGetCheckpoint_HappyPath_ReturnsRichPayload(t *testing.T) {
	wm := mustJSON(map[string]any{"foo": "bar"})
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{
		CheckpointID:  "cp-1",
		CreatedAt:     1700000000,
		Version:       3,
		WorkingMemory: wm,
		DagSteps: []DagStepData{
			{NodeID: "n1", State: "completed"},
			{NodeID: "n2", State: "running"},
		},
	})
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	resp, err := srv.GetCheckpoint(ctx, &daemonpb.GetCheckpointRequest{
		MissionId:    "mission-1",
		CheckpointId: "cp-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Checkpoint == nil {
		t.Fatal("expected non-nil checkpoint")
	}
	if resp.Checkpoint.Summary.GetCheckpointId() != "cp-1" {
		t.Errorf("checkpoint_id mismatch: got %q", resp.Checkpoint.Summary.GetCheckpointId())
	}
	if !bytes.Equal(resp.Checkpoint.WorkingMemory, wm) {
		t.Errorf("working memory not round-tripped: got %s", resp.Checkpoint.WorkingMemory)
	}
	if len(resp.Checkpoint.Steps) != 2 {
		t.Errorf("expected 2 dag steps, got %d", len(resp.Checkpoint.Steps))
	}
}

func TestGetCheckpoint_RedactsSecretsForNonOperator(t *testing.T) {
	wm := mustJSON(map[string]any{
		"username": "alice",
		"password": "p@ssw0rd",
	})
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{
		CheckpointID:  "cp-1",
		WorkingMemory: wm,
	})
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	resp, err := srv.GetCheckpoint(ctx, &daemonpb.GetCheckpointRequest{
		MissionId:    "mission-1",
		CheckpointId: "cp-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// json.Marshal HTML-escapes < and >, so re-decode to verify structurally.
	var parsed map[string]any
	if err := json.Unmarshal(resp.Checkpoint.WorkingMemory, &parsed); err != nil {
		t.Fatalf("decoded WorkingMemory should parse: %v (raw: %s)", err, resp.Checkpoint.WorkingMemory)
	}
	if parsed["password"] != redactedPlaceholder {
		t.Errorf("password not redacted: %v", parsed["password"])
	}
	if parsed["username"] != "alice" {
		t.Errorf("non-secret field 'alice' was over-redacted: %v", parsed["username"])
	}
}

func TestGetCheckpoint_OperatorBypassesRedaction(t *testing.T) {
	wm := mustJSON(map[string]any{"password": "p@ssw0rd"})
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{
		CheckpointID:  "cp-1",
		WorkingMemory: wm,
	})
	// requireMissionViewer (mission_handlers.go) checks
	// (user:<sub>, viewer, mission:<id>) directly. In production the FGA model
	// cascades viewer from tenant#member; the fakeAuthorizer here does not
	// model that cascade, so the test seeds the resolved tuple explicitly.
	a := newFakeAuthorizer().
		allow("user:u-alice", "member", "tenant:acme").
		allow("user:u-alice", "viewer", "mission:mission-1").
		allow("user:u-alice", "platform_operator", "system_tenant:_system")
	srv := &DaemonServer{daemon: d, logger: testSlogLogger, authorizer: a}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-alice",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	resp, err := srv.GetCheckpoint(ctx, &daemonpb.GetCheckpointRequest{
		MissionId:    "mission-1",
		CheckpointId: "cp-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Checkpoint.WorkingMemory, &parsed); err != nil {
		t.Fatalf("WorkingMemory should parse as JSON: %v", err)
	}
	if parsed["password"] != "p@ssw0rd" {
		t.Errorf("operator should see plaintext password, got %v", parsed["password"])
	}
	if parsed["password"] == redactedPlaceholder {
		t.Errorf("operator should NOT see redaction placeholder")
	}
}

func TestGetCheckpoint_NotFound(t *testing.T) {
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-1"})
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := srv.GetCheckpoint(ctx, &daemonpb.GetCheckpointRequest{
		MissionId:    "mission-1",
		CheckpointId: "cp-missing",
	})
	if grpcCode(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v (err=%v)", grpcCode(err), err)
	}
}

func TestGetCheckpoint_EmitsAuditEvent(t *testing.T) {
	d := newFakeDaemon().withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-1"})
	w := newFakeAuditWriter()
	srv := &DaemonServer{
		daemon:                 d,
		logger:                 testSlogLogger,
		tenantAdminAuditWriter: w,
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u-bob",
		Tenant:  auth.MustNewTenantID("acme"),
	})
	if _, err := srv.GetCheckpoint(ctx, &daemonpb.GetCheckpointRequest{
		MissionId:    "mission-1",
		CheckpointId: "cp-1",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	events := w.recorded()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "checkpoint.read" {
		t.Errorf("expected action checkpoint.read, got %q", events[0].Action)
	}
	if events[0].TargetID != "cp-1" {
		t.Errorf("expected target_id cp-1, got %q", events[0].TargetID)
	}
}

// ----- DiffCheckpoints --------------------------------------------------------

func TestDiffCheckpoints_ByteLevelWalk(t *testing.T) {
	a := mustJSON(map[string]any{
		"shared_key": "before",
		"a_only":     "x",
	})
	b := mustJSON(map[string]any{
		"shared_key": "after",
		"b_only":     "y",
	})
	d := newFakeDaemon().
		withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-A", WorkingMemory: a}).
		withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-B", WorkingMemory: b})

	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.DiffCheckpoints(ctx, &daemonpb.DiffCheckpointsRequest{
		MissionId:     "mission-1",
		CheckpointAId: "cp-A",
		CheckpointBId: "cp-B",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deltas := resp.Diff.GetWorkingMemoryDeltas()
	if len(deltas) != 3 {
		t.Fatalf("expected 3 working memory deltas (changed/removed/added), got %d", len(deltas))
	}
	hasChanged, hasAdded, hasRemoved := false, false, false
	for _, d := range deltas {
		switch d.Key {
		case "shared_key":
			if d.Op != daemonpb.MemoryKeyDelta_OP_CHANGED {
				t.Errorf("shared_key should be CHANGED, got %v", d.Op)
			}
			hasChanged = true
		case "a_only":
			if d.Op != daemonpb.MemoryKeyDelta_OP_REMOVED {
				t.Errorf("a_only should be REMOVED, got %v", d.Op)
			}
			hasRemoved = true
		case "b_only":
			if d.Op != daemonpb.MemoryKeyDelta_OP_ADDED {
				t.Errorf("b_only should be ADDED, got %v", d.Op)
			}
			hasAdded = true
		}
	}
	if !hasChanged || !hasAdded || !hasRemoved {
		t.Errorf("missing expected delta types: changed=%v added=%v removed=%v",
			hasChanged, hasAdded, hasRemoved)
	}
}

func TestDiffCheckpoints_RedactsSecretKeys(t *testing.T) {
	a := mustJSON(map[string]any{"vault_token": "AAAA"})
	b := mustJSON(map[string]any{"vault_token": "BBBB"})
	d := newFakeDaemon().
		withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-A", WorkingMemory: a}).
		withCheckpoint("mission-1", CheckpointData{CheckpointID: "cp-B", WorkingMemory: b})

	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.DiffCheckpoints(ctx, &daemonpb.DiffCheckpointsRequest{
		MissionId:     "mission-1",
		CheckpointAId: "cp-A",
		CheckpointBId: "cp-B",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deltas := resp.Diff.GetWorkingMemoryDeltas()
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	d0 := deltas[0]
	if d0.Op != daemonpb.MemoryKeyDelta_OP_CHANGED {
		t.Errorf("expected OP_CHANGED, got %v", d0.Op)
	}
	// before/after are JSON byte payloads — decode and compare structurally.
	var beforeVal, afterVal string
	if err := json.Unmarshal(d0.Before, &beforeVal); err != nil {
		t.Fatalf("delta.Before should parse as JSON string: %v (raw: %s)", err, d0.Before)
	}
	if err := json.Unmarshal(d0.After, &afterVal); err != nil {
		t.Fatalf("delta.After should parse as JSON string: %v", err)
	}
	if beforeVal != redactedPlaceholder {
		t.Errorf("before not redacted: %q", beforeVal)
	}
	if afterVal != redactedPlaceholder {
		t.Errorf("after not redacted: %q", afterVal)
	}
}

func TestDiffCheckpoints_FindingDeltas(t *testing.T) {
	d := newFakeDaemon().
		withCheckpoint("mission-1", CheckpointData{
			CheckpointID: "cp-A",
			FindingSnapshots: []FindingSnapshotData{
				{FindingID: "f1", Severity: "high"},
			},
		}).
		withCheckpoint("mission-1", CheckpointData{
			CheckpointID: "cp-B",
			FindingSnapshots: []FindingSnapshotData{
				{FindingID: "f1", Severity: "high"},
				{FindingID: "f2", Severity: "medium"},
			},
		})
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.DiffCheckpoints(ctx, &daemonpb.DiffCheckpointsRequest{
		MissionId:     "mission-1",
		CheckpointAId: "cp-A",
		CheckpointBId: "cp-B",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deltas := resp.Diff.GetFindingDeltas()
	if len(deltas) != 1 {
		t.Fatalf("expected 1 finding delta (added f2), got %d", len(deltas))
	}
	if deltas[0].FindingId != "f2" || deltas[0].Op != daemonpb.FindingDelta_OP_ADDED {
		t.Errorf("expected ADDED f2, got id=%s op=%v", deltas[0].FindingId, deltas[0].Op)
	}
}

func TestDiffCheckpoints_DagStepDeltas(t *testing.T) {
	d := newFakeDaemon().
		withCheckpoint("mission-1", CheckpointData{
			CheckpointID: "cp-A",
			DagSteps:     []DagStepData{{NodeID: "n1", State: "running"}},
		}).
		withCheckpoint("mission-1", CheckpointData{
			CheckpointID: "cp-B",
			DagSteps:     []DagStepData{{NodeID: "n1", State: "completed"}},
		})
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.DiffCheckpoints(ctx, &daemonpb.DiffCheckpointsRequest{
		MissionId:     "mission-1",
		CheckpointAId: "cp-A",
		CheckpointBId: "cp-B",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deltas := resp.Diff.GetDagStepDeltas()
	if len(deltas) != 1 {
		t.Fatalf("expected 1 dag step delta, got %d", len(deltas))
	}
	if deltas[0].NodeId != "n1" || deltas[0].Op != daemonpb.DagStepDelta_OP_CHANGED {
		t.Errorf("expected CHANGED n1, got id=%s op=%v", deltas[0].NodeId, deltas[0].Op)
	}
}

// ----- ResumeMission rewind ---------------------------------------------------

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
	srv := &DaemonServer{daemon: d, logger: testSlogLogger}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	stream := &mockServerStreamForResume{ctx: ctx}
	err := srv.ResumeMission(&daemonpb.ResumeMissionRequest{
		MissionId:          "mission-1",
		TargetCheckpointId: "cp-missing",
	}, stream)
	if grpcCode(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v (err=%v)", grpcCode(err), err)
	}
}

// ----- helpers ----------------------------------------------------------------

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func idForI(i int) string {
	// Deterministic ascii ID for ListCheckpoints pagination tests.
	return "cp-" + strings.Repeat("0", 4-len(itoa(i))) + itoa(i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
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
