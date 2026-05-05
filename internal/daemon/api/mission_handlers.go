// Package api — daemon gRPC handlers for the four new mission-checkpointing
// RPCs introduced in v0.103.0:
//
//   - ListCheckpoints   mission-checkpointing R13
//   - GetCheckpoint     mission-checkpointing R14
//   - DiffCheckpoints   mission-checkpointing R15
//   - ResumeMission(target_checkpoint_id)  mission-checkpointing R16
//
// FGA enforcement is layered: ext-authz first checks the platform-wide
// `tenant#member` relation (per the registered registry annotations
// emitted by `make authz-registry`), and these handlers additionally
// enforce mission-scoped semantics via the daemon's authorizer when
// available. When the authorizer is not wired (dev / kind without FGA
// stack), tenant scoping via the per-tenant data-plane Pool is the
// safety net.
//
// Spec: mission-checkpointing R13/R14/R15/R16, week-4-handlers-ui-e2e
// §1 tasks 1-15.
package api

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zero-day-ai/gibson/internal/audit"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// listCheckpointsDefaultPageSize is the default page size used when the
// caller does not specify one. Caps at 200 (the proto contract ceiling).
const (
	listCheckpointsDefaultPageSize = 50
	listCheckpointsMaxPageSize     = 200
)

// diffSizeLimitBytes caps the wire size of a single DiffCheckpoints
// response. Beyond this, the server returns codes.ResourceExhausted with
// a hint to re-request both checkpoints individually and diff
// client-side.
const diffSizeLimitBytes = 10 * 1024 * 1024 // 10 MiB

// ListCheckpoints returns a paginated, RBAC-scoped list of checkpoints
// for the given mission.
//
// Backend: delegates to the existing daemon-layer `GetMissionCheckpoints`
// which already enforces per-tenant Pool access. Pagination is applied
// in-handler over the returned slice (the underlying store currently
// returns at most one checkpoint per mission until the per-super-step
// store wires up — see mission-checkpointing Phase 2A notes).
//
// Spec: mission-checkpointing R13.1, R13.2 (tenant scoping), R13.3, R13.4.
func (s *DaemonServer) ListCheckpoints(
	ctx context.Context,
	req *daemonpb.ListCheckpointsRequest,
) (*daemonpb.ListCheckpointsResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id is required")
	}

	if err := s.requireMissionViewer(ctx, req.GetMissionId(), "ListCheckpoints"); err != nil {
		return nil, err
	}

	// Pull checkpoints via the existing per-tenant data-plane path.
	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, req.GetMissionId())
	if err != nil {
		s.logger.Error("ListCheckpoints: backend lookup failed",
			"mission_id", req.GetMissionId(),
			"error", err,
		)
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "mission not found: %s", req.GetMissionId())
		}
		return nil, preserveStatus(err, "ListCheckpoints: backend lookup failed")
	}

	// Apply page-size policy.
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = listCheckpointsDefaultPageSize
	}
	if pageSize > listCheckpointsMaxPageSize {
		pageSize = listCheckpointsMaxPageSize
	}

	// page_token is an opaque offset into the slice. Bad token = restart.
	offset := parseListOffsetToken(req.GetPageToken())
	if offset > len(checkpoints) {
		offset = len(checkpoints)
	}
	end := offset + pageSize
	if end > len(checkpoints) {
		end = len(checkpoints)
	}

	// Order: descending by default (newest first). The Order enum landed
	// in v0.103.0 — explicit OLDEST_FIRST requests reverse the slice.
	if req.GetOrder() == daemonpb.ListCheckpointsRequest_ORDER_OLDEST_FIRST {
		// reverse copy
		reversed := make([]checkpointDataView, len(checkpoints))
		for i, cp := range checkpoints {
			reversed[len(checkpoints)-1-i] = toCheckpointDataView(cp)
		}
		summaries := buildCheckpointSummaries(reversed[offset:end], req.GetMissionId())
		nextToken := ""
		if end < len(reversed) {
			nextToken = formatListOffsetToken(end)
		}
		return &daemonpb.ListCheckpointsResponse{
			Checkpoints:   summaries,
			NextPageToken: nextToken,
			TotalCount:    int32(len(reversed)),
		}, nil
	}

	page := make([]checkpointDataView, 0, end-offset)
	for _, cp := range checkpoints[offset:end] {
		page = append(page, toCheckpointDataView(cp))
	}

	summaries := buildCheckpointSummaries(page, req.GetMissionId())
	nextToken := ""
	if end < len(checkpoints) {
		nextToken = formatListOffsetToken(end)
	}

	s.logger.Debug("ListCheckpoints: returning page",
		"mission_id", req.GetMissionId(),
		"offset", offset,
		"page_size", pageSize,
		"returned", len(summaries),
		"total", len(checkpoints),
	)

	return &daemonpb.ListCheckpointsResponse{
		Checkpoints:   summaries,
		NextPageToken: nextToken,
		TotalCount:    int32(len(checkpoints)),
	}, nil
}

// GetCheckpoint returns the full checkpoint payload for the given
// (mission, checkpoint) pair. Decryption + redaction are layered onto
// the existing checkpoint store path. Secret-bearing fields are
// replaced with the literal `<redacted:secret>` placeholder for non-
// platform-operator callers (R14.5).
//
// Spec: mission-checkpointing R14.1–R14.6.
func (s *DaemonServer) GetCheckpoint(
	ctx context.Context,
	req *daemonpb.GetCheckpointRequest,
) (*daemonpb.GetCheckpointResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id is required")
	}
	if req.GetCheckpointId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "checkpoint_id is required")
	}

	if err := s.requireMissionViewer(ctx, req.GetMissionId(), "GetCheckpoint"); err != nil {
		return nil, err
	}

	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, req.GetMissionId())
	if err != nil {
		s.logger.Error("GetCheckpoint: backend lookup failed",
			"mission_id", req.GetMissionId(),
			"checkpoint_id", req.GetCheckpointId(),
			"error", err,
		)
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "mission not found: %s", req.GetMissionId())
		}
		return nil, preserveStatus(err, "GetCheckpoint: backend lookup failed")
	}

	var found *checkpointDataView
	for _, cp := range checkpoints {
		if cp.CheckpointID == req.GetCheckpointId() {
			view := toCheckpointDataView(cp)
			found = &view
			break
		}
	}
	if found == nil {
		return nil, status_grpc.Errorf(codes.NotFound,
			"checkpoint %s not found for mission %s",
			req.GetCheckpointId(), req.GetMissionId())
	}

	summary := buildSingleCheckpointSummary(*found, req.GetMissionId())

	// Build the proto Checkpoint shell. Working_memory / mission_memory
	// remain nil here — the rich opaque-bytes path is wired up by the
	// per-super-step ThreadedCheckpointer in Phase 2A; this handler
	// surfaces the metadata-only shape that the dashboard's timeline
	// + side-panel expects for the legacy mission-level checkpoint.
	out := &daemonpb.Checkpoint{
		Summary: summary,
		// WorkingMemory / MissionMemory / Steps / Findings /
		// ParallelGroups stay zero-valued: the legacy mission.Checkpoint
		// does not surface those fields. The per-super-step store will
		// populate them once wired through Phase 2A's ThreadedCheckpointer.
	}

	// Audit emission (R14.6).
	s.emitCheckpointReadAudit(ctx, req.GetMissionId(), req.GetCheckpointId(), req.GetIncludeBlobs())

	return &daemonpb.GetCheckpointResponse{Checkpoint: out}, nil
}

// DiffCheckpoints returns structured deltas between two checkpoints of
// the same mission. Both checkpoints are loaded via the existing path,
// then walked field-by-field; only differing fields produce deltas.
// On overrun (>10 MiB serialized diff) the handler returns
// codes.ResourceExhausted with the canonical client-side-fallback hint.
//
// Spec: mission-checkpointing R15.1–R15.6.
func (s *DaemonServer) DiffCheckpoints(
	ctx context.Context,
	req *daemonpb.DiffCheckpointsRequest,
) (*daemonpb.DiffCheckpointsResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id is required")
	}
	if req.GetCheckpointAId() == "" || req.GetCheckpointBId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "both checkpoint_a_id and checkpoint_b_id are required")
	}

	if err := s.requireMissionViewer(ctx, req.GetMissionId(), "DiffCheckpoints"); err != nil {
		return nil, err
	}

	// Load both checkpoints via the existing mission-checkpoints path.
	// The loader is tenant-scoped through the daemon's per-tenant Pool.
	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, req.GetMissionId())
	if err != nil {
		return nil, preserveStatus(err, "DiffCheckpoints: backend lookup failed")
	}
	var a, b *checkpointDataView
	for _, cp := range checkpoints {
		switch cp.CheckpointID {
		case req.GetCheckpointAId():
			view := toCheckpointDataView(cp)
			a = &view
		case req.GetCheckpointBId():
			view := toCheckpointDataView(cp)
			b = &view
		}
	}
	if a == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointAId())
	}
	if b == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointBId())
	}

	// Walk the metadata-level fields and emit deltas only for changed
	// values. Working / mission memory deltas stay empty pending the
	// Phase 2A per-super-step bytes path — same reason GetCheckpoint
	// returns nil for those fields today.
	diff := &daemonpb.CheckpointDiff{}

	if a.CompletedNodes != b.CompletedNodes ||
		a.TotalNodes != b.TotalNodes ||
		a.FindingsCount != b.FindingsCount ||
		a.Version != b.Version {
		// Encode the metadata change as a single MemoryKeyDelta with key
		// "checkpoint:metadata" so the dashboard can render the
		// completedness drift at minimum.
		delta := &daemonpb.MemoryKeyDelta{
			Key:    "checkpoint:metadata",
			Op:     daemonpb.MemoryKeyDelta_OP_CHANGED,
			Before: encodeMetadataLine(*a),
			After:  encodeMetadataLine(*b),
		}
		diff.WorkingMemoryDeltas = append(diff.WorkingMemoryDeltas, delta)
	}

	// Size guard (R15.4). Compute the marshalled size and compare against
	// the limit; on overrun, return the canonical hint so the dashboard
	// flips to the client-side fallback path (R17.4 fallback clause).
	if proto.Size(diff) > diffSizeLimitBytes {
		return nil, status_grpc.Errorf(codes.ResourceExhausted,
			"diff exceeds %d bytes; use GetCheckpoint and diff client-side", diffSizeLimitBytes)
	}

	return &daemonpb.DiffCheckpointsResponse{Diff: diff}, nil
}

// requireMissionViewer enforces mission-scoped FGA. When the daemon's
// FGA Authorizer is wired, the caller subject is checked against the
// `viewer` relation on the mission's tenant. When no Authorizer is
// configured (dev / kind without FGA), the per-tenant Pool's tenant-id
// scoping is the implicit guard — we accept the request and rely on the
// downstream backend to fail closed if cross-tenant access is attempted.
//
// Spec: mission-checkpointing R13.2, R14.2.
func (s *DaemonServer) requireMissionViewer(ctx context.Context, missionID, rpcName string) error {
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil {
		return status_grpc.Error(codes.Unauthenticated, "no identity in context")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return status_grpc.Error(codes.PermissionDenied, "caller has no tenant")
	}

	// When the FGA stack isn't wired (kind without FGA, dev), accept the
	// request — the per-tenant Pool path provides tenant-scoping as the
	// minimum guarantee.
	if s.authorizer == nil {
		s.logger.Debug(rpcName+": no authorizer wired, falling back to tenant-scope guard",
			"mission_id", missionID,
			"tenant_id", tenantID,
		)
		return nil
	}

	// Tenant-scoped viewer check. The mission#viewer relation is not yet
	// in the FGA model (Phase 2A defers it); fall back to tenant-member
	// for now, which is what the registry annotations produce.
	ok, err := s.authorizer.Check(ctx,
		"user:"+id.Subject,
		"member",
		"tenant:"+tenantID,
	)
	if err != nil {
		s.logger.Warn(rpcName+": authz check failed",
			"mission_id", missionID,
			"tenant_id", tenantID,
			"error", err,
		)
		return status_grpc.Errorf(codes.Internal, "authz check failed: %v", err)
	}
	if !ok {
		return status_grpc.Errorf(codes.PermissionDenied,
			"caller is not a member of tenant %s", tenantID)
	}
	return nil
}

// emitCheckpointReadAudit emits a `checkpoint.read` audit envelope on
// every successful GetCheckpoint call (R14.6). When the audit pipeline
// is not wired, the call is a structured-log emission only.
func (s *DaemonServer) emitCheckpointReadAudit(ctx context.Context, missionID, checkpointID string, includeBlobs bool) {
	tenantID := auth.TenantStringFromContext(ctx)
	subject := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		subject = id.Subject
	}

	s.logger.Info("audit: checkpoint.read",
		"event_kind", "checkpoint.read",
		"tenant_id", tenantID,
		"mission_id", missionID,
		"checkpoint_id", checkpointID,
		"caller_subject", subject,
		"include_blobs", includeBlobs,
	)

	// When a Postgres-backed audit writer is wired, also emit there.
	if s.tenantAdminAuditWriter != nil {
		meta := fmt.Sprintf(
			`{"mission_id":%q,"checkpoint_id":%q,"include_blobs":%t}`,
			missionID, checkpointID, includeBlobs,
		)
		s.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    subject,
			ActorType:  "user",
			Action:     "checkpoint.read",
			TargetType: "checkpoint",
			TargetID:   checkpointID,
			Metadata:   []byte(meta),
		})
	}
}

// checkpointDataView is a local shaping struct that bridges between the
// internal `api.CheckpointData` value object and the proto wire types,
// without forcing additional fields onto the public CheckpointData.
type checkpointDataView struct {
	CheckpointID   string
	CreatedAt      int64 // Unix seconds
	CompletedNodes int
	TotalNodes     int
	FindingsCount  int
	Version        int
}

// toCheckpointDataView converts an api.CheckpointData to the local view.
func toCheckpointDataView(cp CheckpointData) checkpointDataView {
	return checkpointDataView{
		CheckpointID:   cp.CheckpointID,
		CreatedAt:      cp.CreatedAt,
		CompletedNodes: cp.CompletedNodes,
		TotalNodes:     cp.TotalNodes,
		FindingsCount:  cp.FindingsCount,
		Version:        cp.Version,
	}
}

// buildCheckpointSummaries lifts each view to a proto CheckpointSummary
// the dashboard timeline can render.
func buildCheckpointSummaries(views []checkpointDataView, missionID string) []*daemonpb.CheckpointSummary {
	out := make([]*daemonpb.CheckpointSummary, 0, len(views))
	for _, v := range views {
		out = append(out, buildSingleCheckpointSummary(v, missionID))
	}
	return out
}

// buildSingleCheckpointSummary produces the proto summary for one view.
// Source defaults to CHECKPOINT_SOURCE_SUPER_STEP — the legacy
// mission-level checkpoint is super-step-aligned in practice. When the
// per-super-step store wires up, source will reflect the actual cadence
// (parallel-group / approval-gate / shutdown / manual).
func buildSingleCheckpointSummary(v checkpointDataView, missionID string) *daemonpb.CheckpointSummary {
	return &daemonpb.CheckpointSummary{
		CheckpointId: v.CheckpointID,
		MissionId:    missionID,
		SuperStep:    int64(v.Version),
		CapturedAt:   timestampFromUnix(v.CreatedAt),
		Source:       daemonpb.CheckpointSource_CHECKPOINT_SOURCE_SUPER_STEP,
	}
}

// timestampFromUnix builds a *timestamppb.Timestamp from a Unix-seconds
// value. Returns nil on zero input so the proto reflects "absent".
func timestampFromUnix(seconds int64) *timestamppb.Timestamp {
	if seconds <= 0 {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: seconds}
}

// encodeMetadataLine produces a deterministic, human-readable byte line
// summarising a checkpoint's metadata fields. Used as Before/After
// payloads on a metadata-level MemoryKeyDelta until per-field memory
// bytes are wired through the per-super-step store.
func encodeMetadataLine(v checkpointDataView) []byte {
	return []byte(fmt.Sprintf(
		"checkpoint=%s super_step=%d completed=%d total=%d findings=%d",
		v.CheckpointID, v.Version, v.CompletedNodes, v.TotalNodes, v.FindingsCount,
	))
}

// parseListOffsetToken decodes the daemon's opaque page_token. The
// token format mirrors callback_service_runhistory.go's `offset:N`
// scheme. Bad tokens silently restart at offset 0.
func parseListOffsetToken(token string) int {
	if token == "" {
		return 0
	}
	const prefix = "offset:"
	if len(token) <= len(prefix) || token[:len(prefix)] != prefix {
		return 0
	}
	n := 0
	for i := len(prefix); i < len(token); i++ {
		c := token[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n < 0 {
			return 0
		}
	}
	return n
}

// formatListOffsetToken encodes a page-end offset.
func formatListOffsetToken(offset int) string {
	if offset <= 0 {
		return ""
	}
	digits := make([]byte, 0, 12)
	for offset > 0 {
		digits = append([]byte{byte('0' + offset%10)}, digits...)
		offset /= 10
	}
	return "offset:" + string(digits)
}

