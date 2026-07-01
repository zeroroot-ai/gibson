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
// Phase 3B (this file) lands the byte-level surface — per-super-step
// payload exposure, R14 secret redaction, R15 byte-level diff walk —
// and stitches the orchestrator-side rewind path through to the
// daemon's RewindMission method (Spec 4 R16.4). The `mission#viewer`
// /`mission#admin` FGA gates remain on `tenant#member` /
// `tenant#admin` until Phase 4C lands the model relations + tuple
// writes; a follow-up edit then flips these checks.
//
// Spec: mission-checkpointing R13/R14/R15/R16, week-4-handlers-ui-e2e
// §1 tasks 1-15.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
// in-handler over the returned slice.
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

	// Order: descending by default (newest first).
	if req.GetOrder() == daemonpb.ListCheckpointsRequest_ORDER_OLDEST_FIRST {
		// reverse copy
		reversed := make([]CheckpointData, len(checkpoints))
		for i, cp := range checkpoints {
			reversed[len(checkpoints)-1-i] = cp
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

	page := checkpoints[offset:end]
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

	// Pull the rich per-super-step payload first; fall back to
	// metadata-only if the per-super-step path is not wired.
	payload, payloadErr := s.daemon.GetMissionCheckpointPayload(ctx, req.GetMissionId(), req.GetCheckpointId())
	if payloadErr != nil {
		if strings.Contains(payloadErr.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound,
				"checkpoint %s not found for mission %s",
				req.GetCheckpointId(), req.GetMissionId())
		}
		s.logger.Debug("GetCheckpoint: payload fetch failed, falling back to metadata path",
			"mission_id", req.GetMissionId(),
			"checkpoint_id", req.GetCheckpointId(),
			"error", payloadErr,
		)
	}
	if payload == nil {
		// Fallback: pull metadata only via the legacy path.
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
		for i := range checkpoints {
			if checkpoints[i].CheckpointID == req.GetCheckpointId() {
				cp := checkpoints[i]
				payload = &cp
				break
			}
		}
	}

	if payload == nil {
		return nil, status_grpc.Errorf(codes.NotFound,
			"checkpoint %s not found for mission %s",
			req.GetCheckpointId(), req.GetMissionId())
	}

	// Apply redaction unless caller is a platform_operator (R14.5).
	redactSecrets := !s.callerIsPlatformOperator(ctx)
	out := buildCheckpointProto(*payload, req.GetMissionId(), redactSecrets, req.GetIncludeBlobs())

	// Audit emission (R14.6).
	s.emitCheckpointReadAudit(ctx, req.GetMissionId(), req.GetCheckpointId(), req.GetIncludeBlobs())

	return &daemonpb.GetCheckpointResponse{Checkpoint: out}, nil
}

// DiffCheckpoints returns structured deltas between two checkpoints of
// the same mission. Both checkpoints are loaded via the rich payload
// path (with metadata fallback), then walked field-by-field; only
// differing fields produce deltas. Secret-bearing values are redacted
// for non-platform-operator callers (R15.6). On overrun (>10 MiB
// serialized diff) the handler returns codes.ResourceExhausted with the
// canonical client-side-fallback hint.
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

	a, aErr := s.daemon.GetMissionCheckpointPayload(ctx, req.GetMissionId(), req.GetCheckpointAId())
	if aErr != nil && strings.Contains(aErr.Error(), "not found") {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointAId())
	}
	b, bErr := s.daemon.GetMissionCheckpointPayload(ctx, req.GetMissionId(), req.GetCheckpointBId())
	if bErr != nil && strings.Contains(bErr.Error(), "not found") {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointBId())
	}
	// Fallback: when GetMissionCheckpointPayload returns nil with no error
	// (e.g. dev/kind without rich path), use the legacy metadata view.
	if a == nil || b == nil {
		checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, req.GetMissionId())
		if err != nil {
			return nil, preserveStatus(err, "DiffCheckpoints: backend lookup failed")
		}
		for i := range checkpoints {
			cp := checkpoints[i]
			switch cp.CheckpointID {
			case req.GetCheckpointAId():
				if a == nil {
					a = &cp
				}
			case req.GetCheckpointBId():
				if b == nil {
					b = &cp
				}
			}
		}
	}
	if a == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointAId())
	}
	if b == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "checkpoint %s not found", req.GetCheckpointBId())
	}

	redactSecrets := !s.callerIsPlatformOperator(ctx)
	diff := computeCheckpointDiff(*a, *b, redactSecrets)

	// Size guard (R15.4). On overrun, return the canonical hint so the
	// dashboard flips to the client-side fallback path.
	if proto.Size(diff) > diffSizeLimitBytes {
		return nil, status_grpc.Errorf(codes.ResourceExhausted,
			"diff exceeds %d bytes; use GetCheckpoint and diff client-side", diffSizeLimitBytes)
	}

	return &daemonpb.DiffCheckpointsResponse{Diff: diff}, nil
}

// requireMissionViewer enforces mission-scoped FGA via `mission#viewer`,
// which cascades from `tenant#member` via the OpenFGA model relation
// `define viewer: [user] or admin or member from belongs_to` (see
// internal/platform/authz/model.fga `type mission`). When no Authorizer is
// configured, the per-tenant Pool's tenant-id scoping is the implicit guard.
//
// Self-healing: missions created before CreateMission's belongs_to write
// became required may be missing their FGA tuple. When the viewer check
// fails, this function checks whether the caller is a tenant member and, if
// so, writes the missing tuple and allows the request. The heal is logged at
// WARN so we can track and confirm the backfill is converging.
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

	// When the FGA stack isn't wired, the per-tenant Pool path provides
	// tenant-scoping as the minimum guarantee.
	if s.authorizer == nil {
		s.logger.Debug(rpcName+": no authorizer wired, falling back to tenant-scope guard",
			"mission_id", missionID,
			"tenant_id", tenantID,
		)
		return nil
	}

	// Primary check: viewer relation on the mission (cascades via belongs_to).
	ok, err := s.authorizer.Check(ctx,
		"user:"+id.Subject,
		"viewer",
		"mission:"+missionID,
	)
	if err != nil {
		s.logger.Warn(rpcName+": authz check failed",
			"mission_id", missionID,
			"tenant_id", tenantID,
			"error", err,
		)
		return status_grpc.Errorf(codes.Internal, "authz check failed: %v", err)
	}
	if ok {
		return nil
	}

	// Viewer check failed. Self-heal: the mission may be missing its
	// belongs_to tuple (created before CreateMission's write became
	// required). If the caller is a tenant member, write the tuple now.
	isMember, memberErr := s.authorizer.Check(ctx,
		"user:"+id.Subject,
		"member",
		"tenant:"+tenantID,
	)
	if memberErr != nil {
		s.logger.Warn(rpcName+": member check during heal failed",
			"mission_id", missionID,
			"tenant_id", tenantID,
			"error", memberErr,
		)
		return status_grpc.Errorf(codes.PermissionDenied,
			"caller does not have viewer access to mission %s", missionID)
	}
	if !isMember {
		return status_grpc.Errorf(codes.PermissionDenied,
			"caller does not have viewer access to mission %s", missionID)
	}

	// Caller is a tenant member. Write the missing belongs_to tuple.
	healTuple := authz.Tuple{
		User:     "tenant:" + tenantID,
		Relation: "belongs_to",
		Object:   "mission:" + missionID,
	}
	s.logger.Warn(rpcName+": mission missing belongs_to FGA tuple — writing heal tuple",
		"mission_id", missionID,
		"tenant_id", tenantID,
		"user", id.Subject,
	)
	if writeErr := s.authorizer.Write(ctx, []authz.Tuple{healTuple}); writeErr != nil {
		s.logger.Error(rpcName+": heal write failed",
			"mission_id", missionID,
			"tenant_id", tenantID,
			"error", writeErr,
		)
		return status_grpc.Errorf(codes.PermissionDenied,
			"caller does not have viewer access to mission %s", missionID)
	}
	return nil
}

// callerIsPlatformOperator reports whether the request context carries
// a platform_operator identity. Used to bypass secret redaction (R14.5
// final clause). When the authorizer is not wired, returns false (fail
// closed — non-operator) so dev/kind never accidentally surfaces
// plaintext secrets to a viewer subject.
func (s *DaemonServer) callerIsPlatformOperator(ctx context.Context) bool {
	if s.authorizer == nil {
		return false
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return false
	}
	ok, err := s.authorizer.Check(ctx,
		"user:"+id.Subject,
		"platform_operator",
		"system_tenant:_system",
	)
	if err != nil {
		return false
	}
	return ok
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

// ────────────────────────────────────────────────────────────────────────
// Proto-shape builders
// ────────────────────────────────────────────────────────────────────────

// buildCheckpointSummaries lifts each CheckpointData to a proto
// CheckpointSummary the dashboard timeline can render.
func buildCheckpointSummaries(views []CheckpointData, missionID string) []*daemonpb.CheckpointSummary {
	out := make([]*daemonpb.CheckpointSummary, 0, len(views))
	for _, v := range views {
		out = append(out, buildSingleCheckpointSummary(v, missionID))
	}
	return out
}

// buildSingleCheckpointSummary produces the proto summary for one view.
// Source defaults to CHECKPOINT_SOURCE_SUPER_STEP when the backend's
// Source string is empty.
func buildSingleCheckpointSummary(v CheckpointData, missionID string) *daemonpb.CheckpointSummary {
	return &daemonpb.CheckpointSummary{
		CheckpointId:        v.CheckpointID,
		MissionId:           missionID,
		SuperStep:           int64(v.Version),
		CapturedAt:          timestampFromUnix(v.CreatedAt),
		SizeBytes:           v.SizeBytes,
		Source:              checkpointSourceFromString(v.Source),
		InFlightIdempotency: idempotencyFromString(v.InFlightIdempotency),
		ParallelGroupId:     v.ParallelGroupID,
	}
}

// buildCheckpointProto produces the full Checkpoint proto from a
// CheckpointData payload. Applies secret redaction to working/mission
// memory bytes when redactSecrets is true.
func buildCheckpointProto(v CheckpointData, missionID string, redactSecrets, includeBlobs bool) *daemonpb.Checkpoint {
	out := &daemonpb.Checkpoint{
		Summary: buildSingleCheckpointSummary(v, missionID),
	}
	if redactSecrets {
		out.WorkingMemory = redactSecretsInJSONBytes(v.WorkingMemory)
		out.MissionMemory = redactSecretsInJSONBytes(v.MissionMemory)
	} else {
		out.WorkingMemory = v.WorkingMemory
		out.MissionMemory = v.MissionMemory
	}

	for _, step := range v.DagSteps {
		ds := &daemonpb.DagStep{
			NodeId:     step.NodeID,
			State:      step.State,
			StartedAt:  timestampFromUnix(step.StartedAtUnix),
			FinishedAt: timestampFromUnix(step.FinishedAtUnix),
		}
		if includeBlobs {
			if redactSecrets {
				ds.Inputs = redactSecretsInJSONBytes(step.Inputs)
				ds.Outputs = redactSecretsInJSONBytes(step.Outputs)
			} else {
				ds.Inputs = step.Inputs
				ds.Outputs = step.Outputs
			}
		}
		out.Steps = append(out.Steps, ds)
	}

	for _, f := range v.FindingSnapshots {
		fs := &daemonpb.FindingSnapshot{
			FindingId: f.FindingID,
			Severity:  f.Severity,
			Payload:   f.Payload,
		}
		if redactSecrets {
			fs.Payload = redactSecretsInJSONBytes(fs.Payload)
		}
		out.Findings = append(out.Findings, fs)
	}

	if len(v.ParallelGroups) > 0 {
		out.ParallelGroups = make(map[string]*daemonpb.ParallelGroupState, len(v.ParallelGroups))
		for gid, g := range v.ParallelGroups {
			out.ParallelGroups[gid] = &daemonpb.ParallelGroupState{
				GroupId:          g.GroupID,
				Expected:         g.Expected,
				Completed:        g.Completed,
				CompletedNodeIds: g.CompletedNodeIDs,
			}
		}
	}

	return out
}

// timestampFromUnix builds a *timestamppb.Timestamp from a Unix-seconds
// value. Returns nil on zero input so the proto reflects "absent".
func timestampFromUnix(seconds int64) *timestamppb.Timestamp {
	if seconds <= 0 {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: seconds}
}

// checkpointSourceFromString maps the daemon's snake-case `source`
// string to the proto enum.
func checkpointSourceFromString(src string) daemonpb.CheckpointSource {
	switch src {
	case "super_step":
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_SUPER_STEP
	case "approval_gate":
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_APPROVAL_GATE
	case "graceful_shutdown":
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_GRACEFUL_SHUTDOWN
	case "parallel_group":
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_PARALLEL_GROUP
	case "manual":
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_MANUAL
	case "":
		// Empty falls back to super-step at the legacy path.
		return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_SUPER_STEP
	}
	return daemonpb.CheckpointSource_CHECKPOINT_SOURCE_UNSPECIFIED
}

// idempotencyFromString maps the daemon's idempotency mode string to
// the proto enum.
func idempotencyFromString(s string) manifestpb.ToolIdempotency {
	switch s {
	case "AT_MOST_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE
	case "AT_LEAST_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE
	case "EXACTLY_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE
	}
	return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED
}

// ────────────────────────────────────────────────────────────────────────
// Diff walker (R15)
// ────────────────────────────────────────────────────────────────────────

// computeCheckpointDiff walks two CheckpointData payloads and emits a
// per-domain CheckpointDiff. Memory deltas are computed by parsing the
// JSON-encoded working/mission memory bytes; non-JSON bytes are
// compared byte-for-byte and emitted as a single "<opaque>" delta.
// DagStepDeltas are computed by node ID; FindingDeltas by finding ID;
// ParallelGroupDeltas by group ID. Secret redaction is applied when
// redactSecrets is true.
func computeCheckpointDiff(a, b CheckpointData, redactSecrets bool) *daemonpb.CheckpointDiff {
	diff := &daemonpb.CheckpointDiff{}

	diff.WorkingMemoryDeltas = diffMemoryBytes(a.WorkingMemory, b.WorkingMemory, redactSecrets)
	diff.MissionMemoryDeltas = diffMemoryBytes(a.MissionMemory, b.MissionMemory, redactSecrets)
	diff.DagStepDeltas = diffDagSteps(a.DagSteps, b.DagSteps)
	diff.FindingDeltas = diffFindings(a.FindingSnapshots, b.FindingSnapshots)
	diff.ParallelGroupDeltas = diffParallelGroups(a.ParallelGroups, b.ParallelGroups)

	// Always emit a metadata-level fallback delta when no rich-payload
	// deltas were produced and the metadata diverges. Keeps the
	// dashboard's diff view useful on the metadata-only fallback path.
	if len(diff.WorkingMemoryDeltas) == 0 && len(diff.MissionMemoryDeltas) == 0 &&
		len(diff.DagStepDeltas) == 0 && len(diff.FindingDeltas) == 0 &&
		len(diff.ParallelGroupDeltas) == 0 &&
		(a.CompletedNodes != b.CompletedNodes ||
			a.TotalNodes != b.TotalNodes ||
			a.FindingsCount != b.FindingsCount ||
			a.Version != b.Version) {
		diff.WorkingMemoryDeltas = append(diff.WorkingMemoryDeltas, &daemonpb.MemoryKeyDelta{
			Key:    "checkpoint:metadata",
			Op:     daemonpb.MemoryKeyDelta_OP_CHANGED,
			Before: encodeMetadataLine(a),
			After:  encodeMetadataLine(b),
		})
	}

	return diff
}

// diffMemoryBytes parses a/b as JSON maps and emits per-key deltas. If
// either side fails to parse, falls back to a single "<opaque>" delta.
func diffMemoryBytes(a, b []byte, redactSecrets bool) []*daemonpb.MemoryKeyDelta {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	var aMap, bMap map[string]any
	aOk := json.Unmarshal(a, &aMap) == nil && aMap != nil
	bOk := json.Unmarshal(b, &bMap) == nil && bMap != nil
	if !aOk || !bOk {
		// Opaque path — neither side parses, so emit a single byte-level
		// delta when the bytes differ.
		if equalBytes(a, b) {
			return nil
		}
		before, after := a, b
		if redactSecrets {
			before = redactSecretsInJSONBytes(before)
			after = redactSecretsInJSONBytes(after)
		}
		return []*daemonpb.MemoryKeyDelta{{
			Key:    "bytes:opaque",
			Op:     daemonpb.MemoryKeyDelta_OP_CHANGED,
			Before: before,
			After:  after,
		}}
	}

	// Walk the union of keys, emit ADDED / REMOVED / CHANGED.
	keys := make(map[string]struct{}, len(aMap)+len(bMap))
	for k := range aMap {
		keys[k] = struct{}{}
	}
	for k := range bMap {
		keys[k] = struct{}{}
	}
	out := make([]*daemonpb.MemoryKeyDelta, 0, len(keys))
	placeholder := []byte(`"` + redactedPlaceholder + `"`)
	for k := range keys {
		av, aHas := aMap[k]
		bv, bHas := bMap[k]
		switch {
		case !aHas && bHas:
			afterBytes := jsonBytesOf(bv)
			if redactSecrets && isSecretKey(k) {
				afterBytes = placeholder
			}
			out = append(out, &daemonpb.MemoryKeyDelta{
				Key:   k,
				Op:    daemonpb.MemoryKeyDelta_OP_ADDED,
				After: afterBytes,
			})
		case aHas && !bHas:
			beforeBytes := jsonBytesOf(av)
			if redactSecrets && isSecretKey(k) {
				beforeBytes = placeholder
			}
			out = append(out, &daemonpb.MemoryKeyDelta{
				Key:    k,
				Op:     daemonpb.MemoryKeyDelta_OP_REMOVED,
				Before: beforeBytes,
			})
		case aHas && bHas:
			ab := jsonBytesOf(av)
			bb := jsonBytesOf(bv)
			if equalBytes(ab, bb) {
				continue
			}
			if redactSecrets && isSecretKey(k) {
				ab = placeholder
				bb = placeholder
			}
			out = append(out, &daemonpb.MemoryKeyDelta{
				Key:    k,
				Op:     daemonpb.MemoryKeyDelta_OP_CHANGED,
				Before: ab,
				After:  bb,
			})
		}
	}
	return out
}

// diffDagSteps compares DAG step snapshots by node ID.
func diffDagSteps(a, b []DagStepData) []*daemonpb.DagStepDelta {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	aIdx := make(map[string]DagStepData, len(a))
	for _, s := range a {
		aIdx[s.NodeID] = s
	}
	bIdx := make(map[string]DagStepData, len(b))
	for _, s := range b {
		bIdx[s.NodeID] = s
	}
	keys := make(map[string]struct{}, len(aIdx)+len(bIdx))
	for k := range aIdx {
		keys[k] = struct{}{}
	}
	for k := range bIdx {
		keys[k] = struct{}{}
	}
	out := make([]*daemonpb.DagStepDelta, 0, len(keys))
	for k := range keys {
		as, aOk := aIdx[k]
		bs, bOk := bIdx[k]
		switch {
		case !aOk && bOk:
			out = append(out, &daemonpb.DagStepDelta{
				NodeId: k,
				Op:     daemonpb.DagStepDelta_OP_ADDED,
				After:  encodeDagStepBytes(bs),
			})
		case aOk && !bOk:
			out = append(out, &daemonpb.DagStepDelta{
				NodeId: k,
				Op:     daemonpb.DagStepDelta_OP_REMOVED,
				Before: encodeDagStepBytes(as),
			})
		case aOk && bOk:
			if dagStepEqual(as, bs) {
				continue
			}
			out = append(out, &daemonpb.DagStepDelta{
				NodeId: k,
				Op:     daemonpb.DagStepDelta_OP_CHANGED,
				Before: encodeDagStepBytes(as),
				After:  encodeDagStepBytes(bs),
			})
		}
	}
	return out
}

// diffFindings compares finding snapshots by finding ID. Findings are
// considered "changed" if their severity or payload differ.
func diffFindings(a, b []FindingSnapshotData) []*daemonpb.FindingDelta {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	aIdx := make(map[string]FindingSnapshotData, len(a))
	for _, f := range a {
		aIdx[f.FindingID] = f
	}
	bIdx := make(map[string]FindingSnapshotData, len(b))
	for _, f := range b {
		bIdx[f.FindingID] = f
	}
	keys := make(map[string]struct{}, len(aIdx)+len(bIdx))
	for k := range aIdx {
		keys[k] = struct{}{}
	}
	for k := range bIdx {
		keys[k] = struct{}{}
	}
	out := make([]*daemonpb.FindingDelta, 0, len(keys))
	for k := range keys {
		af, aOk := aIdx[k]
		bf, bOk := bIdx[k]
		switch {
		case !aOk && bOk:
			out = append(out, &daemonpb.FindingDelta{
				FindingId: k,
				Op:        daemonpb.FindingDelta_OP_ADDED,
				After:     encodeFindingBytes(bf),
			})
		case aOk && !bOk:
			out = append(out, &daemonpb.FindingDelta{
				FindingId: k,
				Op:        daemonpb.FindingDelta_OP_REMOVED,
				Before:    encodeFindingBytes(af),
			})
		case aOk && bOk:
			if findingEqual(af, bf) {
				continue
			}
			out = append(out, &daemonpb.FindingDelta{
				FindingId: k,
				Op:        daemonpb.FindingDelta_OP_CHANGED,
				Before:    encodeFindingBytes(af),
				After:     encodeFindingBytes(bf),
			})
		}
	}
	return out
}

// diffParallelGroups compares the per-group barrier state.
func diffParallelGroups(a, b map[string]ParallelGroupStateData) []*daemonpb.ParallelGroupDelta {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	keys := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	out := make([]*daemonpb.ParallelGroupDelta, 0, len(keys))
	for k := range keys {
		ag, aOk := a[k]
		bg, bOk := b[k]
		switch {
		case !aOk && bOk:
			out = append(out, &daemonpb.ParallelGroupDelta{
				GroupId: k,
				Op:      daemonpb.ParallelGroupDelta_OP_ADDED,
				After:   encodeParallelGroupBytes(bg),
			})
		case aOk && !bOk:
			out = append(out, &daemonpb.ParallelGroupDelta{
				GroupId: k,
				Op:      daemonpb.ParallelGroupDelta_OP_REMOVED,
				Before:  encodeParallelGroupBytes(ag),
			})
		case aOk && bOk:
			if parallelGroupEqual(ag, bg) {
				continue
			}
			out = append(out, &daemonpb.ParallelGroupDelta{
				GroupId: k,
				Op:      daemonpb.ParallelGroupDelta_OP_CHANGED,
				Before:  encodeParallelGroupBytes(ag),
				After:   encodeParallelGroupBytes(bg),
			})
		}
	}
	return out
}

// jsonBytesOf marshals an interface{} to its JSON-bytes form. Returns
// `null` on marshal failure.
func jsonBytesOf(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dagStepEqual(a, b DagStepData) bool {
	return a.NodeID == b.NodeID &&
		a.State == b.State &&
		a.StartedAtUnix == b.StartedAtUnix &&
		a.FinishedAtUnix == b.FinishedAtUnix &&
		a.RetryCount == b.RetryCount &&
		a.Error == b.Error &&
		equalBytes(a.Inputs, b.Inputs) &&
		equalBytes(a.Outputs, b.Outputs)
}

func findingEqual(a, b FindingSnapshotData) bool {
	return a.FindingID == b.FindingID &&
		a.Severity == b.Severity &&
		a.Title == b.Title &&
		a.NodeID == b.NodeID &&
		equalBytes(a.Payload, b.Payload)
}

func parallelGroupEqual(a, b ParallelGroupStateData) bool {
	if a.GroupID != b.GroupID || a.Expected != b.Expected || a.Completed != b.Completed {
		return false
	}
	if len(a.CompletedNodeIDs) != len(b.CompletedNodeIDs) {
		return false
	}
	for i := range a.CompletedNodeIDs {
		if a.CompletedNodeIDs[i] != b.CompletedNodeIDs[i] {
			return false
		}
	}
	return true
}

// encodeDagStepBytes produces a JSON-encoded summary of a DAG step
// snapshot, used as the before/after byte payload on a DagStepDelta.
func encodeDagStepBytes(s DagStepData) []byte {
	body, _ := json.Marshal(struct {
		NodeID         string `json:"node_id"`
		State          string `json:"state"`
		StartedAtUnix  int64  `json:"started_at,omitempty"`
		FinishedAtUnix int64  `json:"finished_at,omitempty"`
		RetryCount     int32  `json:"retry_count,omitempty"`
		Error          string `json:"error,omitempty"`
	}{
		NodeID:         s.NodeID,
		State:          s.State,
		StartedAtUnix:  s.StartedAtUnix,
		FinishedAtUnix: s.FinishedAtUnix,
		RetryCount:     s.RetryCount,
		Error:          s.Error,
	})
	return body
}

// encodeFindingBytes produces a JSON-encoded summary of a finding row.
func encodeFindingBytes(f FindingSnapshotData) []byte {
	body, _ := json.Marshal(struct {
		FindingID string `json:"finding_id"`
		Severity  string `json:"severity"`
		Title     string `json:"title,omitempty"`
		NodeID    string `json:"node_id,omitempty"`
	}{
		FindingID: f.FindingID,
		Severity:  f.Severity,
		Title:     f.Title,
		NodeID:    f.NodeID,
	})
	return body
}

// encodeParallelGroupBytes produces a JSON-encoded summary of a
// parallel-group barrier state row.
func encodeParallelGroupBytes(g ParallelGroupStateData) []byte {
	body, _ := json.Marshal(struct {
		GroupID          string   `json:"group_id"`
		Expected         int32    `json:"expected"`
		Completed        int32    `json:"completed"`
		CompletedNodeIDs []string `json:"completed_node_ids,omitempty"`
	}{
		GroupID:          g.GroupID,
		Expected:         g.Expected,
		Completed:        g.Completed,
		CompletedNodeIDs: g.CompletedNodeIDs,
	})
	return body
}

// encodeMetadataLine produces a deterministic, human-readable byte line
// summarising a checkpoint's metadata fields. Used as the
// fallback-path "metadata-only" delta payload.
func encodeMetadataLine(v CheckpointData) []byte {
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

// applyRewindIdempotency runs the orchestrator-side rewind dispatcher
// for the in-flight tool captured at the target checkpoint. When the
// target carries no in-flight tool, this is a no-op. Emits per-tool
// `mission.rewind.tool_cancelled` audit hints. Returns a
// FailedPrecondition gRPC error when the contract demands FailMission
// (EXACTLY_ONCE without resumption token).
//
// Spec: mission-checkpointing R6.3-R6.6, R16.4.
func (s *DaemonServer) applyRewindIdempotency(ctx context.Context, missionID, targetCheckpointID string) error {
	payload, err := s.daemon.GetMissionCheckpointPayload(ctx, missionID, targetCheckpointID)
	if err != nil || payload == nil {
		// Best effort — without payload visibility, fall through and let
		// the orchestrator's resume loop apply default semantics.
		return nil
	}
	if payload.InFlightNodeID == "" {
		// Nothing was in flight at the target; resume cleanly.
		return nil
	}
	dispatcher := NewRewindDispatcher(&serverRewindEmitter{server: s, ctx: ctx})
	tool := InFlightTool{
		NodeID:          payload.InFlightNodeID,
		ResumptionToken: payload.ResumptionToken,
		Idempotency:     ResolveIdempotencyFromString(payload.InFlightIdempotency),
	}
	if rerr := dispatcher.Rewind(ctx, missionID, []InFlightTool{tool}); rerr != nil {
		return status_grpc.Errorf(codes.FailedPrecondition, "rewind blocked by idempotency contract: %v", rerr)
	}
	return nil
}

// serverRewindEmitter implements RewindEmitter against
// the DaemonServer's audit writer + structured logger.
type serverRewindEmitter struct {
	server *DaemonServer
	ctx    context.Context
}

func (e *serverRewindEmitter) OnToolDispatch(_ context.Context, missionID, nodeID string, mode manifestpb.ToolIdempotency, action IdempotencyAction) {
	tenantID := auth.TenantStringFromContext(e.ctx)
	subject := ""
	if id, err := auth.IdentityFromContext(e.ctx); err == nil {
		subject = id.Subject
	}
	e.server.logger.Info("audit: mission.rewind.tool_cancelled",
		"event_kind", "mission.rewind.tool_cancelled",
		"tenant_id", tenantID,
		"mission_id", missionID,
		"node_id", nodeID,
		"idempotency_mode", mode.String(),
		"action", action.String(),
		"caller_subject", subject,
	)
	if e.server.tenantAdminAuditWriter != nil {
		meta := fmt.Sprintf(
			`{"mission_id":%q,"node_id":%q,"idempotency_mode":%q,"action":%q}`,
			missionID, nodeID, mode.String(), action.String(),
		)
		e.server.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    subject,
			ActorType:  "user",
			Action:     "mission.rewind.tool_cancelled",
			TargetType: "mission",
			TargetID:   missionID,
			Metadata:   []byte(meta),
		})
	}
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

// redactedPlaceholder is the literal string substituted for secret-bearing field values.
const redactedPlaceholder = "<redacted:secret>"

// redactSecretsInJSONBytes walks JSON-encoded data and replaces secret-bearing
// field values with redactedPlaceholder, then re-marshals. Returns the original
// bytes if data is empty or fails to parse — non-JSON payloads pass through.
// Moved inline from internal/engine/checkpoint (retired in #1117).
func redactSecretsInJSONBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return data
	}
	walked := redactValue(v, "")
	out, err := json.Marshal(walked)
	if err != nil {
		return data
	}
	return out
}

// isSecretKey reports whether a field name matches the secret-bearing pattern set.
func isSecretKey(key string) bool {
	if key == "" {
		return false
	}
	low := strings.ToLower(key)
	switch {
	case strings.Contains(low, "password"):
		return true
	case strings.Contains(low, "token"):
		return true
	case strings.Contains(low, "secret"):
		return true
	case strings.Contains(low, "credential"):
		return true
	case strings.Contains(low, "apikey"):
		return true
	case strings.Contains(low, "api_key"):
		return true
	case strings.Contains(low, "private_key"):
		return true
	case strings.Contains(low, "privatekey"):
		return true
	}
	return false
}

// redactValue recursively walks an interface{} produced by json.Unmarshal,
// substituting redactedPlaceholder when the parent key matches the secret pattern
// or when the value is a vault-resolved hint.
func redactValue(v any, parentKey string) any {
	switch x := v.(type) {
	case map[string]any:
		if src, ok := x["source"].(string); ok && strings.EqualFold(src, "vault") {
			return redactedPlaceholder
		}
		for k, child := range x {
			x[k] = redactValue(child, k)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = redactValue(child, parentKey)
		}
		return x
	case string:
		if isSecretKey(parentKey) {
			return redactedPlaceholder
		}
		if strings.HasPrefix(x, "vault:") {
			return redactedPlaceholder
		}
		return x
	default:
		if isSecretKey(parentKey) {
			return redactedPlaceholder
		}
		return v
	}
}
