// Package api — user_state.go
//
// Implements the per-user Redis-backed RPC handlers added in
// dashboard-no-backing-store-clients (Module 2 — Redis-read RPCs).
//
// Six domains, all scoped to a per-tenant Redis logical namespace:
//
//  1. User Onboarding State     key: user-onboarding:{tenantID}:{userID}     TTL 90d
//  2. User Layout Preferences   key: user-layout:{tenantID}:{userID}          no TTL
//  3. User Activity Feed        key: useract:{tenantID}:{userID}:{kind}       TTL 7d
//     key: useract:{tenantID}:{userID}:lastActive   TTL 7d
//  4. Signup Progress           key: signup-progress:{attemptID}              TTL 300s
//  5. Membership Cache Invalidation  key: dashboard:memberships:user:{userID}
//  6. Chat Attachment Staging   key: chatattach:{tenantID}:{attachmentID}     TTL 1h
//
// Cross-tenant isolation: all user-scoped keys include tenantID in the prefix.
// Signup-progress keys use an opaque UUID capability that carries no PII.
package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ============================================================================
// Key constants and helpers
// ============================================================================

const (
	userOnboardingKeyPfx  = "user-onboarding:"
	userLayoutKeyPfx      = "user-layout:"
	userActivityKeyPfx    = "useract:"
	signupProgressKeyPfx  = "signup-progress:"
	membershipCacheKeyPfx = "dashboard:memberships:user:"
	chatAttachKeyPfx      = "chatattach:"

	userOnboardingTTL    = 90 * 24 * time.Hour
	userActivityTTL      = 7 * 24 * time.Hour
	signupProgressDefTTL = 5 * time.Minute
	chatAttachDefTTL     = time.Hour

	activityMaxItems = 5
)

func uonboardingKey(tenantID, userID string) string {
	return fmt.Sprintf("%s%s:%s", userOnboardingKeyPfx, tenantID, userID)
}

func ulayoutKey(tenantID, userID string) string {
	return fmt.Sprintf("%s%s:%s", userLayoutKeyPfx, tenantID, userID)
}

func uactivityListKey(tenantID, userID, kind string) string {
	return fmt.Sprintf("%s%s:%s:%s", userActivityKeyPfx, tenantID, userID, kind)
}

func uactivityLastActiveKey(tenantID, userID string) string {
	return fmt.Sprintf("%s%s:%s:lastActive", userActivityKeyPfx, tenantID, userID)
}

func signupProgressKey(attemptID string) string { return signupProgressKeyPfx + attemptID }

func membershipCacheKey(userID string) string { return membershipCacheKeyPfx + userID }

func chatAttachKey(tenantID, attachmentID string) string {
	return fmt.Sprintf("%s%s:%s", chatAttachKeyPfx, tenantID, attachmentID)
}

// ============================================================================
// Wire-up
// ============================================================================

// WithUserStateRedis wires the Redis client used by the user-state RPC handlers.
func (s *DaemonServer) WithUserStateRedis(client goredis.UniversalClient) *DaemonServer {
	s.userStateRedis = client
	return s
}

func (s *DaemonServer) requireUserStateRedis() (goredis.UniversalClient, error) {
	if s.userStateRedis == nil {
		return nil, status_grpc.Error(codes.Unavailable, "user state Redis not yet initialised")
	}
	return s.userStateRedis, nil
}

// ============================================================================
// Shared context resolver
// ============================================================================

// resolveUserCtx reads tenant and user IDs from the request fields, falling back
// to the gRPC context populated by ext-authz when the fields are empty.
func resolveUserCtx(ctx context.Context, reqTenantID, reqUserID string) (tenantID, userID string, err error) {
	if reqTenantID != "" {
		tenantID = reqTenantID
	} else {
		t, ok := auth.TenantFromContext(ctx)
		if !ok || t.IsZero() {
			return "", "", status_grpc.Error(codes.PermissionDenied, "missing tenant in context")
		}
		tenantID = t.String()
	}
	if reqUserID != "" {
		userID = reqUserID
	} else {
		if id, idErr := auth.IdentityFromContext(ctx); idErr == nil {
			userID = id.Subject
		}
	}
	return tenantID, userID, nil
}

func userStateWarn(logger interface {
	WarnContext(ctx context.Context, msg string, args ...any)
}, ctx context.Context, msg string, err error, tenantID, userID string) {
	logger.WarnContext(ctx, msg,
		slog.String("tenant_id", tenantID),
		slog.String("user_id", userID),
		slog.String("error", err.Error()),
	)
}

// ============================================================================
// 1. User Onboarding State
// ============================================================================

func defaultUserOnboardingState(tenantID, userID string) *tenantv1.UserOnboardingState {
	now := time.Now().UTC().Format(time.RFC3339)
	return &tenantv1.UserOnboardingState{
		UserId:          userID,
		TenantId:        tenantID,
		WizardCompleted: false,
		WizardSkipped:   false,
		CurrentStepId:   "welcome",
		CompletedSteps:  []string{},
		SkippedSteps:    []string{},
		SetupTasks:      defaultSetupTasks(),
		StartedAt:       now,
		UpdatedAt:       now,
		Version:         1,
	}
}

func defaultSetupTasks() []*tenantv1.OnboardingSetupTask {
	return []*tenantv1.OnboardingSetupTask{
		{Id: "configure_llm", Status: "pending", Category: "essential", EstimatedMinutes: 5},
		{Id: "select_agent", Status: "pending", Category: "essential", EstimatedMinutes: 3},
		{Id: "create_mission", Status: "pending", Category: "essential", EstimatedMinutes: 5},
		{Id: "invite_team", Status: "pending", Category: "recommended", EstimatedMinutes: 3},
		{Id: "explore_findings", Status: "pending", Category: "optional", EstimatedMinutes: 10},
	}
}

// GetUserOnboardingState implements UserServiceServer.
func (s *DaemonServer) GetUserOnboardingState(
	ctx context.Context,
	req *tenantv1.GetUserOnboardingStateRequest,
) (*tenantv1.GetUserOnboardingStateResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}

	raw, rErr := rc.Get(ctx, uonboardingKey(tenant, userID)).Result()
	if rErr == goredis.Nil {
		state := defaultUserOnboardingState(tenant, userID)
		if wErr := persistOnboardingState(ctx, rc, tenant, userID, state); wErr != nil {
			userStateWarn(s.logger, ctx, "GetUserOnboardingState: failed to write default", wErr, tenant, userID)
		}
		return &tenantv1.GetUserOnboardingStateResponse{State: state}, nil
	}
	if rErr != nil {
		userStateWarn(s.logger, ctx, "GetUserOnboardingState: Redis read failed", rErr, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to read onboarding state")
	}
	var state tenantv1.UserOnboardingState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		userStateWarn(s.logger, ctx, "GetUserOnboardingState: unmarshal failed", err, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to parse onboarding state")
	}
	return &tenantv1.GetUserOnboardingStateResponse{State: &state}, nil
}

// UpdateUserOnboardingState implements UserServiceServer.
func (s *DaemonServer) UpdateUserOnboardingState(
	ctx context.Context,
	req *tenantv1.UpdateUserOnboardingStateRequest,
) (*tenantv1.UpdateUserOnboardingStateResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetState() == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "state is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	state := req.GetState()
	state.UserId = userID
	state.TenantId = tenant
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if wErr := persistOnboardingState(ctx, rc, tenant, userID, state); wErr != nil {
		return nil, wErr
	}
	return &tenantv1.UpdateUserOnboardingStateResponse{State: state}, nil
}

// ResetUserOnboardingState implements UserServiceServer.
func (s *DaemonServer) ResetUserOnboardingState(
	ctx context.Context,
	req *tenantv1.ResetUserOnboardingStateRequest,
) (*tenantv1.ResetUserOnboardingStateResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	state := defaultUserOnboardingState(tenant, userID)
	if wErr := persistOnboardingState(ctx, rc, tenant, userID, state); wErr != nil {
		return nil, wErr
	}
	return &tenantv1.ResetUserOnboardingStateResponse{State: state}, nil
}

func persistOnboardingState(
	ctx context.Context,
	rc goredis.UniversalClient,
	tenantID, userID string,
	state *tenantv1.UserOnboardingState,
) error {
	b, err := json.Marshal(state)
	if err != nil {
		return status_grpc.Errorf(codes.Internal, "failed to marshal onboarding state: %v", err)
	}
	if rErr := rc.Set(ctx, uonboardingKey(tenantID, userID), b, userOnboardingTTL).Err(); rErr != nil {
		return status_grpc.Error(codes.Internal, "failed to persist onboarding state")
	}
	return nil
}

// ============================================================================
// 2. User Layout Preferences
// ============================================================================

func defaultLayoutPreferences() *tenantv1.UserLayoutPreferences {
	return &tenantv1.UserLayoutPreferences{
		Cols:      12,
		RowHeight: 80,
		Widgets: []*tenantv1.WidgetConfig{
			{Id: "kpi-summary", Type: "kpi-summary", Position: &tenantv1.WidgetPosition{X: 0, Y: 0, W: 12, H: 2}, Visible: true},
			{Id: "findings-chart", Type: "findings-chart", Position: &tenantv1.WidgetPosition{X: 0, Y: 2, W: 8, H: 4}, Visible: true},
			{Id: "severity-distribution", Type: "severity-distribution", Position: &tenantv1.WidgetPosition{X: 8, Y: 2, W: 4, H: 4}, Visible: true},
			{Id: "mission-heatmap", Type: "mission-heatmap", Position: &tenantv1.WidgetPosition{X: 0, Y: 6, W: 6, H: 4}, Visible: true},
			{Id: "agent-performance", Type: "agent-performance", Position: &tenantv1.WidgetPosition{X: 6, Y: 6, W: 6, H: 4}, Visible: true},
		},
	}
}

// GetUserLayout implements UserServiceServer.
func (s *DaemonServer) GetUserLayout(
	ctx context.Context,
	req *tenantv1.GetUserLayoutRequest,
) (*tenantv1.GetUserLayoutResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	raw, rErr := rc.Get(ctx, ulayoutKey(tenant, userID)).Result()
	if rErr == goredis.Nil {
		return &tenantv1.GetUserLayoutResponse{Layout: defaultLayoutPreferences(), IsDefault: true}, nil
	}
	if rErr != nil {
		userStateWarn(s.logger, ctx, "GetUserLayout: Redis read failed", rErr, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to read layout")
	}
	var layout tenantv1.UserLayoutPreferences
	if err := json.Unmarshal([]byte(raw), &layout); err != nil {
		userStateWarn(s.logger, ctx, "GetUserLayout: unmarshal failed", err, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to parse layout")
	}
	return &tenantv1.GetUserLayoutResponse{Layout: &layout, IsDefault: false}, nil
}

// SaveUserLayout implements UserServiceServer.
func (s *DaemonServer) SaveUserLayout(
	ctx context.Context,
	req *tenantv1.SaveUserLayoutRequest,
) (*tenantv1.SaveUserLayoutResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetLayout() == nil || len(req.GetLayout().GetWidgets()) == 0 {
		return nil, status_grpc.Error(codes.InvalidArgument, "layout with at least one widget is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(req.GetLayout())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to marshal layout: %v", err)
	}
	if rErr := rc.Set(ctx, ulayoutKey(tenant, userID), b, 0).Err(); rErr != nil {
		userStateWarn(s.logger, ctx, "SaveUserLayout: Redis write failed", rErr, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to persist layout")
	}
	return &tenantv1.SaveUserLayoutResponse{Layout: req.GetLayout()}, nil
}

// ResetUserLayout implements UserServiceServer.
func (s *DaemonServer) ResetUserLayout(
	ctx context.Context,
	req *tenantv1.ResetUserLayoutRequest,
) (*tenantv1.ResetUserLayoutResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	if rErr := rc.Del(ctx, ulayoutKey(tenant, userID)).Err(); rErr != nil && rErr != goredis.Nil {
		userStateWarn(s.logger, ctx, "ResetUserLayout: Redis delete failed", rErr, tenant, userID)
		return nil, status_grpc.Error(codes.Internal, "failed to reset layout")
	}
	return &tenantv1.ResetUserLayoutResponse{}, nil
}

// ============================================================================
// 3. User Activity Feed
// ============================================================================

// GetUserActivity implements UserServiceServer.
func (s *DaemonServer) GetUserActivity(
	ctx context.Context,
	req *tenantv1.GetUserActivityRequest,
) (*tenantv1.GetUserActivityResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}

	pipe := rc.Pipeline()
	missionsCmd := pipe.LRange(ctx, uactivityListKey(tenant, userID, "mission"), 0, activityMaxItems-1)
	nodesCmd := pipe.LRange(ctx, uactivityListKey(tenant, userID, "node"), 0, activityMaxItems-1)
	findingsCmd := pipe.LRange(ctx, uactivityListKey(tenant, userID, "finding"), 0, activityMaxItems-1)
	lastCmd := pipe.Get(ctx, uactivityLastActiveKey(tenant, userID))
	if _, pErr := pipe.Exec(ctx); pErr != nil && pErr != goredis.Nil {
		userStateWarn(s.logger, ctx, "GetUserActivity: pipeline failed", pErr, tenant, userID)
		return &tenantv1.GetUserActivityResponse{Activity: &tenantv1.UserActivityContext{}}, nil
	}

	missionsRaw, _ := missionsCmd.Result()
	nodesRaw, _ := nodesCmd.Result()
	findingsRaw, _ := findingsCmd.Result()
	lastActiveStr, _ := lastCmd.Result()

	return &tenantv1.GetUserActivityResponse{
		Activity: &tenantv1.UserActivityContext{
			RecentMissions:   parseActivityItems(missionsRaw),
			RecentNodes:      parseActivityItems(nodesRaw),
			RecentFindings:   parseActivityItems(findingsRaw),
			LastActiveAtUnix: parseLastActive(lastActiveStr),
		},
	}, nil
}

// RecordUserActivity implements UserServiceServer.
func (s *DaemonServer) RecordUserActivity(
	ctx context.Context,
	req *tenantv1.RecordUserActivityRequest,
) (*tenantv1.RecordUserActivityResponse, error) {
	tenant, userID, err := resolveUserCtx(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetItem() == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "item is required")
	}
	if req.GetKind() == tenantv1.ActivityKind_ACTIVITY_KIND_UNSPECIFIED {
		return nil, status_grpc.Error(codes.InvalidArgument, "kind must be specified")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}

	kindStr := activityKindStr(req.GetKind())
	listKey := uactivityListKey(tenant, userID, kindStr)
	lastKey := uactivityLastActiveKey(tenant, userID)
	nowMs := fmt.Sprintf("%d", time.Now().UnixMilli())

	itemJSON, err := json.Marshal(req.GetItem())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to marshal activity item: %v", err)
	}

	pipe := rc.Pipeline()
	pipe.LPush(ctx, listKey, string(itemJSON))
	pipe.LTrim(ctx, listKey, 0, activityMaxItems-1)
	pipe.Expire(ctx, listKey, userActivityTTL)
	pipe.Set(ctx, lastKey, nowMs, userActivityTTL)
	if _, pErr := pipe.Exec(ctx); pErr != nil {
		userStateWarn(s.logger, ctx, "RecordUserActivity: pipeline failed (non-fatal)", pErr, tenant, userID)
		// Fire-and-forget — don't fail the caller on non-critical recording.
	}
	return &tenantv1.RecordUserActivityResponse{}, nil
}

func parseActivityItems(raw []string) []*tenantv1.ActivityItem {
	out := make([]*tenantv1.ActivityItem, 0, len(raw))
	for _, s := range raw {
		var item tenantv1.ActivityItem
		if jsonErr := json.Unmarshal([]byte(s), &item); jsonErr == nil {
			out = append(out, &item)
		}
	}
	return out
}

func parseLastActive(s string) int64 {
	if s == "" {
		return 0
	}
	var ms int64
	if _, err := fmt.Sscanf(s, "%d", &ms); err != nil {
		return 0
	}
	return ms
}

func activityKindStr(k tenantv1.ActivityKind) string {
	switch k {
	case tenantv1.ActivityKind_ACTIVITY_KIND_MISSION:
		return "mission"
	case tenantv1.ActivityKind_ACTIVITY_KIND_NODE:
		return "node"
	case tenantv1.ActivityKind_ACTIVITY_KIND_FINDING:
		return "finding"
	default:
		return "unknown"
	}
}

// ============================================================================
// 4. Signup Progress
// ============================================================================

// GetSignupProgress implements UserServiceServer.
// This RPC is unauthenticated — no tenant/user context is needed.
func (s *DaemonServer) GetSignupProgress(
	ctx context.Context,
	req *tenantv1.GetSignupProgressRequest,
) (*tenantv1.GetSignupProgressResponse, error) {
	if req.GetAttemptId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "attempt_id is required")
	}
	if !isUUID(req.GetAttemptId()) {
		return nil, status_grpc.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	raw, rErr := rc.Get(ctx, signupProgressKey(req.GetAttemptId())).Result()
	if rErr == goredis.Nil {
		return &tenantv1.GetSignupProgressResponse{Found: false}, nil
	}
	if rErr != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to read signup progress")
	}
	var progress tenantv1.SignupProgressState
	if err := json.Unmarshal([]byte(raw), &progress); err != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to parse signup progress")
	}
	return &tenantv1.GetSignupProgressResponse{Progress: &progress, Found: true}, nil
}

// SetSignupProgress implements UserServiceServer.
func (s *DaemonServer) SetSignupProgress(
	ctx context.Context,
	req *tenantv1.SetSignupProgressRequest,
) (*tenantv1.SetSignupProgressResponse, error) {
	if req.GetAttemptId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "attempt_id is required")
	}
	if !isUUID(req.GetAttemptId()) {
		return nil, status_grpc.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	if req.GetProgress() == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "progress is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	ttl := signupProgressDefTTL
	if req.GetTtlSeconds() > 0 {
		ttl = time.Duration(req.GetTtlSeconds()) * time.Second
	}
	b, err := json.Marshal(req.GetProgress())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to marshal progress: %v", err)
	}
	if rErr := rc.Set(ctx, signupProgressKey(req.GetAttemptId()), b, ttl).Err(); rErr != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to write signup progress")
	}
	return &tenantv1.SetSignupProgressResponse{}, nil
}

// ============================================================================
// 5. Membership Cache Invalidation
// ============================================================================

// InvalidateMembershipCache implements UserServiceServer.
func (s *DaemonServer) InvalidateMembershipCache(
	ctx context.Context,
	req *tenantv1.InvalidateMembershipCacheRequest,
) (*tenantv1.InvalidateMembershipCacheResponse, error) {
	if req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	if rErr := rc.Del(ctx, membershipCacheKey(req.GetUserId())).Err(); rErr != nil && rErr != goredis.Nil {
		s.logger.WarnContext(ctx, "InvalidateMembershipCache: Redis delete failed",
			slog.String("user_id", req.GetUserId()),
			slog.String("error", rErr.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to invalidate membership cache")
	}
	return &tenantv1.InvalidateMembershipCacheResponse{}, nil
}

// ============================================================================
// 6. Chat Attachment Staging
// ============================================================================

// StageAttachment implements UserServiceServer.
func (s *DaemonServer) StageAttachment(
	ctx context.Context,
	req *tenantv1.StageAttachmentRequest,
) (*tenantv1.StageAttachmentResponse, error) {
	tenant, _, err := resolveUserCtx(ctx, req.GetTenantId(), "")
	if err != nil {
		return nil, err
	}
	if req.GetText() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "text is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	ttl := chatAttachDefTTL
	if req.GetTtlSeconds() > 0 {
		ttl = time.Duration(req.GetTtlSeconds()) * time.Second
	}
	attachmentID := mintUUID()
	if rErr := rc.Set(ctx, chatAttachKey(tenant, attachmentID), req.GetText(), ttl).Err(); rErr != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to stage attachment")
	}
	return &tenantv1.StageAttachmentResponse{AttachmentId: attachmentID}, nil
}

// ConsumeAttachment implements UserServiceServer.
func (s *DaemonServer) ConsumeAttachment(
	ctx context.Context,
	req *tenantv1.ConsumeAttachmentRequest,
) (*tenantv1.ConsumeAttachmentResponse, error) {
	tenant, _, err := resolveUserCtx(ctx, req.GetTenantId(), "")
	if err != nil {
		return nil, err
	}
	if req.GetAttachmentId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "attachment_id is required")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	// GETDEL atomically reads and deletes — prevents replay of a stolen attachment_id.
	text, rErr := rc.GetDel(ctx, chatAttachKey(tenant, req.GetAttachmentId())).Result()
	if rErr == goredis.Nil {
		return nil, status_grpc.Error(codes.NotFound, "attachment not found or expired")
	}
	if rErr != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to consume attachment")
	}
	return &tenantv1.ConsumeAttachmentResponse{Text: text}, nil
}

// ============================================================================
// Small helpers
// ============================================================================

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func mintUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely path — fall back to time-based nonce.
		now := time.Now().UnixNano()
		return fmt.Sprintf("%016x-%d", now, now>>32)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
