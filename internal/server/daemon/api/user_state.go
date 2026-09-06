// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// Bounds on the signup-progress store.
//
// SetSignupProgress is a pre-authentication surface: it is annotated
// unauthenticated in the authz registry because it runs before any identity
// exists, and it keys on an attempt_id the caller invents. There is therefore
// no subject to scope a key to and no owner to check a write against — the
// UUID shape is the only thing distinguishing one caller's key from another's,
// and it is not a secret in any meaningful sense.
//
// What is left is to bound what an unattributable caller can occupy: how long
// a document lives, how large it is, and how many can exist at once. Each of
// the three was previously unbounded — in particular ttl_seconds was taken
// verbatim, so a caller chose how long its key stayed resident in a Redis the
// rest of the platform shares.
const (
	// signupProgressMaxTTL caps ttl_seconds. Signup is a single sitting; five
	// minutes is the default and an hour is already far past any real flow.
	signupProgressMaxTTL = time.Hour

	// signupProgressMaxBytes caps one serialised progress document.
	signupProgressMaxBytes = 8 << 10

	// signupProgressMaxOutstanding caps how many progress documents may be
	// live at once. Reaching it evicts the least recently written, so a burst
	// costs the burst's own documents rather than the store.
	signupProgressMaxOutstanding = 5000

	// signupProgressIndexKey is the sorted set that makes the cap enforceable:
	// attempt ids scored by write time. It is not itself the data — losing it
	// costs eviction ordering, not correctness.
	signupProgressIndexKey = signupProgressKeyPfx + "index"
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

// resolveUserCtx returns the (tenant, user) pair every user-state key in this
// file is built from. Both values come exclusively from the identity that
// ext-authz established on the gRPC context.
//
// The tenant_id / user_id fields on these requests are deliberately NOT read.
// ext-authz authorizes each UserService RPC against an object derived from the
// caller's own identity (`object_deriver: tenant_from_identity`); no deriver
// inspects a request body, so a tenant or user id arriving on the wire is
// authorized by nothing and must never select the key space. An RPC that
// genuinely needs to name another tenant must gate on requireTenantAdmin.
//
// Fails closed: a request with no tenant, or no caller subject, is rejected
// rather than served against a partially-empty key.
func resolveUserCtx(ctx context.Context) (tenantID, userID string, err error) {
	tenantID, err = resolveTenantCtx(ctx)
	if err != nil {
		return "", "", err
	}
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || id.Subject == "" {
		return "", "", status_grpc.Error(codes.PermissionDenied, "missing caller identity in context")
	}
	return tenantID, id.Subject, nil
}

// resolveTenantCtx is the tenant-only variant of resolveUserCtx, for the
// handlers whose key space is tenant-scoped but not user-scoped. Same rule:
// the tenant comes from the authenticated context, never from the request.
func resolveTenantCtx(ctx context.Context) (string, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok || t.IsZero() {
		return "", status_grpc.Error(codes.PermissionDenied, "missing tenant in context")
	}
	return t.String(), nil
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	tenant, userID, err := resolveUserCtx(ctx)
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
	ttl := clampSignupProgressTTL(req.GetTtlSeconds())
	b, err := json.Marshal(req.GetProgress())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to marshal progress: %v", err)
	}
	if len(b) > signupProgressMaxBytes {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"progress is larger than the %d-byte limit", signupProgressMaxBytes)
	}
	// The injected signup clock, not the wall clock: this timestamp is the
	// index's ordering key and the input to the staleness cut-off, so it is
	// exactly the kind of time a test needs to move forward.
	now := s.signupNow()
	pipe := rc.Pipeline()
	pipe.Set(ctx, signupProgressKey(req.GetAttemptId()), b, ttl)
	pipe.ZAdd(ctx, signupProgressIndexKey, goredis.Z{
		Score:  float64(now.UnixMilli()),
		Member: req.GetAttemptId(),
	})
	pipe.Expire(ctx, signupProgressIndexKey, signupProgressMaxTTL)
	if _, rErr := pipe.Exec(ctx); rErr != nil {
		return nil, status_grpc.Error(codes.Internal, "failed to write signup progress")
	}
	s.trimSignupProgress(ctx, rc, now)
	return &tenantv1.SetSignupProgressResponse{}, nil
}

// clampSignupProgressTTL turns the request's ttl_seconds into a lifetime the
// daemon is willing to hold.
//
// The field used to be taken verbatim, so the caller — unauthenticated, on a
// key it named itself — decided how long its document occupied a Redis the
// whole platform shares. Absent or non-positive means the default; anything
// above the cap is clamped rather than refused, because a caller asking for
// too long is asking for something harmless once it is bounded.
func clampSignupProgressTTL(ttlSeconds int32) time.Duration {
	if ttlSeconds <= 0 {
		return signupProgressDefTTL
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl > signupProgressMaxTTL {
		return signupProgressMaxTTL
	}
	return ttl
}

// trimSignupProgress holds the number of live progress documents at or below
// signupProgressMaxOutstanding by dropping the least recently written, and
// clears index entries whose document has already expired on its own.
//
// Best-effort by design: it runs after the write has been acknowledged, and a
// failure here costs eviction ordering, not the caller's request. The cap is
// the reason the index exists — without it, an unauthenticated caller's only
// limit on how many keys it could create was how many UUIDs it cared to
// generate.
func (s *DaemonServer) trimSignupProgress(ctx context.Context, rc goredis.UniversalClient, now time.Time) {
	if err := trimSignupProgressIndex(ctx, rc, now); err != nil {
		userStateWarn(s.logger, ctx, "SetSignupProgress: index maintenance failed (non-fatal)", err, "", "")
	}
}

// trimSignupProgressIndex does the work, returning the first failure rather
// than logging at each step, so the whole routine has one reporting site.
func trimSignupProgressIndex(ctx context.Context, rc goredis.UniversalClient, now time.Time) error {
	// Entries older than the maximum TTL cannot have a live document behind
	// them, so they are index litter rather than outstanding attempts.
	staleBefore := now.Add(-signupProgressMaxTTL).UnixMilli()
	if err := rc.ZRemRangeByScore(ctx, signupProgressIndexKey,
		"-inf", strconv.FormatInt(staleBefore, 10)).Err(); err != nil {
		return fmt.Errorf("prune expired index entries: %w", err)
	}

	card, err := rc.ZCard(ctx, signupProgressIndexKey).Result()
	if err != nil {
		return fmt.Errorf("read index size: %w", err)
	}
	excess := card - signupProgressMaxOutstanding
	if excess <= 0 {
		return nil
	}

	oldest, err := rc.ZRange(ctx, signupProgressIndexKey, 0, excess-1).Result()
	if err != nil {
		return fmt.Errorf("read eviction candidates: %w", err)
	}
	if len(oldest) == 0 {
		return nil
	}

	keys := make([]string, 0, len(oldest))
	members := make([]any, 0, len(oldest))
	for _, attemptID := range oldest {
		keys = append(keys, signupProgressKey(attemptID))
		members = append(members, attemptID)
	}
	pipe := rc.Pipeline()
	pipe.Del(ctx, keys...)
	pipe.ZRem(ctx, signupProgressIndexKey, members...)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("evict oldest progress documents: %w", err)
	}
	return nil
}

// ============================================================================
// 5. Membership Cache Invalidation
// ============================================================================

// InvalidateMembershipCache implements UserServiceServer.
func (s *DaemonServer) InvalidateMembershipCache(
	ctx context.Context,
	req *tenantv1.InvalidateMembershipCacheRequest,
) (*tenantv1.InvalidateMembershipCacheResponse, error) {
	// The membership cache key is global (dashboard:memberships:user:<id>), not
	// tenant-prefixed, so the subject must be the caller themselves.
	// self-scoping is correct regardless of who calls this: no caller —
	// present or future — has a legitimate reason to evict another user's
	// cache entry from here. (There is in fact no production caller today:
	// dashboard/src/lib/auth/membership.ts's invalidateMembershipCache is
	// exported but never invoked outside its own file and tests. Self-
	// scoping still blocks the obvious next consumer — an admin evicting a
	// member they just removed — which would need a distinct admin-gated
	// RPC, not a relaxation of this one.)
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || id.Subject == "" {
		return nil, status_grpc.Error(codes.PermissionDenied, "missing caller identity in context")
	}
	if req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetUserId() != id.Subject {
		return nil, status_grpc.Error(codes.PermissionDenied, "user_id must be the calling user")
	}
	rc, err := s.requireUserStateRedis()
	if err != nil {
		return nil, err
	}
	if rErr := rc.Del(ctx, membershipCacheKey(id.Subject)).Err(); rErr != nil && !errors.Is(rErr, goredis.Nil) {
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
	tenant, err := resolveTenantCtx(ctx)
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
	tenant, err := resolveTenantCtx(ctx)
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
