// Package api — user_state_test.go
//
// Round-trip and cross-tenant isolation tests for the per-user Redis-backed
// RPC handlers (Module 2: Redis-read RPCs).
//
// All tests use miniredis (in-process Redis) and two tenant contexts
// (tenant-A, tenant-B) to verify isolation at the key level.
package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newUserStateServer starts a miniredis instance and wires it into a DaemonServer.
// It returns the server plus a cleanup function that stops the miniredis.
func newUserStateServer(t *testing.T) *DaemonServer {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	srv := &DaemonServer{logger: testSlogLogger}
	srv.WithUserStateRedis(client)
	return srv
}

// tenantAndSubjectCtx returns a context with both tenant and subject installed.
func tenantAndSubjectCtx(tenantID, subject string) context.Context {
	t, _ := auth.NewTenantID(tenantID)
	// Set both Tenant and Subject in a single WithIdentity call — calling
	// WithTenant then WithIdentity replaces the identity and loses the tenant.
	return auth.WithIdentity(context.Background(), auth.Identity{
		Tenant:  t,
		Subject: subject,
	})
}

// ---------------------------------------------------------------------------
// User Onboarding State
// ---------------------------------------------------------------------------

func TestGetUserOnboardingState_DefaultForNewUser(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	resp, err := srv.GetUserOnboardingState(ctx, &userv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.GetState())
	assert.Equal(t, "user-1", resp.GetState().GetUserId())
	assert.Equal(t, "tenant-a", resp.GetState().GetTenantId())
	assert.False(t, resp.GetState().GetWizardCompleted())
	assert.Equal(t, "welcome", resp.GetState().GetCurrentStepId())
	assert.NotEmpty(t, resp.GetState().GetSetupTasks())
}

func TestGetUserOnboardingState_RoundTrip(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// First GET creates the default.
	_, err := srv.GetUserOnboardingState(ctx, &userv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)

	// Update.
	state := &userv1.UserOnboardingState{
		UserId:          "user-1",
		TenantId:        "tenant-a",
		WizardCompleted: true,
		CurrentStepId:   "completion",
		CompletedSteps:  []string{"welcome", "llm-provider", "completion"},
		Version:         1,
	}
	_, err = srv.UpdateUserOnboardingState(ctx, &userv1.UpdateUserOnboardingStateRequest{
		State: state,
	})
	require.NoError(t, err)

	// Read back.
	resp, err := srv.GetUserOnboardingState(ctx, &userv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetState().GetWizardCompleted())
	assert.Equal(t, "completion", resp.GetState().GetCurrentStepId())
}

func TestGetUserOnboardingState_CrossTenantIsolation(t *testing.T) {
	srv := newUserStateServer(t)

	// User-1 in tenant-A sets a custom state.
	ctxA := tenantAndSubjectCtx("tenant-a", "user-1")
	state := &userv1.UserOnboardingState{
		WizardCompleted: true,
		CurrentStepId:   "completion",
	}
	_, err := srv.UpdateUserOnboardingState(ctxA, &userv1.UpdateUserOnboardingStateRequest{
		State: state,
	})
	require.NoError(t, err)

	// User-1 in tenant-B sees a fresh default (different key).
	ctxB := tenantAndSubjectCtx("tenant-b", "user-1")
	resp, err := srv.GetUserOnboardingState(ctxB, &userv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)
	assert.False(t, resp.GetState().GetWizardCompleted(), "tenant-B must not see tenant-A's state")
}

func TestResetUserOnboardingState(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// Advance past default.
	_, err := srv.UpdateUserOnboardingState(ctx, &userv1.UpdateUserOnboardingStateRequest{
		State: &userv1.UserOnboardingState{WizardCompleted: true, CurrentStepId: "completion"},
	})
	require.NoError(t, err)

	// Reset.
	resp, err := srv.ResetUserOnboardingState(ctx, &userv1.ResetUserOnboardingStateRequest{})
	require.NoError(t, err)
	assert.False(t, resp.GetState().GetWizardCompleted())
	assert.Equal(t, "welcome", resp.GetState().GetCurrentStepId())
}

// ---------------------------------------------------------------------------
// User Layout Preferences
// ---------------------------------------------------------------------------

func TestGetUserLayout_DefaultWhenNoneSaved(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	resp, err := srv.GetUserLayout(ctx, &userv1.GetUserLayoutRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetIsDefault())
	assert.Equal(t, int32(12), resp.GetLayout().GetCols())
	assert.NotEmpty(t, resp.GetLayout().GetWidgets())
}

func TestSaveUserLayout_RoundTrip(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	layout := &userv1.UserLayoutPreferences{
		Cols:      8,
		RowHeight: 100,
		Widgets: []*userv1.WidgetConfig{
			{Id: "w1", Type: "kpi-summary", Position: &userv1.WidgetPosition{X: 0, Y: 0, W: 8, H: 2}, Visible: true},
		},
	}
	saveResp, err := srv.SaveUserLayout(ctx, &userv1.SaveUserLayoutRequest{Layout: layout})
	require.NoError(t, err)
	assert.Equal(t, int32(8), saveResp.GetLayout().GetCols())

	getResp, err := srv.GetUserLayout(ctx, &userv1.GetUserLayoutRequest{})
	require.NoError(t, err)
	assert.False(t, getResp.GetIsDefault())
	assert.Equal(t, int32(8), getResp.GetLayout().GetCols())
	assert.Equal(t, int32(100), getResp.GetLayout().GetRowHeight())
}

func TestSaveUserLayout_CrossTenantIsolation(t *testing.T) {
	srv := newUserStateServer(t)

	ctxA := tenantAndSubjectCtx("tenant-a", "user-1")
	layout := &userv1.UserLayoutPreferences{
		Cols:      4,
		RowHeight: 50,
		Widgets:   []*userv1.WidgetConfig{{Id: "w1", Type: "kpi-summary", Position: &userv1.WidgetPosition{X: 0, Y: 0, W: 4, H: 2}, Visible: true}},
	}
	_, err := srv.SaveUserLayout(ctxA, &userv1.SaveUserLayoutRequest{Layout: layout})
	require.NoError(t, err)

	ctxB := tenantAndSubjectCtx("tenant-b", "user-1")
	resp, err := srv.GetUserLayout(ctxB, &userv1.GetUserLayoutRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetIsDefault(), "tenant-B must not see tenant-A's layout")
}

func TestResetUserLayout(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// Save a custom layout.
	layout := &userv1.UserLayoutPreferences{
		Cols:    4,
		Widgets: []*userv1.WidgetConfig{{Id: "w1", Type: "kpi-summary", Position: &userv1.WidgetPosition{W: 4, H: 2}, Visible: true}},
	}
	_, err := srv.SaveUserLayout(ctx, &userv1.SaveUserLayoutRequest{Layout: layout})
	require.NoError(t, err)

	// Reset.
	_, err = srv.ResetUserLayout(ctx, &userv1.ResetUserLayoutRequest{})
	require.NoError(t, err)

	// Verify default is returned.
	resp, err := srv.GetUserLayout(ctx, &userv1.GetUserLayoutRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetIsDefault())
}

// ---------------------------------------------------------------------------
// User Activity Feed
// ---------------------------------------------------------------------------

func TestRecordAndGetUserActivity_RoundTrip(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	item := &userv1.ActivityItem{Id: "m1", Label: "My Mission", TimestampUnix: 1000}
	_, err := srv.RecordUserActivity(ctx, &userv1.RecordUserActivityRequest{
		Kind: userv1.ActivityKind_ACTIVITY_KIND_MISSION,
		Item: item,
	})
	require.NoError(t, err)

	resp, err := srv.GetUserActivity(ctx, &userv1.GetUserActivityRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetActivity().GetRecentMissions(), 1)
	assert.Equal(t, "m1", resp.GetActivity().GetRecentMissions()[0].GetId())
	assert.NotZero(t, resp.GetActivity().GetLastActiveAtUnix())
}

func TestGetUserActivity_CrossTenantIsolation(t *testing.T) {
	srv := newUserStateServer(t)

	ctxA := tenantAndSubjectCtx("tenant-a", "user-1")
	_, err := srv.RecordUserActivity(ctxA, &userv1.RecordUserActivityRequest{
		Kind: userv1.ActivityKind_ACTIVITY_KIND_MISSION,
		Item: &userv1.ActivityItem{Id: "m1", Label: "Tenant A Mission", TimestampUnix: 1000},
	})
	require.NoError(t, err)

	ctxB := tenantAndSubjectCtx("tenant-b", "user-1")
	resp, err := srv.GetUserActivity(ctxB, &userv1.GetUserActivityRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetActivity().GetRecentMissions(), "tenant-B must not see tenant-A's activity")
}

func TestRecordUserActivity_AllKinds(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	for _, tc := range []struct {
		kind userv1.ActivityKind
		id   string
	}{
		{userv1.ActivityKind_ACTIVITY_KIND_MISSION, "m1"},
		{userv1.ActivityKind_ACTIVITY_KIND_NODE, "n1"},
		{userv1.ActivityKind_ACTIVITY_KIND_FINDING, "f1"},
	} {
		_, err := srv.RecordUserActivity(ctx, &userv1.RecordUserActivityRequest{
			Kind: tc.kind,
			Item: &userv1.ActivityItem{Id: tc.id, TimestampUnix: 1},
		})
		require.NoError(t, err)
	}

	resp, err := srv.GetUserActivity(ctx, &userv1.GetUserActivityRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.GetActivity().GetRecentMissions(), 1)
	assert.Len(t, resp.GetActivity().GetRecentNodes(), 1)
	assert.Len(t, resp.GetActivity().GetRecentFindings(), 1)
}

func TestRecordUserActivity_MaxItemsTrimmed(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// Insert 7 items; the list must be trimmed to 5.
	for i := 0; i < 7; i++ {
		item, _ := json.Marshal(userv1.ActivityItem{Id: "m" + string(rune('0'+i)), TimestampUnix: int64(i)})
		_ = item
		_, err := srv.RecordUserActivity(ctx, &userv1.RecordUserActivityRequest{
			Kind: userv1.ActivityKind_ACTIVITY_KIND_MISSION,
			Item: &userv1.ActivityItem{Id: "m" + string(rune('0'+i)), TimestampUnix: int64(i)},
		})
		require.NoError(t, err)
	}

	resp, err := srv.GetUserActivity(ctx, &userv1.GetUserActivityRequest{})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(resp.GetActivity().GetRecentMissions()), activityMaxItems,
		"activity list must be trimmed to %d", activityMaxItems)
}

// ---------------------------------------------------------------------------
// Signup Progress
// ---------------------------------------------------------------------------

func TestSignupProgress_RoundTrip(t *testing.T) {
	srv := newUserStateServer(t)
	// GetSignupProgress is unauthenticated.
	ctx := context.Background()

	id := mintUUID()
	progress := &userv1.SignupProgressState{
		Step:              "create_user",
		StepStartedAtUnix: 1000,
	}

	// Write (authenticated call — simulate with tenant context).
	authCtx := tenantAndSubjectCtx("tenant-a", "user-1")
	_, err := srv.SetSignupProgress(authCtx, &userv1.SetSignupProgressRequest{
		AttemptId: id,
		Progress:  progress,
	})
	require.NoError(t, err)

	// Poll (unauthenticated).
	resp, err := srv.GetSignupProgress(ctx, &userv1.GetSignupProgressRequest{AttemptId: id})
	require.NoError(t, err)
	assert.True(t, resp.GetFound())
	assert.Equal(t, "create_user", resp.GetProgress().GetStep())
}

func TestGetSignupProgress_NotFound(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := context.Background()

	unknownID := mintUUID()
	resp, err := srv.GetSignupProgress(ctx, &userv1.GetSignupProgressRequest{AttemptId: unknownID})
	require.NoError(t, err)
	assert.False(t, resp.GetFound())
	assert.Nil(t, resp.GetProgress())
}

func TestGetSignupProgress_InvalidUUID(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := context.Background()

	_, err := srv.GetSignupProgress(ctx, &userv1.GetSignupProgressRequest{AttemptId: "not-a-uuid"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

// ---------------------------------------------------------------------------
// Membership Cache Invalidation
// ---------------------------------------------------------------------------

func TestInvalidateMembershipCache_Idempotent(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// Invalidate a key that doesn't exist — must succeed.
	_, err := srv.InvalidateMembershipCache(ctx, &userv1.InvalidateMembershipCacheRequest{UserId: "sub-123"})
	require.NoError(t, err)

	// Set a fake cache entry directly.
	rc := srv.userStateRedis
	require.NoError(t, rc.Set(ctx, membershipCacheKey("sub-123"), `[{"role":"admin"}]`, 0).Err())

	// Invalidate again — must succeed and delete the key.
	_, err = srv.InvalidateMembershipCache(ctx, &userv1.InvalidateMembershipCacheRequest{UserId: "sub-123"})
	require.NoError(t, err)

	// Key must be gone.
	exists, err := rc.Exists(ctx, membershipCacheKey("sub-123")).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists)
}

// ---------------------------------------------------------------------------
// Chat Attachment Staging
// ---------------------------------------------------------------------------

func TestChatAttachment_StageAndConsume(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	// Stage.
	stageResp, err := srv.StageAttachment(ctx, &userv1.StageAttachmentRequest{Text: "hello world"})
	require.NoError(t, err)
	require.NotEmpty(t, stageResp.GetAttachmentId())

	// Consume.
	consumeResp, err := srv.ConsumeAttachment(ctx, &userv1.ConsumeAttachmentRequest{
		AttachmentId: stageResp.GetAttachmentId(),
	})
	require.NoError(t, err)
	assert.Equal(t, "hello world", consumeResp.GetText())
}

func TestChatAttachment_SingleUse(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	stageResp, err := srv.StageAttachment(ctx, &userv1.StageAttachmentRequest{Text: "once"})
	require.NoError(t, err)

	// First consume succeeds.
	_, err = srv.ConsumeAttachment(ctx, &userv1.ConsumeAttachmentRequest{
		AttachmentId: stageResp.GetAttachmentId(),
	})
	require.NoError(t, err)

	// Second consume must return NotFound (key was deleted).
	_, err = srv.ConsumeAttachment(ctx, &userv1.ConsumeAttachmentRequest{
		AttachmentId: stageResp.GetAttachmentId(),
	})
	assert.Equal(t, codes.NotFound, grpcCode(err), "second consume must return NotFound")
}

func TestChatAttachment_CrossTenantIsolation(t *testing.T) {
	srv := newUserStateServer(t)

	ctxA := tenantAndSubjectCtx("tenant-a", "user-1")
	stageResp, err := srv.StageAttachment(ctxA, &userv1.StageAttachmentRequest{Text: "secret"})
	require.NoError(t, err)

	// Tenant B with the same attachment_id must not find the attachment.
	ctxB := tenantAndSubjectCtx("tenant-b", "user-1")
	_, err = srv.ConsumeAttachment(ctxB, &userv1.ConsumeAttachmentRequest{
		AttachmentId: stageResp.GetAttachmentId(),
	})
	assert.Equal(t, codes.NotFound, grpcCode(err), "tenant-B must not access tenant-A's attachment")
}

func TestStageAttachment_EmptyTextRejected(t *testing.T) {
	srv := newUserStateServer(t)
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")
	_, err := srv.StageAttachment(ctx, &userv1.StageAttachmentRequest{Text: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

// ---------------------------------------------------------------------------
// Unavailable when Redis not wired
// ---------------------------------------------------------------------------

func TestUserStateHandlers_UnavailableWithoutRedis(t *testing.T) {
	srv := &DaemonServer{logger: testSlogLogger}
	// No WithUserStateRedis call.
	ctx := tenantAndSubjectCtx("tenant-a", "user-1")

	cases := []struct {
		name string
		call func() error
	}{
		{"GetUserOnboardingState", func() error {
			_, err := srv.GetUserOnboardingState(ctx, &userv1.GetUserOnboardingStateRequest{})
			return err
		}},
		{"GetUserLayout", func() error {
			_, err := srv.GetUserLayout(ctx, &userv1.GetUserLayoutRequest{})
			return err
		}},
		{"GetUserActivity", func() error {
			_, err := srv.GetUserActivity(ctx, &userv1.GetUserActivityRequest{})
			return err
		}},
		{"SetSignupProgress", func() error {
			_, err := srv.SetSignupProgress(ctx, &userv1.SetSignupProgressRequest{
				AttemptId: mintUUID(),
				Progress:  &userv1.SignupProgressState{Step: "x"},
			})
			return err
		}},
		{"InvalidateMembershipCache", func() error {
			_, err := srv.InvalidateMembershipCache(ctx, &userv1.InvalidateMembershipCacheRequest{UserId: "u1"})
			return err
		}},
		{"StageAttachment", func() error {
			_, err := srv.StageAttachment(ctx, &userv1.StageAttachmentRequest{Text: "x"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			assert.Equal(t, codes.Unavailable, grpcCode(err),
				"%s: must return Unavailable when Redis not wired", tc.name)
		})
	}
}
