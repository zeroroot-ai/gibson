// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ext-authz authorizes these RPCs against an object derived from the CALLER's
// identity (object_deriver: tenant_from_identity in the authz registry), so a
// tenant_id or user_id carried in the request body is authorized by nothing.
// These tests pin the resulting contract: the wire values never reach the
// store, and a request with no authenticated scope is refused outright rather
// than served from the body.

// scopeSpyConversationStore records the (tenant, user) scope each call was
// made with, so a test can assert on the key space the handler selected.
type scopeSpyConversationStore struct {
	tenantIDs []string
	userIDs   []string

	conversations []storedConversation
	messages      []storedMessage
}

func (m *scopeSpyConversationStore) Save(
	_ context.Context,
	tenantID, userID, _, _, _ string,
	_ []storedMessage,
) error {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, userID)
	return nil
}

func (m *scopeSpyConversationStore) List(_ context.Context, tenantID, userID string, _ int) ([]storedConversation, error) {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, userID)
	return m.conversations, nil
}

func (m *scopeSpyConversationStore) Get(_ context.Context, tenantID, callerUserID, _ string) (*storedConversation, []storedMessage, error) {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, callerUserID)
	if len(m.conversations) == 0 {
		return nil, nil, assert.AnError
	}
	return &m.conversations[0], m.messages, nil
}

func (m *scopeSpyConversationStore) Rename(_ context.Context, tenantID, callerUserID, _, _ string) error {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, callerUserID)
	return nil
}

func (m *scopeSpyConversationStore) Delete(_ context.Context, tenantID, userID, _ string) error {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, userID)
	return nil
}

const (
	chatCallerTenant  = "acme"
	chatCallerUser    = "caller-1"
	chatForeignTenant = "victim-co"
	chatForeignUser   = "victim-user"
)

// TestConversationRPCs_ForeignScopeIgnored is the chat half of the fix. The
// conversation store is keyed by (tenant, user); GetConversation in particular
// returns a full message history, so the tenant half of that key must come
// from the authenticated context and never from the request body.
func TestConversationRPCs_ForeignScopeIgnored(t *testing.T) {
	cases := []struct {
		name string
		// call issues the RPC with a foreign tenant_id/user_id in the body.
		call func(t *testing.T, srv *DaemonServer, ctx context.Context)
		// wantUserScoped is false for the RPCs that are tenant-scoped only.
		wantUserScoped bool
	}{
		{
			name: "ListConversations",
			call: func(t *testing.T, srv *DaemonServer, ctx context.Context) {
				t.Helper()
				_, err := srv.ListConversations(ctx, &tenantv1.ListConversationsRequest{
					TenantId: chatForeignTenant,
					UserId:   chatForeignUser,
				})
				require.NoError(t, err)
			},
			wantUserScoped: true,
		},
		{
			name: "GetConversation",
			call: func(t *testing.T, srv *DaemonServer, ctx context.Context) {
				t.Helper()
				_, err := srv.GetConversation(ctx, &tenantv1.GetConversationRequest{
					TenantId:       chatForeignTenant,
					ConversationId: "c1",
				})
				require.NoError(t, err)
			},
			wantUserScoped: true,
		},
		{
			name: "SaveConversation",
			call: func(t *testing.T, srv *DaemonServer, ctx context.Context) {
				t.Helper()
				_, err := srv.SaveConversation(ctx, &tenantv1.SaveConversationRequest{
					TenantId:       chatForeignTenant,
					UserId:         chatForeignUser,
					ConversationId: "c1",
					Title:          "t",
				})
				require.NoError(t, err)
			},
			wantUserScoped: true,
		},
		{
			name: "RenameConversation",
			call: func(t *testing.T, srv *DaemonServer, ctx context.Context) {
				t.Helper()
				_, err := srv.RenameConversation(ctx, &tenantv1.RenameConversationRequest{
					TenantId:       chatForeignTenant,
					ConversationId: "c1",
					Title:          "renamed",
				})
				require.NoError(t, err)
			},
			wantUserScoped: true,
		},
		{
			name: "DeleteConversation",
			call: func(t *testing.T, srv *DaemonServer, ctx context.Context) {
				t.Helper()
				_, err := srv.DeleteConversation(ctx, &tenantv1.DeleteConversationRequest{
					TenantId:       chatForeignTenant,
					ConversationId: "c1",
				})
				require.NoError(t, err)
			},
			wantUserScoped: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &scopeSpyConversationStore{
				conversations: []storedConversation{{ID: "c1", TenantID: chatCallerTenant, UserID: chatCallerUser}},
			}
			srv := blankServer()
			srv.conversationStore = spy

			tc.call(t, srv, tenantAndSubjectCtx(chatCallerTenant, chatCallerUser))

			require.NotEmpty(t, spy.tenantIDs, "the handler must have reached the store")
			for _, got := range spy.tenantIDs {
				assert.Equal(t, chatCallerTenant, got,
					"store was scoped to %q; the request tenant_id must never select the namespace", got)
			}
			if tc.wantUserScoped {
				require.NotEmpty(t, spy.userIDs)
				for _, got := range spy.userIDs {
					assert.Equal(t, chatCallerUser, got,
						"store was scoped to user %q; the request user_id must never select the subject", got)
				}
			}
		})
	}
}

// TestConversationRPCs_NoAuthenticatedScopeRejected proves the body cannot
// stand in for a missing context: with no tenant on the context, a request
// carrying a tenant_id is refused rather than served against it.
func TestConversationRPCs_NoAuthenticatedScopeRejected(t *testing.T) {
	cases := []struct {
		name string
		call func(srv *DaemonServer, ctx context.Context) error
	}{
		{"ListConversations", func(srv *DaemonServer, ctx context.Context) error {
			_, err := srv.ListConversations(ctx, &tenantv1.ListConversationsRequest{
				TenantId: chatForeignTenant, UserId: chatForeignUser,
			})
			return err
		}},
		{"GetConversation", func(srv *DaemonServer, ctx context.Context) error {
			_, err := srv.GetConversation(ctx, &tenantv1.GetConversationRequest{
				TenantId: chatForeignTenant, ConversationId: "c1",
			})
			return err
		}},
		{"SaveConversation", func(srv *DaemonServer, ctx context.Context) error {
			_, err := srv.SaveConversation(ctx, &tenantv1.SaveConversationRequest{
				TenantId: chatForeignTenant, UserId: chatForeignUser,
				ConversationId: "c1", Title: "t",
			})
			return err
		}},
		{"RenameConversation", func(srv *DaemonServer, ctx context.Context) error {
			_, err := srv.RenameConversation(ctx, &tenantv1.RenameConversationRequest{
				TenantId: chatForeignTenant, ConversationId: "c1", Title: "renamed",
			})
			return err
		}},
		{"DeleteConversation", func(srv *DaemonServer, ctx context.Context) error {
			_, err := srv.DeleteConversation(ctx, &tenantv1.DeleteConversationRequest{
				TenantId: chatForeignTenant, ConversationId: "c1",
			})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &scopeSpyConversationStore{
				conversations: []storedConversation{{ID: "c1"}},
			}
			srv := blankServer()
			srv.conversationStore = spy

			err := tc.call(srv, context.Background())
			assert.Equal(t, codes.InvalidArgument, grpcCode(err),
				"%s must refuse a request with no authenticated tenant", tc.name)
			assert.Empty(t, spy.tenantIDs, "a refused request must not reach the store")
		})
	}
}

// TestUserStateRPCs_ForeignScopeIgnored covers the user-state family, whose
// Redis keys are built from (tenant, user). resolveUserCtx used to prefer the
// wire values outright, which made every key in the file caller-selected.
func TestUserStateRPCs_ForeignScopeIgnored(t *testing.T) {
	srv := newUserStateServer(t)
	callerCtx := tenantAndSubjectCtx(chatCallerTenant, chatCallerUser)

	// Write onboarding state as the caller, but name a foreign tenant/user.
	_, err := srv.UpdateUserOnboardingState(callerCtx, &tenantv1.UpdateUserOnboardingStateRequest{
		TenantId: chatForeignTenant,
		UserId:   chatForeignUser,
		State:    &tenantv1.UserOnboardingState{WizardCompleted: true, CurrentStepId: "completion"},
	})
	require.NoError(t, err)

	// The write must have landed in the caller's own key: the foreign
	// tenant/user pair still sees a fresh default.
	victimCtx := tenantAndSubjectCtx(chatForeignTenant, chatForeignUser)
	victim, err := srv.GetUserOnboardingState(victimCtx, &tenantv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)
	assert.False(t, victim.GetState().GetWizardCompleted(),
		"the named tenant/user must not have been written to")

	// And the caller reads back their own state, with the server-stamped ids
	// reflecting the authenticated scope rather than the request body.
	mine, err := srv.GetUserOnboardingState(callerCtx, &tenantv1.GetUserOnboardingStateRequest{})
	require.NoError(t, err)
	assert.True(t, mine.GetState().GetWizardCompleted())
	assert.Equal(t, chatCallerTenant, mine.GetState().GetTenantId())
	assert.Equal(t, chatCallerUser, mine.GetState().GetUserId())
}

// TestConsumeAttachment_ForeignTenantIgnored pins the staging namespace: the
// GETDEL anti-replay protection is only meaningful if the tenant half of the
// key is not caller-selected.
func TestConsumeAttachment_ForeignTenantIgnored(t *testing.T) {
	srv := newUserStateServer(t)

	staged, err := srv.StageAttachment(
		tenantAndSubjectCtx(chatCallerTenant, chatCallerUser),
		&tenantv1.StageAttachmentRequest{Text: "secret"},
	)
	require.NoError(t, err)

	// A caller in another tenant naming the victim's tenant must not reach it.
	_, err = srv.ConsumeAttachment(
		tenantAndSubjectCtx(chatForeignTenant, chatForeignUser),
		&tenantv1.ConsumeAttachmentRequest{
			TenantId:     chatCallerTenant,
			AttachmentId: staged.GetAttachmentId(),
		},
	)
	assert.Equal(t, codes.NotFound, grpcCode(err))

	// The owner can still consume it — the staged value was never touched.
	got, err := srv.ConsumeAttachment(
		tenantAndSubjectCtx(chatCallerTenant, chatCallerUser),
		&tenantv1.ConsumeAttachmentRequest{AttachmentId: staged.GetAttachmentId()},
	)
	require.NoError(t, err)
	assert.Equal(t, "secret", got.GetText())
}

// TestInvalidateMembershipCache_ForeignUserRejected pins the one user-state
// key that is global rather than tenant-prefixed: it may only be evicted by
// the user it belongs to.
func TestInvalidateMembershipCache_ForeignUserRejected(t *testing.T) {
	srv := newUserStateServer(t)

	_, err := srv.InvalidateMembershipCache(
		tenantAndSubjectCtx(chatCallerTenant, chatCallerUser),
		&tenantv1.InvalidateMembershipCacheRequest{UserId: chatForeignUser},
	)
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))

	_, err = srv.InvalidateMembershipCache(
		tenantAndSubjectCtx(chatCallerTenant, chatCallerUser),
		&tenantv1.InvalidateMembershipCacheRequest{UserId: chatCallerUser},
	)
	assert.NoError(t, err)
}

// TestAlertRPCs_ForeignScopeIgnored covers the alert family, whose store is
// keyed by (tenant, user) in the same shape as the chat store.
func TestAlertRPCs_ForeignScopeIgnored(t *testing.T) {
	spy := &scopeSpyAlertStore{}
	srv := blankServer()
	srv.alertStore = spy

	ctx := tenantAndSubjectCtx(chatCallerTenant, chatCallerUser)

	_, err := srv.ListAlerts(ctx, &tenantv1.ListAlertsRequest{
		TenantId: chatForeignTenant, UserId: chatForeignUser,
	})
	require.NoError(t, err)

	_, err = srv.MarkAlertRead(ctx, &tenantv1.MarkAlertReadRequest{
		TenantId: chatForeignTenant, AlertId: "a1",
	})
	require.NoError(t, err)

	_, err = srv.MarkAllAlertsRead(ctx, &tenantv1.MarkAllAlertsReadRequest{
		TenantId: chatForeignTenant, UserId: chatForeignUser,
	})
	require.NoError(t, err)

	require.Len(t, spy.tenantIDs, 3)
	for _, got := range spy.tenantIDs {
		assert.Equal(t, chatCallerTenant, got)
	}
	require.NotEmpty(t, spy.userIDs)
	for _, got := range spy.userIDs {
		assert.Equal(t, chatCallerUser, got)
	}
}

// scopeSpyAlertStore records the scope each alert-store call was made with.
type scopeSpyAlertStore struct {
	tenantIDs []string
	userIDs   []string
}

func (m *scopeSpyAlertStore) ListAlerts(_ context.Context, tenantID, userID string, _ bool, _ int) ([]*storedAlert, error) {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, userID)
	return nil, nil
}

func (m *scopeSpyAlertStore) MarkAlertRead(_ context.Context, tenantID, callerUserID, _ string) error {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, callerUserID)
	return nil
}

func (m *scopeSpyAlertStore) MarkAllAlertsRead(_ context.Context, tenantID, userID string) (int32, error) {
	m.tenantIDs = append(m.tenantIDs, tenantID)
	m.userIDs = append(m.userIDs, userID)
	return 0, nil
}
