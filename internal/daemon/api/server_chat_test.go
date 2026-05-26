package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
)

// ---------------------------------------------------------------------------
// mockConversationStore
// ---------------------------------------------------------------------------

type mockConversationStore struct {
	conversations []*storedConversation
	messages      []*storedMessage
	listErr       error
	getErr        error
}

func (m *mockConversationStore) ListConversations(_ context.Context, _, _ string, _ int) ([]*storedConversation, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.conversations, nil
}

func (m *mockConversationStore) GetConversation(_ context.Context, _, _ string) (*storedConversation, []*storedMessage, error) {
	if m.getErr != nil {
		return nil, nil, m.getErr
	}
	if len(m.conversations) == 0 {
		return nil, nil, assert.AnError
	}
	return m.conversations[0], m.messages, nil
}

// ---------------------------------------------------------------------------
// ListConversations tests
// ---------------------------------------------------------------------------

func TestListConversations_EmptyTenantIDFallsBackToSystemTenant_NilStoreReturnsEmpty(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil conversationStore, the handler returns empty list successfully.
	srv := blankServer()
	resp, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "", UserId: "u1"})
	require.NoError(t, err)
	assert.Empty(t, resp.Conversations)
}

func TestListConversations_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListConversations_NilStore_ReturnsEmpty(t *testing.T) {
	// Nil conversationStore → returns empty list, not error.
	srv := blankServer()
	resp, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	assert.Empty(t, resp.Conversations)
}

func TestListConversations_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{listErr: assert.AnError}
	_, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: "u1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestListConversations_Success_ReturnsMapped(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{
		conversations: []*storedConversation{
			{
				ID:            "c1",
				TenantID:      "acme",
				UserID:        "u1",
				Title:         "Test Chat",
				MessageCount:  3,
				CreatedAtUnix: 1000,
				UpdatedAtUnix: 2000,
			},
		},
	}
	resp, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	require.Len(t, resp.Conversations, 1)
	assert.Equal(t, "c1", resp.Conversations[0].Id)
	assert.Equal(t, "Test Chat", resp.Conversations[0].Title)
	assert.Equal(t, int32(3), resp.Conversations[0].MessageCount)
}

// ---------------------------------------------------------------------------
// GetConversation tests
// ---------------------------------------------------------------------------

func TestGetConversation_EmptyTenantIDFallsBackToSystemTenant_NilStoreNotFound(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil conversationStore, the handler returns NotFound.
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "",
		ConversationId: "c1",
	})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetConversation_MissingConversationID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetConversation_NilStore_NotFound(t *testing.T) {
	// Nil conversationStore → NotFound (no store = conversation cannot exist).
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "c1",
	})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetConversation_StoreError_NotFound(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{getErr: assert.AnError}
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "c1",
	})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetConversation_Success_ReturnsMappedMessages(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{
		conversations: []*storedConversation{
			{ID: "c1", TenantID: "acme", UserID: "u1", Title: "My Chat"},
		},
		messages: []*storedMessage{
			{ID: "m1", Role: "user", Content: "Hello", CreatedAtUnix: 100},
			{ID: "m2", Role: "assistant", Content: "Hi there", CreatedAtUnix: 200},
		},
	}
	resp, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "c1",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Conversation)
	assert.Equal(t, "c1", resp.Conversation.Id)
	require.Len(t, resp.Messages, 2)
	assert.Equal(t, "user", resp.Messages[0].Role)
	assert.Equal(t, "assistant", resp.Messages[1].Role)
	assert.Equal(t, "Hello", resp.Messages[0].Content)
}
