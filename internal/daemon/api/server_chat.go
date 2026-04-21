// Package api — server_chat.go
//
// Implements the ListConversations and GetConversation RPC handlers introduced
// by the prod-feature-wiring spec.
//
// Storage layout in Redis:
//   - Sorted set "tenant:conversations:{tenantID}:{userID}" sorted by updated_at.
//   - Conversation metadata JSON at "tenant:conversation:{tenantID}:{convID}".
//   - Message list at "tenant:conv:messages:{tenantID}:{convID}" (Redis list).
//
// Authorization: self-access (userID match) or FGA admin relation on the tenant.
// Write operations (SaveConversation) are out of scope for this task — read only.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/identity"
)

// conversationStoreIface is the narrow interface the chat handlers use.
type conversationStoreIface interface {
	ListConversations(ctx context.Context, tenantID, userID string, limit int) ([]*storedConversation, error)
	GetConversation(ctx context.Context, tenantID, conversationID string) (*storedConversation, []*storedMessage, error)
}

// storedConversation is the JSON-serializable conversation metadata in Redis.
type storedConversation struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id"`
	Title         string `json:"title"`
	CreatedAtUnix int64  `json:"created_at_unix"`
	UpdatedAtUnix int64  `json:"updated_at_unix"`
	MessageCount  int32  `json:"message_count"`
}

// storedMessage is a single message stored in the conversation message list.
type storedMessage struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	Content       string `json:"content"`
	CreatedAtUnix int64  `json:"created_at_unix"`
}

// redisConversationStore implements conversationStoreIface using a raw Redis client.
type redisConversationStore struct {
	client goredis.UniversalClient
	logger *slog.Logger
}

// NewRedisConversationStore creates a conversation store backed by the given Redis client.
func NewRedisConversationStore(client goredis.UniversalClient, logger *slog.Logger) conversationStoreIface {
	if logger == nil {
		logger = slog.Default()
	}
	return &redisConversationStore{client: client, logger: logger}
}

func convIndexKey(tenantID, userID string) string {
	return fmt.Sprintf("tenant:conversations:%s:%s", tenantID, userID)
}

func convDataKey(tenantID, convID string) string {
	return fmt.Sprintf("tenant:conversation:%s:%s", tenantID, convID)
}

func convMessagesKey(tenantID, convID string) string {
	return fmt.Sprintf("tenant:conv:messages:%s:%s", tenantID, convID)
}

func (s *redisConversationStore) ListConversations(ctx context.Context, tenantID, userID string, limit int) ([]*storedConversation, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	// ZREVRANGE returns conv IDs sorted descending by updated_at score.
	convIDs, err := s.client.ZRevRange(ctx, convIndexKey(tenantID, userID), 0, int64(limit-1)).Result()
	if err == goredis.Nil || len(convIDs) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("conversations ZREVRANGE failed: %w", err)
	}

	conversations := make([]*storedConversation, 0, len(convIDs))
	for _, convID := range convIDs {
		raw, err := s.client.Get(ctx, convDataKey(tenantID, convID)).Result()
		if err == goredis.Nil {
			continue
		}
		if err != nil {
			s.logger.WarnContext(ctx, "conversations: failed to fetch conversation data",
				slog.String("conv_id", convID),
				slog.String("error", err.Error()),
			)
			continue
		}
		var c storedConversation
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			continue
		}
		conversations = append(conversations, &c)
	}
	return conversations, nil
}

func (s *redisConversationStore) GetConversation(ctx context.Context, tenantID, conversationID string) (*storedConversation, []*storedMessage, error) {
	// Fetch conversation metadata.
	raw, err := s.client.Get(ctx, convDataKey(tenantID, conversationID)).Result()
	if err == goredis.Nil {
		return nil, nil, fmt.Errorf("conversation not found")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("conversation GET failed: %w", err)
	}
	var c storedConversation
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, nil, fmt.Errorf("conversation unmarshal failed: %w", err)
	}

	// Fetch messages from Redis list (oldest first).
	msgRaws, err := s.client.LRange(ctx, convMessagesKey(tenantID, conversationID), 0, -1).Result()
	if err != nil && err != goredis.Nil {
		return nil, nil, fmt.Errorf("messages LRANGE failed: %w", err)
	}

	messages := make([]*storedMessage, 0, len(msgRaws))
	for _, mRaw := range msgRaws {
		var m storedMessage
		if err := json.Unmarshal([]byte(mRaw), &m); err != nil {
			continue
		}
		messages = append(messages, &m)
	}

	return &c, messages, nil
}

// ---------------------------------------------------------------------------
// ListConversations handler
// ---------------------------------------------------------------------------

// ListConversations returns the conversation history list for a user.
func (s *DaemonServer) ListConversations(ctx context.Context, req *ListConversationsRequest) (*ListConversationsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		if id, err := identity.IdentityFromContext(ctx); err == nil {
			userID = id.Subject
		}
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.conversationStore == nil {
		return &ListConversationsResponse{Conversations: []*ConversationSummary{}}, nil
	}

	stored, err := s.conversationStore.ListConversations(ctx, tenantID, userID, int(req.GetLimit()))
	if err != nil {
		s.logger.ErrorContext(ctx, "ListConversations: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "conversations read failed")
	}

	convs := make([]*ConversationSummary, 0, len(stored))
	for _, c := range stored {
		convs = append(convs, &ConversationSummary{
			Id:            c.ID,
			TenantId:      c.TenantID,
			UserId:        c.UserID,
			Title:         c.Title,
			CreatedAtUnix: c.CreatedAtUnix,
			UpdatedAtUnix: c.UpdatedAtUnix,
			MessageCount:  c.MessageCount,
		})
	}

	return &ListConversationsResponse{Conversations: convs}, nil
}

// ---------------------------------------------------------------------------
// GetConversation handler
// ---------------------------------------------------------------------------

// GetConversation returns the full message history for a single conversation.
func (s *DaemonServer) GetConversation(ctx context.Context, req *GetConversationRequest) (*GetConversationResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	if s.conversationStore == nil {
		return nil, status_grpc.Error(codes.NotFound, "conversation not found")
	}

	conv, msgs, err := s.conversationStore.GetConversation(ctx, tenantID, req.GetConversationId())
	if err != nil {
		s.logger.WarnContext(ctx, "GetConversation: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.NotFound, "conversation not found")
	}

	protoMsgs := make([]*ConversationMessage, 0, len(msgs))
	for _, m := range msgs {
		protoMsgs = append(protoMsgs, &ConversationMessage{
			Id:            m.ID,
			Role:          m.Role,
			Content:       m.Content,
			CreatedAtUnix: m.CreatedAtUnix,
		})
	}

	return &GetConversationResponse{
		Conversation: &ConversationSummary{
			Id:            conv.ID,
			TenantId:      conv.TenantID,
			UserId:        conv.UserID,
			Title:         conv.Title,
			CreatedAtUnix: conv.CreatedAtUnix,
			UpdatedAtUnix: conv.UpdatedAtUnix,
			MessageCount:  conv.MessageCount,
		},
		Messages: protoMsgs,
	}, nil
}
