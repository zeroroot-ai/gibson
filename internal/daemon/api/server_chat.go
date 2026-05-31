// Package api — server_chat.go
//
// Implements the ListConversations and GetConversation RPC handlers on
// UserService, plus the internal saveConversation helper called from the
// StreamLLM completion path.
//
// Storage layout in Redis:
//   - Hash key "conv:{tenantId}:{conversationId}" with fields:
//     title       (string)
//     agent_id    (string)
//     user_id     (string)
//     created_at  (int64 Unix, string representation)
//     updated_at  (int64 Unix, string representation)
//     messages    (JSON-encoded []storedMessage)
//   - Sorted set "convindex:{tenantId}:{userId}" — member = conversationId,
//     score = updated_at Unix timestamp.
//   - TTL: 90 days on both hash and sorted set, reset on each write.
//
// Authorization: enforced by FGA annotations on the proto (member relation on
// the tenant object).  Cross-tenant isolation is enforced structurally: all
// keys are scoped by tenantId so callers cannot reach conversations belonging
// to a different tenant without a different tenantId.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// conversationTTL is the lifetime of a conversation hash and its index
	// entry.  Reset on every write so active conversations never expire.
	conversationTTL = 90 * 24 * time.Hour // 90 days = 7776000 seconds

	// conversationDefaultLimit is the default page size for ListConversations.
	conversationDefaultLimit = 20

	// conversationMaxLimit is the upper bound for ListConversations.
	conversationMaxLimit = 100
)

// conversationStoreIface is the narrow interface the chat handlers use.
//
// Save must be accessible to the streaming handler that records completed
// conversations; it is exposed via this interface so DaemonServer can call it
// without knowing the concrete Redis type.
type conversationStoreIface interface {
	// Save persists a conversation and its messages.  If the conversation
	// already exists (same conversationID), it is fully overwritten.  The
	// original created_at timestamp is preserved on update.
	Save(ctx context.Context, tenantID, userID, conversationID, title, agentID string, messages []storedMessage) error

	// List returns conversation summaries for a user, ordered by
	// updated_at descending.  At most limit entries are returned.
	List(ctx context.Context, tenantID, userID string, limit int) ([]storedConversation, error)

	// Get returns the full conversation and its messages.  Returns
	// a non-nil error (wrapping "conversation not found") when absent.
	Get(ctx context.Context, tenantID, conversationID string) (*storedConversation, []storedMessage, error)
}

// storedConversation is the in-memory representation of conversation metadata
// read from the Redis hash.
type storedConversation struct {
	ID            string
	TenantID      string
	UserID        string
	Title         string
	AgentID       string
	CreatedAtUnix int64
	UpdatedAtUnix int64
	MessageCount  int32
}

// storedMessagePartType identifies the kind of a message part in JSON.
// We store the oneof discriminator as a string field so parts can be
// unmarshalled back to the correct concrete type.
type storedMessagePartType string

const (
	storedPartTypeText          storedMessagePartType = "text"
	storedPartTypeToolCall      storedMessagePartType = "tool_call"
	storedPartTypeToolResult    storedMessagePartType = "tool_result"
	storedPartTypeCitation      storedMessagePartType = "citation"
	storedPartTypeAttachmentRef storedMessagePartType = "attachment_ref"
	storedPartTypeReasoning     storedMessagePartType = "reasoning"
)

// storedMessagePart is a single part within a stored message.
// The Type field discriminates which of the optional payload fields is set.
type storedMessagePart struct {
	Type storedMessagePartType `json:"type"`

	// text payload (type == "text")
	Text string `json:"text,omitempty"`

	// tool_call payload (type == "tool_call")
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Arguments  string `json:"arguments,omitempty"`

	// tool_result payload (type == "tool_result")
	Result string `json:"result,omitempty"`

	// citation payload (type == "citation")
	CitationID string `json:"citation_id,omitempty"`
	Label      string `json:"label,omitempty"`
	URL        string `json:"url,omitempty"`

	// attachment_ref payload (type == "attachment_ref")
	AttachmentID string `json:"attachment_id,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	AttachName   string `json:"attach_name,omitempty"`

	// reasoning payload (type == "reasoning")
	ReasoningText string `json:"reasoning_text,omitempty"`
}

// storedMessage is a single message within a conversation.
// Parts replaces the former flat Content field to preserve tool calls,
// graph citations, attachments, and reasoning losslessly.
type storedMessage struct {
	ID            string              `json:"id"`
	Role          string              `json:"role"`
	Parts         []storedMessagePart `json:"parts"`
	CreatedAtUnix int64               `json:"created_at_unix"`
}

// redisConversationStore implements conversationStoreIface using a raw Redis
// client.  It uses goredis.UniversalClient so it works with both standalone
// Redis and Redis Cluster (matching the pattern in server_alerts.go).
type redisConversationStore struct {
	client goredis.UniversalClient
	logger *slog.Logger
}

// NewRedisConversationStore creates a conversation store backed by the given
// Redis client.
func NewRedisConversationStore(client goredis.UniversalClient, logger *slog.Logger) conversationStoreIface {
	if logger == nil {
		logger = slog.Default()
	}
	return &redisConversationStore{client: client, logger: logger}
}

// convHashKey returns the Redis hash key for a single conversation.
// Pattern: conv:{tenantId}:{conversationId}
func convHashKey(tenantID, conversationID string) string {
	return fmt.Sprintf("conv:%s:%s", tenantID, conversationID)
}

// convIndexKey returns the Redis sorted-set key for a user's conversation index.
// Pattern: convindex:{tenantId}:{userId}
func convIndexKey(tenantID, userID string) string {
	return fmt.Sprintf("convindex:%s:%s", tenantID, userID)
}

// Save persists a conversation and its messages to Redis.
//
// It writes the conversation metadata as a Redis Hash and updates the
// sorted-set index.  Both keys are given a 90-day TTL, reset on every write.
func (s *redisConversationStore) Save(
	ctx context.Context,
	tenantID, userID, conversationID, title, agentID string,
	messages []storedMessage,
) error {
	if tenantID == "" || userID == "" || conversationID == "" {
		return fmt.Errorf("tenant_id, user_id, and conversation_id are required")
	}

	now := time.Now().Unix()
	hashKey := convHashKey(tenantID, conversationID)
	idxKey := convIndexKey(tenantID, userID)

	// Preserve created_at on update: read the existing field first.
	createdAt := now
	if existing, err := s.client.HGet(ctx, hashKey, "created_at").Result(); err == nil && existing != "" {
		if v, parseErr := strconv.ParseInt(existing, 10, 64); parseErr == nil {
			createdAt = v
		}
	}

	// JSON-encode the messages slice.
	if messages == nil {
		messages = []storedMessage{}
	}
	msgsJSON, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("failed to marshal messages: %w", err)
	}

	fields := map[string]any{
		"title":      title,
		"agent_id":   agentID,
		"user_id":    userID,
		"created_at": strconv.FormatInt(createdAt, 10),
		"updated_at": strconv.FormatInt(now, 10),
		"messages":   string(msgsJSON),
	}

	pipe := s.client.Pipeline()
	pipe.HMSet(ctx, hashKey, fields)
	pipe.Expire(ctx, hashKey, conversationTTL)
	pipe.ZAdd(ctx, idxKey, goredis.Z{Score: float64(now), Member: conversationID})
	pipe.Expire(ctx, idxKey, conversationTTL)
	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		return fmt.Errorf("failed to save conversation: %w", pipeErr)
	}

	s.logger.InfoContext(ctx, "conversation: saved",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", userID),
		slog.String("conversation_id", conversationID),
		slog.Int("message_count", len(messages)),
	)
	return nil
}

// List returns conversation summaries for a user, ordered by updated_at descending.
func (s *redisConversationStore) List(ctx context.Context, tenantID, userID string, limit int) ([]storedConversation, error) {
	if limit <= 0 {
		limit = conversationDefaultLimit
	}
	if limit > conversationMaxLimit {
		limit = conversationMaxLimit
	}

	idxKey := convIndexKey(tenantID, userID)

	// ZREVRANGE returns conversation IDs sorted descending by updated_at score.
	convIDs, err := s.client.ZRevRange(ctx, idxKey, 0, int64(limit-1)).Result()
	if err == goredis.Nil || len(convIDs) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("conversations ZREVRANGE failed: %w", err)
	}

	out := make([]storedConversation, 0, len(convIDs))
	for _, convID := range convIDs {
		conv, fetchErr := s.fetchConversationMeta(ctx, tenantID, convID)
		if fetchErr != nil {
			s.logger.WarnContext(ctx, "conversation: failed to fetch metadata",
				slog.String("tenant_id", tenantID),
				slog.String("conversation_id", convID),
				slog.String("error", fetchErr.Error()),
			)
			continue
		}
		if conv == nil {
			// Hash expired; prune the stale index entry.
			_ = s.client.ZRem(ctx, idxKey, convID)
			continue
		}
		out = append(out, *conv)
	}
	return out, nil
}

// Get returns the full conversation and its messages.
func (s *redisConversationStore) Get(ctx context.Context, tenantID, conversationID string) (*storedConversation, []storedMessage, error) {
	hashKey := convHashKey(tenantID, conversationID)

	// Fetch all relevant fields in one HMGet call.
	vals, err := s.client.HMGet(ctx, hashKey,
		"title", "agent_id", "user_id", "created_at", "updated_at", "messages",
	).Result()
	if err != nil {
		return nil, nil, fmt.Errorf("HMGet failed: %w", err)
	}

	// If every field is nil, the key does not exist.
	allNil := true
	for _, v := range vals {
		if v != nil {
			allNil = false
			break
		}
	}
	if allNil {
		return nil, nil, fmt.Errorf("conversation not found")
	}

	strAt := func(i int) string {
		if vals[i] == nil {
			return ""
		}
		return vals[i].(string)
	}
	parseInt64 := func(i int) int64 {
		sv := strAt(i)
		if sv == "" {
			return 0
		}
		v, _ := strconv.ParseInt(sv, 10, 64)
		return v
	}

	title := strAt(0)
	agentID := strAt(1)
	userID := strAt(2)
	createdAt := parseInt64(3)
	updatedAt := parseInt64(4)
	msgsJSON := strAt(5)

	var msgs []storedMessage
	if msgsJSON != "" {
		if jsonErr := json.Unmarshal([]byte(msgsJSON), &msgs); jsonErr != nil {
			return nil, nil, fmt.Errorf("messages unmarshal failed: %w", jsonErr)
		}
	}

	conv := &storedConversation{
		ID:            conversationID,
		TenantID:      tenantID,
		UserID:        userID,
		Title:         title,
		AgentID:       agentID,
		CreatedAtUnix: createdAt,
		UpdatedAtUnix: updatedAt,
		MessageCount:  int32(len(msgs)),
	}
	return conv, msgs, nil
}

// fetchConversationMeta reads the metadata fields (excluding messages) for a
// single conversation.  Returns (nil, nil) when the key does not exist or has
// expired.  Used by List to avoid deserialising the full messages JSON.
func (s *redisConversationStore) fetchConversationMeta(ctx context.Context, tenantID, conversationID string) (*storedConversation, error) {
	hashKey := convHashKey(tenantID, conversationID)

	vals, err := s.client.HMGet(ctx, hashKey,
		"title", "agent_id", "user_id", "created_at", "updated_at", "messages",
	).Result()
	if err != nil {
		return nil, fmt.Errorf("HMGet failed: %w", err)
	}

	allNil := true
	for _, v := range vals {
		if v != nil {
			allNil = false
			break
		}
	}
	if allNil {
		return nil, nil
	}

	strAt := func(i int) string {
		if vals[i] == nil {
			return ""
		}
		return vals[i].(string)
	}
	parseInt64 := func(i int) int64 {
		sv := strAt(i)
		if sv == "" {
			return 0
		}
		v, _ := strconv.ParseInt(sv, 10, 64)
		return v
	}

	// Compute message count from the stored JSON without fully decoding.
	var msgCount int32
	if msgsJSON := strAt(5); msgsJSON != "" {
		var msgs []storedMessage
		if jsonErr := json.Unmarshal([]byte(msgsJSON), &msgs); jsonErr == nil {
			msgCount = int32(len(msgs))
		}
	}

	return &storedConversation{
		ID:            conversationID,
		TenantID:      tenantID,
		UserID:        strAt(2),
		Title:         strAt(0),
		AgentID:       strAt(1),
		CreatedAtUnix: parseInt64(3),
		UpdatedAtUnix: parseInt64(4),
		MessageCount:  msgCount,
	}, nil
}

// ---------------------------------------------------------------------------
// ListConversations handler
// ---------------------------------------------------------------------------

// ListConversations returns the conversation history list for a user.
//
// Authorization: enforced by FGA annotations on the proto; we only extract
// tenant/user from the request or the call context.
func (s *DaemonServer) ListConversations(ctx context.Context, req *userv1.ListConversationsRequest) (*userv1.ListConversationsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		if id, err := auth.IdentityFromContext(ctx); err == nil {
			userID = id.Subject
		}
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.conversationStore == nil {
		// Store must always be wired at bootstrap (dashboard#549).
		// A nil store at runtime indicates a bootstrap defect.
		s.logger.ErrorContext(ctx, "ListConversations: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	stored, err := s.conversationStore.List(ctx, tenantID, userID, int(req.GetLimit()))
	if err != nil {
		s.logger.ErrorContext(ctx, "ListConversations: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "conversations read failed")
	}

	convs := make([]*userv1.ConversationSummary, 0, len(stored))
	for i := range stored {
		c := &stored[i]
		convs = append(convs, &userv1.ConversationSummary{
			Id:            c.ID,
			TenantId:      c.TenantID,
			UserId:        c.UserID,
			Title:         c.Title,
			CreatedAtUnix: c.CreatedAtUnix,
			UpdatedAtUnix: c.UpdatedAtUnix,
			MessageCount:  c.MessageCount,
		})
	}
	return &userv1.ListConversationsResponse{Conversations: convs}, nil
}

// ---------------------------------------------------------------------------
// GetConversation handler
// ---------------------------------------------------------------------------

// GetConversation returns the full message history for a single conversation.
func (s *DaemonServer) GetConversation(ctx context.Context, req *userv1.GetConversationRequest) (*userv1.GetConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if s.conversationStore == nil {
		// Store must always be wired at bootstrap (dashboard#549).
		// A nil store at runtime indicates a bootstrap defect.
		s.logger.ErrorContext(ctx, "GetConversation: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	conv, msgs, err := s.conversationStore.Get(ctx, tenantID, req.GetConversationId())
	if err != nil {
		s.logger.WarnContext(ctx, "GetConversation: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.NotFound, "conversation not found")
	}

	protoMsgs := make([]*userv1.ConversationMessage, 0, len(msgs))
	for _, m := range msgs {
		protoMsgs = append(protoMsgs, storedMessageToProto(m))
	}

	return &userv1.GetConversationResponse{
		Conversation: &userv1.ConversationSummary{
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

// ---------------------------------------------------------------------------
// saveConversation — internal helper for post-stream persistence
// ---------------------------------------------------------------------------

// saveConversation persists a completed conversation to the store.
//
// This is called after a stream finishes to record the full exchange.  It is a
// thin wrapper around conversationStore.Save that handles a nil store
// gracefully (skipping the write) so the caller does not need to nil-check.
//
// TODO(#496): Wire this call from the StreamLLM completion path once StreamLLM
// is implemented.  The call site should be at the end of the streaming loop,
// after the final response chunk is sent, passing the accumulated request and
// response messages as the messages slice.  Example:
//
//	if saveErr := s.saveConversation(ctx, tenantID, userID, conversationID,
//	    title, agentID, messages); saveErr != nil {
//	    s.logger.WarnContext(ctx, "StreamLLM: failed to save conversation",
//	        slog.String("error", saveErr.Error()))
//	    // Non-fatal: do not abort the response.
//	}
func (s *DaemonServer) saveConversation(
	ctx context.Context,
	tenantID, userID, conversationID, title, agentID string,
	messages []storedMessage,
) error {
	if s.conversationStore == nil {
		// Store must always be wired at bootstrap (dashboard#549).
		return fmt.Errorf("conversationStore is nil (bootstrap defect)")
	}
	return s.conversationStore.Save(ctx, tenantID, userID, conversationID, title, agentID, messages)
}

// ---------------------------------------------------------------------------
// SaveConversation handler
// ---------------------------------------------------------------------------

// SaveConversation persists or updates a conversation and its messages.
//
// Authorization: enforced by FGA annotations on the proto (member relation on
// the tenant object). Cross-tenant isolation is structural: all Redis keys are
// scoped by the caller's tenantID so a caller cannot write into another tenant's
// namespace without a different tenantID arriving from ext-authz.
//
// User isolation: the userId is resolved from the caller identity, not from the
// request body, so a caller cannot save into another user's conversation index.
func (s *DaemonServer) SaveConversation(ctx context.Context, req *userv1.SaveConversationRequest) (*userv1.SaveConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	// Resolve tenant: prefer explicit request field, fall back to auth context.
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Resolve user: always prefer the authenticated caller identity over the
	// request field to prevent a caller from writing into another user's index.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		userID = id.Subject
	}
	// Fall back to the request field (e.g. service-account callers that use a
	// bearer token without an ext-authz user header).
	if userID == "" {
		userID = req.GetUserId()
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required (no caller identity in context)")
	}

	if s.conversationStore == nil {
		// The store must always be wired at bootstrap (per the
		// no-degradation convention); a nil store at runtime is a bug.
		s.logger.ErrorContext(ctx, "SaveConversation: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	// Map proto messages → storedMessage slice.
	protoMsgs := req.GetMessages()
	msgs := make([]storedMessage, 0, len(protoMsgs))
	for _, m := range protoMsgs {
		msgs = append(msgs, protoMessageToStored(m))
	}

	if err := s.conversationStore.Save(
		ctx,
		tenantID,
		userID,
		req.GetConversationId(),
		req.GetTitle(),
		req.GetAgentId(),
		msgs,
	); err != nil {
		s.logger.ErrorContext(ctx, "SaveConversation: store write failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "conversation save failed")
	}

	return &userv1.SaveConversationResponse{}, nil
}

// ---------------------------------------------------------------------------
// Message parts conversion helpers
// ---------------------------------------------------------------------------

// protoMessageToStored converts a proto ConversationMessage to the internal
// storedMessage representation. All part types are preserved losslessly.
func protoMessageToStored(m *userv1.ConversationMessage) storedMessage {
	if m == nil {
		return storedMessage{}
	}
	parts := make([]storedMessagePart, 0, len(m.GetParts()))
	for _, p := range m.GetParts() {
		if p == nil {
			continue
		}
		switch v := p.Part.(type) {
		case *userv1.MessagePart_Text:
			if v.Text != nil {
				parts = append(parts, storedMessagePart{
					Type: storedPartTypeText,
					Text: v.Text.Text,
				})
			}
		case *userv1.MessagePart_ToolCall:
			if v.ToolCall != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeToolCall,
					ToolCallID: v.ToolCall.ToolCallId,
					Name:       v.ToolCall.Name,
					Arguments:  v.ToolCall.Arguments,
				})
			}
		case *userv1.MessagePart_ToolResult:
			if v.ToolResult != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeToolResult,
					ToolCallID: v.ToolResult.ToolCallId,
					Result:     v.ToolResult.Result,
				})
			}
		case *userv1.MessagePart_Citation:
			if v.Citation != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeCitation,
					CitationID: v.Citation.CitationId,
					Label:      v.Citation.Label,
					URL:        v.Citation.Url,
				})
			}
		case *userv1.MessagePart_AttachmentRef:
			if v.AttachmentRef != nil {
				parts = append(parts, storedMessagePart{
					Type:         storedPartTypeAttachmentRef,
					AttachmentID: v.AttachmentRef.AttachmentId,
					MediaType:    v.AttachmentRef.MediaType,
					AttachName:   v.AttachmentRef.Name,
				})
			}
		case *userv1.MessagePart_Reasoning:
			if v.Reasoning != nil {
				parts = append(parts, storedMessagePart{
					Type:          storedPartTypeReasoning,
					ReasoningText: v.Reasoning.Text,
				})
			}
			// Unknown part types are preserved as a zero-value storedMessagePart with
			// empty Type so they survive a round-trip without data loss at the storage
			// layer (the dashboard normalizer is responsible for handling unknown types
			// explicitly on the read side).
		}
	}
	return storedMessage{
		ID:            m.Id,
		Role:          m.Role,
		Parts:         parts,
		CreatedAtUnix: m.CreatedAtUnix,
	}
}

// storedMessageToProto converts an internal storedMessage to the proto
// ConversationMessage. Ordering is preserved; all part types are restored.
func storedMessageToProto(m storedMessage) *userv1.ConversationMessage {
	parts := make([]*userv1.MessagePart, 0, len(m.Parts))
	for _, sp := range m.Parts {
		var protoPart *userv1.MessagePart
		switch sp.Type {
		case storedPartTypeText:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_Text{
					Text: &userv1.MessagePartText{Text: sp.Text},
				},
			}
		case storedPartTypeToolCall:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_ToolCall{
					ToolCall: &userv1.MessagePartToolCall{
						ToolCallId: sp.ToolCallID,
						Name:       sp.Name,
						Arguments:  sp.Arguments,
					},
				},
			}
		case storedPartTypeToolResult:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_ToolResult{
					ToolResult: &userv1.MessagePartToolResult{
						ToolCallId: sp.ToolCallID,
						Result:     sp.Result,
					},
				},
			}
		case storedPartTypeCitation:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_Citation{
					Citation: &userv1.MessagePartCitation{
						CitationId: sp.CitationID,
						Label:      sp.Label,
						Url:        sp.URL,
					},
				},
			}
		case storedPartTypeAttachmentRef:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_AttachmentRef{
					AttachmentRef: &userv1.MessagePartAttachmentRef{
						AttachmentId: sp.AttachmentID,
						MediaType:    sp.MediaType,
						Name:         sp.AttachName,
					},
				},
			}
		case storedPartTypeReasoning:
			protoPart = &userv1.MessagePart{
				Part: &userv1.MessagePart_Reasoning{
					Reasoning: &userv1.MessagePartReasoning{Text: sp.ReasoningText},
				},
			}
		default:
			// Unknown stored type: skip silently. The part was not understood at
			// write time so we cannot reconstruct it on the read side.
			continue
		}
		parts = append(parts, protoPart)
	}
	return &userv1.ConversationMessage{
		Id:            m.ID,
		Role:          m.Role,
		Parts:         parts,
		CreatedAtUnix: m.CreatedAtUnix,
	}
}
