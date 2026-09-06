// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
//
// Cross-user isolation, within a tenant, is enforced at the hash — not just
// the index: the "convindex:{tenantId}:{userId}" sorted set is a per-user
// LISTING index, but the conversation content itself lives at
// "conv:{tenantId}:{conversationId}", a key any tenant member can address
// once they know (or guess) the conversationId. Get/Save/Rename/Delete each
// compare the hash's stored user_id field against the caller's authenticated
// identity before reading or mutating it — the per-user index alone is not a
// per-user access boundary.
package api

import (
	"context"
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
	// already exists (same conversationID) AND belongs to userID, it is
	// fully overwritten; the original created_at timestamp is preserved on
	// update.  If it already exists and belongs to a DIFFERENT userID, Save
	// returns errConversationOwnedByAnotherUser rather than overwriting it.
	Save(ctx context.Context, tenantID, userID, conversationID, title, agentID string, messages []storedMessage) error

	// List returns conversation summaries for a user, ordered by
	// updated_at descending.  At most limit entries are returned.
	List(ctx context.Context, tenantID, userID string, limit int) ([]storedConversation, error)

	// Get returns the full conversation and its messages, but only when it
	// belongs to callerUserID.  Returns a non-nil error (the sentinel
	// message "conversation not found") when absent OR owned by a different
	// user — the two are indistinguishable to the caller by design, so a
	// caller cannot use this RPC to probe for the existence of another
	// user's conversation ids.
	Get(ctx context.Context, tenantID, callerUserID, conversationID string) (*storedConversation, []storedMessage, error)

	// Rename updates the title and bumps updatedAt for an existing
	// conversation, but only when it belongs to callerUserID.  Returns
	// "conversation not found" when absent OR owned by a different user.
	Rename(ctx context.Context, tenantID, callerUserID, conversationID, newTitle string) error

	// Delete removes a conversation hash and its entry from the caller's own
	// sorted-set index, but only deletes the hash when it belongs to
	// callerUserID.  It is idempotent: deleting a non-existent conversation
	// is not an error.  A conversation that exists but belongs to a
	// different user returns "conversation not found" rather than being
	// destroyed.
	Delete(ctx context.Context, tenantID, callerUserID, conversationID string) error
}

// errConversationOwnedByAnotherUser is the sentinel error message Save
// returns when conversationID already exists under a different user_id.
// String-compared (matching this file's existing "conversation not found"
// convention) rather than a typed error, so redisConversationStore and
// inMemConvStore share one contract without a shared error package.
const errConversationOwnedByAnotherUser = "conversation owned by a different user"

// errConversationNotFound is the sentinel error message Get/Rename/Delete
// return for both "no such conversation" and "conversation belongs to a
// different user" — deliberately the same message for both, so a caller
// cannot use the error to distinguish "doesn't exist" from "isn't yours".
const errConversationNotFound = "conversation not found"

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

	// Preserve created_at on update, and refuse to overwrite a conversation
	// owned by a different user: read both existing fields together. The
	// hash is the sole store of a conversation's content — the per-user
	// sorted set is only a listing index — so this ownership check, not just
	// the index, is what actually keeps one user from clobbering another
	// user's conversation by reusing (or guessing) its conversation_id.
	createdAt := now
	existing, err := s.client.HMGet(ctx, hashKey, "created_at", "user_id").Result()
	// Fail closed on a read error or a short reply. Guarding the block with
	// `err == nil && len(existing) == 2` skipped the ownership check whenever
	// the read failed and fell through to the write — the same fail-open shape
	// Delete had, and the one this check exists to prevent. Get and Delete both
	// return here; Save must too, or a transient read failure is an overwrite.
	if err != nil {
		return fmt.Errorf("conversation ownership check failed: %w", err)
	}
	if len(existing) != 2 {
		return fmt.Errorf("conversation ownership check returned %d fields, want 2", len(existing))
	}
	{
		if v, ok := existing[0].(string); ok && v != "" {
			if parsed, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil {
				createdAt = parsed
			}
		}
		// Hash existence is judged from whether EITHER field came back
		// non-nil, not from the user_id field alone: `existing[1].(string)`
		// evaluates ok=false for a nil HMGet slot (an existing hash missing
		// its user_id field, same ambiguity Delete has — see its comment),
		// which used to make this whole check a no-op and let Save silently
		// overwrite/adopt a hash with no recorded owner. Treat "hash exists
		// but user_id is absent" the same as "owned by someone else":
		// refuse, don't guess.
		existingUserID, _ := existing[1].(string)
		hashExists := existing[0] != nil || existing[1] != nil
		if hashExists && existingUserID != userID {
			return errors.New(errConversationOwnedByAnotherUser)
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

// Get returns the full conversation and its messages, but only when it
// belongs to callerUserID.
func (s *redisConversationStore) Get(ctx context.Context, tenantID, callerUserID, conversationID string) (*storedConversation, []storedMessage, error) {
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
		return nil, nil, errors.New(errConversationNotFound)
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

	// Ownership check: the hash is addressable by (tenant, conversationID)
	// alone, which any tenant member can supply, so this comparison — not
	// the per-user index — is what stops one user from reading another
	// user's conversation. Same "not found" message as true-absence, so the
	// error cannot be used to probe for the existence of another user's
	// conversation id.
	if userID != callerUserID {
		return nil, nil, errors.New(errConversationNotFound)
	}

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
// Authorization: ext-authz enforces the proto's FGA annotation against an
// object derived from the CALLER's identity. That check says nothing about a
// tenant or user id carried in the request body, so both scope keys are taken
// from the authenticated context and the body fields are ignored.
func (s *DaemonServer) ListConversations(ctx context.Context, req *tenantv1.ListConversationsRequest) (*tenantv1.ListConversationsResponse, error) {
	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity (object_deriver: tenant_from_identity), so a body tenant id is
	// authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Conversations are per-user; the subject is the caller, never a body field.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		userID = id.Subject
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

	convs := make([]*tenantv1.ConversationSummary, 0, len(stored))
	for i := range stored {
		c := &stored[i]
		convs = append(convs, &tenantv1.ConversationSummary{
			Id:            c.ID,
			TenantId:      c.TenantID,
			UserId:        c.UserID,
			Title:         c.Title,
			CreatedAtUnix: c.CreatedAtUnix,
			UpdatedAtUnix: c.UpdatedAtUnix,
			MessageCount:  c.MessageCount,
		})
	}
	return &tenantv1.ListConversationsResponse{Conversations: convs}, nil
}

// ---------------------------------------------------------------------------
// GetConversation handler
// ---------------------------------------------------------------------------

// GetConversation returns the full message history for a single conversation.
//
// User isolation: the store's Get resolves the conversation by (tenant,
// conversation_id) — an id any tenant member can supply — so the caller's
// identity is threaded through and compared against the stored owner before
// any content is returned. Not just structural: relying on the per-user
// index alone would let one user read another user's conversation by
// reusing/guessing its id.
func (s *DaemonServer) GetConversation(ctx context.Context, req *tenantv1.GetConversationRequest) (*tenantv1.GetConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity (object_deriver: tenant_from_identity), so a body tenant id is
	// authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// The subject is the caller, never a body field — otherwise a caller
	// could pass someone else's user id and defeat the ownership check below.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required (no caller identity in context)")
	}

	if s.conversationStore == nil {
		// Store must always be wired at bootstrap (dashboard#549).
		// A nil store at runtime indicates a bootstrap defect.
		s.logger.ErrorContext(ctx, "GetConversation: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	conv, msgs, err := s.conversationStore.Get(ctx, tenantID, userID, req.GetConversationId())
	if err != nil {
		s.logger.WarnContext(ctx, "GetConversation: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.NotFound, "conversation not found")
	}

	protoMsgs := make([]*tenantv1.ConversationMessage, 0, len(msgs))
	for _, m := range msgs {
		protoMsgs = append(protoMsgs, storedMessageToProto(m))
	}

	return &tenantv1.GetConversationResponse{
		Conversation: &tenantv1.ConversationSummary{
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
// SaveConversation handler
// ---------------------------------------------------------------------------

// SaveConversation persists or updates a conversation and its messages.
//
// Authorization: ext-authz enforces the proto's FGA annotation (member relation
// on the tenant object) against an object derived from the caller's identity.
//
// Cross-tenant isolation: both the tenant and the user half of every Redis key
// come from the authenticated context, so a caller can only write inside their
// own tenant and their own conversation index. That covers the INDEX, but
// the conversation content lives in a hash addressed by (tenant,
// conversation_id) alone — a caller-supplied id, reachable by any tenant
// member. The store's Save refuses to overwrite an existing hash that
// belongs to a different user (see conversationStoreIface.Save), which is
// what actually keeps a caller from clobbering another user's conversation
// by reusing its id — the index scoping alone does not.
func (s *DaemonServer) SaveConversation(ctx context.Context, req *tenantv1.SaveConversationRequest) (*tenantv1.SaveConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity (object_deriver: tenant_from_identity), so a body tenant id is
	// authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Resolve user from the authenticated caller identity only, so a caller
	// cannot write into another user's index.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		userID = id.Subject
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
		if err.Error() == errConversationOwnedByAnotherUser {
			s.logger.WarnContext(ctx, "SaveConversation: refused to overwrite a conversation owned by a different user",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", userID),
				slog.String("conversation_id", req.GetConversationId()),
			)
			return nil, status_grpc.Error(codes.PermissionDenied, "conversation_id belongs to a different user")
		}
		s.logger.ErrorContext(ctx, "SaveConversation: store write failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "conversation save failed")
	}

	return &tenantv1.SaveConversationResponse{}, nil
}

// ---------------------------------------------------------------------------
// Rename — redisConversationStore
// ---------------------------------------------------------------------------

// Rename updates the title and bumps updatedAt for an existing conversation,
// but only when it belongs to callerUserID.
func (s *redisConversationStore) Rename(ctx context.Context, tenantID, callerUserID, conversationID, newTitle string) error {
	if tenantID == "" || callerUserID == "" || conversationID == "" {
		return errors.New("tenant_id, user_id, and conversation_id are required")
	}
	hashKey := convHashKey(tenantID, conversationID)

	// Verify the key exists AND belongs to the caller before issuing the
	// update. Same "not found" message for both absence and wrong-owner —
	// see errConversationNotFound.
	existingUserID, err := s.client.HGet(ctx, hashKey, "user_id").Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("conversation exists check failed: %w", err)
	}
	if errors.Is(err, goredis.Nil) || existingUserID != callerUserID {
		return errors.New(errConversationNotFound)
	}

	now := time.Now().Unix()
	pipe := s.client.Pipeline()
	pipe.HSet(ctx, hashKey, "title", newTitle, "updated_at", strconv.FormatInt(now, 10))
	pipe.Expire(ctx, hashKey, conversationTTL)
	_, pipeErr := pipe.Exec(ctx)
	if pipeErr != nil {
		return fmt.Errorf("failed to rename conversation: %w", pipeErr)
	}

	s.logger.InfoContext(ctx, "conversation: renamed",
		slog.String("tenant_id", tenantID),
		slog.String("conversation_id", conversationID),
	)
	return nil
}

// ---------------------------------------------------------------------------
// Delete — redisConversationStore
// ---------------------------------------------------------------------------

// Delete removes a conversation hash and its sorted-set index entry, but
// only deletes the hash when it belongs to callerUserID. It is idempotent:
// deleting a non-existent conversation returns nil. A conversation that
// exists but belongs to a different user is left alone (errConversationNotFound)
// rather than destroyed.
func (s *redisConversationStore) Delete(ctx context.Context, tenantID, callerUserID, conversationID string) error {
	if tenantID == "" || callerUserID == "" || conversationID == "" {
		return fmt.Errorf("tenant_id, user_id, and conversation_id are required")
	}
	hashKey := convHashKey(tenantID, conversationID)
	idxKey := convIndexKey(tenantID, callerUserID)

	// Ownership check: the hash is the sole store of a conversation's
	// content, so deleting it based only on the caller's own per-user index
	// key would let one user destroy another user's conversation by
	// reusing/guessing its conversation_id.
	//
	// HGET alone cannot tell "the hash does not exist at all" (the idempotent
	// no-op case this method's contract promises) apart from "the hash
	// exists but its user_id field is absent" — Redis returns the identical
	// redis.Nil for both. A bare `err == goredis.Nil` therefore cannot be
	// treated as "not mine, refuse" (that was the bug: this used to check
	// `err == nil && existingUserID != callerUserID`, so ANY goredis.Nil —
	// missing key OR missing field on an existing hash — skipped the
	// ownership check entirely and fell through to an unconditional delete).
	// Use HMGet across two fields, exactly like Get and Save do, so hash
	// existence is judged from whether ANY field came back non-nil, not from
	// the ownership field in isolation.
	existing, err := s.client.HMGet(ctx, hashKey, "created_at", "user_id").Result()
	if err != nil {
		return fmt.Errorf("conversation exists check failed: %w", err)
	}
	hashExists := existing[0] != nil || existing[1] != nil
	if hashExists {
		existingUserID, _ := existing[1].(string)
		if existingUserID != callerUserID {
			return errors.New(errConversationNotFound)
		}
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, hashKey)
	pipe.ZRem(ctx, idxKey, conversationID)
	_, pipeErr := pipe.Exec(ctx)
	if pipeErr != nil {
		return fmt.Errorf("failed to delete conversation: %w", pipeErr)
	}

	s.logger.InfoContext(ctx, "conversation: deleted",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", callerUserID),
		slog.String("conversation_id", conversationID),
	)
	return nil
}

// ---------------------------------------------------------------------------
// RenameConversation handler
// ---------------------------------------------------------------------------

// RenameConversation updates the title of an existing conversation.
//
// Authorization: enforced by FGA annotations (member relation on the tenant),
// with the tenant taken from the authenticated context.
//
// User isolation: the store's Rename compares the caller's identity against
// the hash's stored owner and reports "not found" for both true-absence and
// a different owner — rename cannot be used to affect, or to probe for the
// existence of, another user's conversation.
func (s *DaemonServer) RenameConversation(ctx context.Context, req *tenantv1.RenameConversationRequest) (*tenantv1.RenameConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}
	if req.GetTitle() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "title is required")
	}

	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity (object_deriver: tenant_from_identity), so a body tenant id is
	// authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// The subject is the caller, never a body field — otherwise a caller
	// could pass someone else's user id and defeat the ownership check below.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required (no caller identity in context)")
	}

	if s.conversationStore == nil {
		s.logger.ErrorContext(ctx, "RenameConversation: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	if err := s.conversationStore.Rename(ctx, tenantID, userID, req.GetConversationId(), req.GetTitle()); err != nil {
		s.logger.WarnContext(ctx, "RenameConversation: store rename failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		if err.Error() == errConversationNotFound {
			return nil, status_grpc.Error(codes.NotFound, "conversation not found")
		}
		return nil, status_grpc.Error(codes.Internal, "conversation rename failed")
	}

	return &tenantv1.RenameConversationResponse{}, nil
}

// ---------------------------------------------------------------------------
// DeleteConversation handler
// ---------------------------------------------------------------------------

// DeleteConversation removes a conversation and its list-index entry.
//
// Authorization: enforced by FGA annotations (member relation on the tenant).
// User isolation: we resolve the userID from the caller's authenticated
// identity so the index entry is removed from the correct user's sorted set,
// AND the store's Delete compares the caller against the hash's stored
// owner before deleting the hash itself — a caller cannot destroy another
// user's conversation by supplying its id.
func (s *DaemonServer) DeleteConversation(ctx context.Context, req *tenantv1.DeleteConversationRequest) (*tenantv1.DeleteConversationResponse, error) {
	if req.GetConversationId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "conversation_id is required")
	}

	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity (object_deriver: tenant_from_identity), so a body tenant id is
	// authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Resolve user from caller identity; fall back to a Get to find the owner.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		userID = id.Subject
	}
	if userID == "" {
		// Without a caller identity we cannot remove the index entry.
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required (no caller identity in context)")
	}

	if s.conversationStore == nil {
		s.logger.ErrorContext(ctx, "DeleteConversation: conversationStore is nil (bootstrap defect)")
		return nil, status_grpc.Error(codes.Internal, "conversation store not available")
	}

	if err := s.conversationStore.Delete(ctx, tenantID, userID, req.GetConversationId()); err != nil {
		if err.Error() == errConversationNotFound {
			s.logger.WarnContext(ctx, "DeleteConversation: refused to delete a conversation owned by a different user",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", userID),
				slog.String("conversation_id", req.GetConversationId()),
			)
			return nil, status_grpc.Error(codes.NotFound, "conversation not found")
		}
		s.logger.ErrorContext(ctx, "DeleteConversation: store delete failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("conversation_id", req.GetConversationId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "conversation delete failed")
	}

	return &tenantv1.DeleteConversationResponse{}, nil
}

// ---------------------------------------------------------------------------
// Message parts conversion helpers
// ---------------------------------------------------------------------------

// protoMessageToStored converts a proto ConversationMessage to the internal
// storedMessage representation. All part types are preserved losslessly.
func protoMessageToStored(m *tenantv1.ConversationMessage) storedMessage {
	if m == nil {
		return storedMessage{}
	}
	parts := make([]storedMessagePart, 0, len(m.GetParts()))
	for _, p := range m.GetParts() {
		if p == nil {
			continue
		}
		switch v := p.Part.(type) {
		case *tenantv1.MessagePart_Text:
			if v.Text != nil {
				parts = append(parts, storedMessagePart{
					Type: storedPartTypeText,
					Text: v.Text.Text,
				})
			}
		case *tenantv1.MessagePart_ToolCall:
			if v.ToolCall != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeToolCall,
					ToolCallID: v.ToolCall.ToolCallId,
					Name:       v.ToolCall.Name,
					Arguments:  v.ToolCall.Arguments,
				})
			}
		case *tenantv1.MessagePart_ToolResult:
			if v.ToolResult != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeToolResult,
					ToolCallID: v.ToolResult.ToolCallId,
					Result:     v.ToolResult.Result,
				})
			}
		case *tenantv1.MessagePart_Citation:
			if v.Citation != nil {
				parts = append(parts, storedMessagePart{
					Type:       storedPartTypeCitation,
					CitationID: v.Citation.CitationId,
					Label:      v.Citation.Label,
					URL:        v.Citation.Url,
				})
			}
		case *tenantv1.MessagePart_AttachmentRef:
			if v.AttachmentRef != nil {
				parts = append(parts, storedMessagePart{
					Type:         storedPartTypeAttachmentRef,
					AttachmentID: v.AttachmentRef.AttachmentId,
					MediaType:    v.AttachmentRef.MediaType,
					AttachName:   v.AttachmentRef.Name,
				})
			}
		case *tenantv1.MessagePart_Reasoning:
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
func storedMessageToProto(m storedMessage) *tenantv1.ConversationMessage {
	parts := make([]*tenantv1.MessagePart, 0, len(m.Parts))
	for _, sp := range m.Parts {
		var protoPart *tenantv1.MessagePart
		switch sp.Type {
		case storedPartTypeText:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_Text{
					Text: &tenantv1.MessagePartText{Text: sp.Text},
				},
			}
		case storedPartTypeToolCall:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_ToolCall{
					ToolCall: &tenantv1.MessagePartToolCall{
						ToolCallId: sp.ToolCallID,
						Name:       sp.Name,
						Arguments:  sp.Arguments,
					},
				},
			}
		case storedPartTypeToolResult:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_ToolResult{
					ToolResult: &tenantv1.MessagePartToolResult{
						ToolCallId: sp.ToolCallID,
						Result:     sp.Result,
					},
				},
			}
		case storedPartTypeCitation:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_Citation{
					Citation: &tenantv1.MessagePartCitation{
						CitationId: sp.CitationID,
						Label:      sp.Label,
						Url:        sp.URL,
					},
				},
			}
		case storedPartTypeAttachmentRef:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_AttachmentRef{
					AttachmentRef: &tenantv1.MessagePartAttachmentRef{
						AttachmentId: sp.AttachmentID,
						MediaType:    sp.MediaType,
						Name:         sp.AttachName,
					},
				},
			}
		case storedPartTypeReasoning:
			protoPart = &tenantv1.MessagePart{
				Part: &tenantv1.MessagePart_Reasoning{
					Reasoning: &tenantv1.MessagePartReasoning{Text: sp.ReasoningText},
				},
			}
		default:
			// Unknown stored type: skip silently. The part was not understood at
			// write time so we cannot reconstruct it on the read side.
			continue
		}
		parts = append(parts, protoPart)
	}
	return &tenantv1.ConversationMessage{
		Id:            m.ID,
		Role:          m.Role,
		Parts:         parts,
		CreatedAtUnix: m.CreatedAtUnix,
	}
}
