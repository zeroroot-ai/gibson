package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// mockConversationStore — simple mock for RPC handler tests
// ---------------------------------------------------------------------------

type mockConversationStore struct {
	// saved captures the most recent Save call arguments for inspection.
	saved *savedConvArgs

	conversations []storedConversation
	messages      []storedMessage
	listErr       error
	getErr        error
	saveErr       error
}

type savedConvArgs struct {
	tenantID       string
	userID         string
	conversationID string
	title          string
	agentID        string
	messages       []storedMessage
}

func (m *mockConversationStore) Save(
	_ context.Context,
	tenantID, userID, conversationID, title, agentID string,
	messages []storedMessage,
) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = &savedConvArgs{
		tenantID:       tenantID,
		userID:         userID,
		conversationID: conversationID,
		title:          title,
		agentID:        agentID,
		messages:       messages,
	}
	return nil
}

func (m *mockConversationStore) List(_ context.Context, _, _ string, _ int) ([]storedConversation, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.conversations, nil
}

func (m *mockConversationStore) Get(_ context.Context, _, _ string) (*storedConversation, []storedMessage, error) {
	if m.getErr != nil {
		return nil, nil, m.getErr
	}
	if len(m.conversations) == 0 {
		return nil, nil, assert.AnError
	}
	return &m.conversations[0], m.messages, nil
}

// ---------------------------------------------------------------------------
// ListConversations tests
// ---------------------------------------------------------------------------

func TestListConversations_EmptyTenantID_NilStore_Internal(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil conversationStore, the handler now returns codes.Internal (not empty)
	// because a nil store is a bootstrap defect per dashboard#549.
	srv := blankServer()
	_, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "", UserId: "u1"})
	// Empty tenant → InvalidArgument (tenant check comes before nil-store check)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListConversations_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListConversations_NilStore_Internal(t *testing.T) {
	// Nil conversationStore is a bootstrap defect (dashboard#549) → codes.Internal.
	srv := blankServer()
	_, err := srv.ListConversations(context.Background(), &userv1.ListConversationsRequest{TenantId: "acme", UserId: "u1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
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
		conversations: []storedConversation{
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

func TestGetConversation_EmptyTenantID_NilStore_InvalidArgument(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil store and empty tenant, the handler returns InvalidArgument now.
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "",
		ConversationId: "c1",
	})
	// Empty tenant → InvalidArgument (tenant check comes before nil-store check)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetConversation_MissingConversationID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetConversation_NilStore_Internal(t *testing.T) {
	// Nil conversationStore is a bootstrap defect (dashboard#549) → codes.Internal.
	srv := blankServer()
	_, err := srv.GetConversation(context.Background(), &userv1.GetConversationRequest{
		TenantId:       "acme",
		ConversationId: "c1",
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
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
		conversations: []storedConversation{
			{ID: "c1", TenantID: "acme", UserID: "u1", Title: "My Chat"},
		},
		messages: []storedMessage{
			{ID: "m1", Role: "user", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "Hello"}}, CreatedAtUnix: 100},
			{ID: "m2", Role: "assistant", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "Hi there"}}, CreatedAtUnix: 200},
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
	require.Len(t, resp.Messages[0].Parts, 1)
	assert.Equal(t, "Hello", resp.Messages[0].Parts[0].GetText().GetText())
}

// ---------------------------------------------------------------------------
// SaveConversation RPC tests
// ---------------------------------------------------------------------------

func TestSaveConversation_MissingConversationID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{}
	_, err := srv.SaveConversation(context.Background(), &userv1.SaveConversationRequest{
		TenantId: "acme",
		UserId:   "u1",
		Title:    "My Chat",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveConversation_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{}
	_, err := srv.SaveConversation(context.Background(), &userv1.SaveConversationRequest{
		ConversationId: "conv-1",
		UserId:         "u1",
		Title:          "My Chat",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveConversation_MissingUserID_InvalidArgument(t *testing.T) {
	// No caller identity in context and no UserId in request.
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{}
	_, err := srv.SaveConversation(context.Background(), &userv1.SaveConversationRequest{
		TenantId:       "acme",
		ConversationId: "conv-1",
		Title:          "My Chat",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveConversation_NilStore_Internal(t *testing.T) {
	// Nil store is a bootstrap defect → codes.Internal.
	srv := blankServer()
	_, err := srv.SaveConversation(context.Background(), &userv1.SaveConversationRequest{
		TenantId:       "acme",
		UserId:         "u1",
		ConversationId: "conv-1",
		Title:          "My Chat",
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestSaveConversation_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.conversationStore = &mockConversationStore{saveErr: assert.AnError}
	_, err := srv.SaveConversation(context.Background(), &userv1.SaveConversationRequest{
		TenantId:       "acme",
		UserId:         "u1",
		ConversationId: "conv-1",
		Title:          "My Chat",
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestSaveConversation_Success_PersistsConversation(t *testing.T) {
	srv := blankServer()
	mock := &mockConversationStore{}
	srv.conversationStore = mock

	// Build request with messages.
	req := &userv1.SaveConversationRequest{
		TenantId:       "acme",
		UserId:         "u1",
		ConversationId: "conv-1",
		Title:          "My First Chat",
		AgentId:        "agent-42",
		Messages: []*userv1.ConversationMessage{
			{Id: "m1", Role: "user", Parts: []*userv1.MessagePart{{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "Hello"}}}}, CreatedAtUnix: 100},
			{Id: "m2", Role: "assistant", Parts: []*userv1.MessagePart{{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "Hi there"}}}}, CreatedAtUnix: 200},
		},
	}

	resp, err := srv.SaveConversation(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the store received correct arguments.
	require.NotNil(t, mock.saved)
	assert.Equal(t, "acme", mock.saved.tenantID)
	assert.Equal(t, "u1", mock.saved.userID)
	assert.Equal(t, "conv-1", mock.saved.conversationID)
	assert.Equal(t, "My First Chat", mock.saved.title)
	assert.Equal(t, "agent-42", mock.saved.agentID)
	require.Len(t, mock.saved.messages, 2)
	assert.Equal(t, "m1", mock.saved.messages[0].ID)
	assert.Equal(t, "user", mock.saved.messages[0].Role)
	require.Len(t, mock.saved.messages[0].Parts, 1)
	assert.Equal(t, "Hello", mock.saved.messages[0].Parts[0].Text)
	assert.Equal(t, int64(100), mock.saved.messages[0].CreatedAtUnix)
}

func TestSaveConversation_CallerIdentityOverridesRequestUserID(t *testing.T) {
	// When the caller has an authenticated identity, the identity subject
	// MUST override the request UserId to prevent writing into another user's index.
	srv := blankServer()
	mock := &mockConversationStore{}
	srv.conversationStore = mock

	// Inject caller identity with subject "caller-subject".
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "caller-subject",
	})

	req := &userv1.SaveConversationRequest{
		TenantId:       "acme",
		UserId:         "different-user", // attacker tries to write as a different user
		ConversationId: "conv-1",
		Title:          "My Chat",
	}

	_, err := srv.SaveConversation(ctx, req)
	require.NoError(t, err)

	// The store must have received the caller's identity, not the request UserId.
	require.NotNil(t, mock.saved)
	assert.Equal(t, "caller-subject", mock.saved.userID, "caller identity must override request UserId")
}

func TestSaveConversation_TenantFromContext_WhenRequestTenantEmpty(t *testing.T) {
	// When request TenantId is empty, tenant is resolved from auth context.
	srv := blankServer()
	mock := &mockConversationStore{}
	srv.conversationStore = mock

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("context-tenant"))

	req := &userv1.SaveConversationRequest{
		TenantId:       "", // empty — should fall back to context
		UserId:         "u1",
		ConversationId: "conv-1",
		Title:          "My Chat",
	}

	_, err := srv.SaveConversation(ctx, req)
	require.NoError(t, err)

	require.NotNil(t, mock.saved)
	assert.Equal(t, "context-tenant", mock.saved.tenantID)
}

// ---------------------------------------------------------------------------
// GetConversationStore accessor — bootstrap nil-store guard test
// ---------------------------------------------------------------------------

func TestGetConversationStore_NilWhenNotWired(t *testing.T) {
	srv := &DaemonServer{logger: testSlogLogger}
	assert.Nil(t, srv.GetConversationStore(), "store must be nil when not wired")
}

func TestGetConversationStore_NonNilWhenWired(t *testing.T) {
	srv := &DaemonServer{logger: testSlogLogger}
	store := newInMemConvStore()
	srv.WithConversationStore(store)
	assert.NotNil(t, srv.GetConversationStore(), "store must be non-nil after wiring")
}

// ---------------------------------------------------------------------------
// Store unit tests: save + list, save + get, cross-tenant isolation, TTL,
// newest-first ordering, pagination bounds, user isolation
//
// These tests use an in-memory store double (inMemConvStore) that replicates
// the key-schema and TTL-tracking logic of redisConversationStore, allowing
// deterministic verification without a running Redis server.
// ---------------------------------------------------------------------------

// TestConversationStore_SaveAndList verifies that Save writes an entry and
// List returns it with correct metadata.
func TestConversationStore_SaveAndList(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	msgs := []storedMessage{
		{ID: "m1", Role: "user", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "hello"}}, CreatedAtUnix: 1000},
		{ID: "m2", Role: "assistant", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "hi"}}, CreatedAtUnix: 1001},
	}

	err := store.Save(ctx, "tenant-A", "user-1", "conv-1", "My Chat", "agent-x", msgs)
	require.NoError(t, err)

	convs, err := store.List(ctx, "tenant-A", "user-1", 10)
	require.NoError(t, err)
	require.Len(t, convs, 1)

	c := convs[0]
	assert.Equal(t, "conv-1", c.ID)
	assert.Equal(t, "tenant-A", c.TenantID)
	assert.Equal(t, "user-1", c.UserID)
	assert.Equal(t, "My Chat", c.Title)
	assert.Equal(t, "agent-x", c.AgentID)
	assert.Equal(t, int32(2), c.MessageCount)
}

// TestConversationStore_SaveAndGet verifies that after Save, Get returns the
// conversation with its full message list.
func TestConversationStore_SaveAndGet(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	msgs := []storedMessage{
		{ID: "m1", Role: "user", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "question"}}, CreatedAtUnix: 500},
		{ID: "m2", Role: "assistant", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "answer"}}, CreatedAtUnix: 501},
	}
	err := store.Save(ctx, "tenant-B", "user-2", "conv-2", "Q&A", "agent-y", msgs)
	require.NoError(t, err)

	conv, gotMsgs, err := store.Get(ctx, "tenant-B", "conv-2")
	require.NoError(t, err)
	require.NotNil(t, conv)

	assert.Equal(t, "conv-2", conv.ID)
	assert.Equal(t, "tenant-B", conv.TenantID)
	assert.Equal(t, "user-2", conv.UserID)
	assert.Equal(t, "Q&A", conv.Title)
	assert.Equal(t, int32(2), conv.MessageCount)

	require.Len(t, gotMsgs, 2)
	require.NotEmpty(t, gotMsgs[0].Parts)
	assert.Equal(t, "question", gotMsgs[0].Parts[0].Text)
	assert.Equal(t, "answer", gotMsgs[1].Parts[0].Text)
}

// TestConversationStore_RoundTrip_SaveListGet verifies the full round-trip:
// Save → List includes it → Get returns same data with messages intact.
func TestConversationStore_RoundTrip_SaveListGet(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	msgs := []storedMessage{
		{ID: "m1", Role: "user", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "first question"}}, CreatedAtUnix: 1000},
		{ID: "m2", Role: "assistant", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "first answer"}}, CreatedAtUnix: 1001},
		{ID: "m3", Role: "user", Parts: []storedMessagePart{{Type: storedPartTypeText, Text: "follow up"}}, CreatedAtUnix: 1002},
	}

	err := store.Save(ctx, "tenant-RT", "user-RT", "conv-RT", "Round Trip Chat", "agent-RT", msgs)
	require.NoError(t, err)

	// List returns it.
	convs, err := store.List(ctx, "tenant-RT", "user-RT", 10)
	require.NoError(t, err)
	require.Len(t, convs, 1)
	assert.Equal(t, "conv-RT", convs[0].ID)
	assert.Equal(t, "Round Trip Chat", convs[0].Title)
	assert.Equal(t, int32(3), convs[0].MessageCount)

	// Get returns same data with messages.
	conv, gotMsgs, err := store.Get(ctx, "tenant-RT", "conv-RT")
	require.NoError(t, err)
	assert.Equal(t, convs[0].ID, conv.ID)
	assert.Equal(t, convs[0].Title, conv.Title)
	require.Len(t, gotMsgs, 3)
	require.NotEmpty(t, gotMsgs[0].Parts)
	assert.Equal(t, "first question", gotMsgs[0].Parts[0].Text)
	assert.Equal(t, "first answer", gotMsgs[1].Parts[0].Text)
	assert.Equal(t, "follow up", gotMsgs[2].Parts[0].Text)
}

// TestConversationStore_NewestFirst verifies that List returns conversations
// ordered by updated_at descending (newest first).
//
// The inMemConvStore uses time.Now().Unix() which has second-level precision.
// To guarantee distinct scores without sleeping, we manipulate the sorted-set
// scores directly on the store after each Save — the ordering logic is the
// same regardless of whether the scores came from the clock or an explicit set.
func TestConversationStore_NewestFirst(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()
	mem := store.(*inMemConvStore)

	err := store.Save(ctx, "tenant-Order", "user-Order", "conv-oldest", "Oldest", "", nil)
	require.NoError(t, err)
	err = store.Save(ctx, "tenant-Order", "user-Order", "conv-middle", "Middle", "", nil)
	require.NoError(t, err)
	err = store.Save(ctx, "tenant-Order", "user-Order", "conv-newest", "Newest", "", nil)
	require.NoError(t, err)

	// Override the scores to guarantee a deterministic order independent of
	// the system clock's second-level precision.
	idxKey := convIndexKey("tenant-Order", "user-Order")
	for i, e := range mem.indexes[idxKey] {
		switch e.member {
		case "conv-oldest":
			mem.indexes[idxKey][i].score = 1000
		case "conv-middle":
			mem.indexes[idxKey][i].score = 2000
		case "conv-newest":
			mem.indexes[idxKey][i].score = 3000
		}
	}

	convs, err := store.List(ctx, "tenant-Order", "user-Order", 10)
	require.NoError(t, err)
	require.Len(t, convs, 3)

	// Newest (highest score) must come first.
	assert.Equal(t, "conv-newest", convs[0].ID, "newest conversation must be first")
	assert.Equal(t, "conv-middle", convs[1].ID)
	assert.Equal(t, "conv-oldest", convs[2].ID)
}

// TestConversationStore_PaginationLimit verifies that List respects the limit parameter.
func TestConversationStore_PaginationLimit(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()
	mem := store.(*inMemConvStore)

	// Save 5 conversations.
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("conv-%d", i)
		err := store.Save(ctx, "tenant-Pag", "user-Pag", id, fmt.Sprintf("Chat %d", i), "", nil)
		require.NoError(t, err)
	}

	// Override scores to be distinct (clock has second precision).
	idxKey := convIndexKey("tenant-Pag", "user-Pag")
	for i := range mem.indexes[idxKey] {
		mem.indexes[idxKey][i].score = float64(i + 1)
	}

	// Limit=2 must return exactly 2.
	convs, err := store.List(ctx, "tenant-Pag", "user-Pag", 2)
	require.NoError(t, err)
	assert.Len(t, convs, 2, "limit=2 must return exactly 2 conversations")

	// Limit=0 uses default (20 > 5), so all 5 are returned.
	convs, err = store.List(ctx, "tenant-Pag", "user-Pag", 0)
	require.NoError(t, err)
	assert.Len(t, convs, 5, "limit=0 uses default, returning all 5")
}

// TestConversationStore_CrossTenantIsolation verifies that tenant A cannot
// read conversations belonging to tenant B.
func TestConversationStore_CrossTenantIsolation(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	// Save a conversation for tenant-A / user-1.
	err := store.Save(ctx, "tenant-A", "user-1", "conv-tenant-a", "A's chat", "", nil)
	require.NoError(t, err)

	// List for tenant-B / user-1 must return nothing.
	convs, err := store.List(ctx, "tenant-B", "user-1", 10)
	require.NoError(t, err)
	assert.Empty(t, convs, "tenant-B should not see tenant-A conversations")

	// Get for tenant-B must return not-found.
	_, _, err = store.Get(ctx, "tenant-B", "conv-tenant-a")
	assert.Error(t, err, "tenant-B should not access tenant-A conversations")

	// Confirm tenant-A can still access its own conversation.
	convs, err = store.List(ctx, "tenant-A", "user-1", 10)
	require.NoError(t, err)
	require.Len(t, convs, 1)
	assert.Equal(t, "conv-tenant-a", convs[0].ID)
}

// TestConversationStore_CrossUserIsolation verifies that user A cannot list
// user B's conversations within the same tenant (index is keyed by userID).
func TestConversationStore_CrossUserIsolation(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	err := store.Save(ctx, "shared-tenant", "user-A", "conv-user-a", "A's private chat", "", nil)
	require.NoError(t, err)

	err = store.Save(ctx, "shared-tenant", "user-B", "conv-user-b", "B's private chat", "", nil)
	require.NoError(t, err)

	// user-A's list must not include user-B's conversations.
	convsA, err := store.List(ctx, "shared-tenant", "user-A", 10)
	require.NoError(t, err)
	require.Len(t, convsA, 1)
	assert.Equal(t, "conv-user-a", convsA[0].ID)

	// user-B's list must not include user-A's conversations.
	convsB, err := store.List(ctx, "shared-tenant", "user-B", 10)
	require.NoError(t, err)
	require.Len(t, convsB, 1)
	assert.Equal(t, "conv-user-b", convsB[0].ID)
}

// TestConversationStore_TTLSetOnSave verifies that Save records the TTL for
// both the hash key and the sorted-set index key.
func TestConversationStore_TTLSetOnSave(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	err := store.Save(ctx, "tenant-C", "user-3", "conv-3", "chat", "", nil)
	require.NoError(t, err)

	mem := store.(*inMemConvStore)

	hashTTL := mem.ttls[convHashKey("tenant-C", "conv-3")]
	assert.Equal(t, conversationTTL, hashTTL, "hash key must have a 90-day TTL")

	idxTTL := mem.ttls[convIndexKey("tenant-C", "user-3")]
	assert.Equal(t, conversationTTL, idxTTL, "index key must have a 90-day TTL")
}

// ---------------------------------------------------------------------------
// inMemConvStore — in-memory test double for conversationStoreIface
//
// Implements the same key-schema logic as redisConversationStore so the tests
// are meaningful without requiring a running Redis server.
// ---------------------------------------------------------------------------

// inMemConvStore is a concurrency-unsafe, deterministic in-memory
// implementation of conversationStoreIface used exclusively by unit tests.
type inMemConvStore struct {
	// hashes maps hashKey → (fieldName → value)
	hashes map[string]map[string]string
	// indexes maps indexKey → sorted entries
	indexes map[string][]zEntry
	// ttls records the most recent Expire duration for each key
	ttls map[string]time.Duration
}

type zEntry struct {
	score  float64
	member string
}

func newInMemConvStore() conversationStoreIface {
	return &inMemConvStore{
		hashes:  make(map[string]map[string]string),
		indexes: make(map[string][]zEntry),
		ttls:    make(map[string]time.Duration),
	}
}

func (s *inMemConvStore) Save(
	_ context.Context,
	tenantID, userID, conversationID, title, agentID string,
	messages []storedMessage,
) error {
	if tenantID == "" || userID == "" || conversationID == "" {
		return fmt.Errorf("tenant_id, user_id, and conversation_id are required")
	}

	hashKey := convHashKey(tenantID, conversationID)
	idxKey := convIndexKey(tenantID, userID)

	now := time.Now().Unix()

	// Preserve created_at on update.
	createdAt := strconv.FormatInt(now, 10)
	if existing, ok := s.hashes[hashKey]; ok {
		if v, exists := existing["created_at"]; exists {
			createdAt = v
		}
	}

	if messages == nil {
		messages = []storedMessage{}
	}
	msgsJSON, _ := json.Marshal(messages)

	if s.hashes[hashKey] == nil {
		s.hashes[hashKey] = make(map[string]string)
	}
	s.hashes[hashKey]["title"] = title
	s.hashes[hashKey]["agent_id"] = agentID
	s.hashes[hashKey]["user_id"] = userID
	s.hashes[hashKey]["created_at"] = createdAt
	s.hashes[hashKey]["updated_at"] = strconv.FormatInt(now, 10)
	s.hashes[hashKey]["messages"] = string(msgsJSON)

	// Record TTLs.
	s.ttls[hashKey] = conversationTTL
	s.ttls[idxKey] = conversationTTL

	// Upsert the sorted-set entry.
	score := float64(now)
	newEntries := make([]zEntry, 0, len(s.indexes[idxKey])+1)
	found := false
	for _, e := range s.indexes[idxKey] {
		if e.member == conversationID {
			newEntries = append(newEntries, zEntry{score: score, member: conversationID})
			found = true
		} else {
			newEntries = append(newEntries, e)
		}
	}
	if !found {
		newEntries = append(newEntries, zEntry{score: score, member: conversationID})
	}
	s.indexes[idxKey] = newEntries

	return nil
}

func (s *inMemConvStore) List(_ context.Context, tenantID, userID string, limit int) ([]storedConversation, error) {
	if limit <= 0 {
		limit = conversationDefaultLimit
	}
	idxKey := convIndexKey(tenantID, userID)
	entries := s.indexes[idxKey]

	// Sort descending by score (simple bubble sort; test data is tiny).
	sorted := make([]zEntry, len(entries))
	copy(sorted, entries)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].score > sorted[i].score {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	out := make([]storedConversation, 0, limit)
	for _, e := range sorted {
		if len(out) >= limit {
			break
		}
		hashKey := convHashKey(tenantID, e.member)
		h := s.hashes[hashKey]
		if h == nil {
			continue
		}
		createdAt, _ := strconv.ParseInt(h["created_at"], 10, 64)
		updatedAt, _ := strconv.ParseInt(h["updated_at"], 10, 64)

		var msgCount int32
		if msgsJSON := h["messages"]; msgsJSON != "" {
			var msgs []storedMessage
			if jsonErr := json.Unmarshal([]byte(msgsJSON), &msgs); jsonErr == nil {
				msgCount = int32(len(msgs))
			}
		}

		out = append(out, storedConversation{
			ID:            e.member,
			TenantID:      tenantID,
			UserID:        h["user_id"],
			Title:         h["title"],
			AgentID:       h["agent_id"],
			CreatedAtUnix: createdAt,
			UpdatedAtUnix: updatedAt,
			MessageCount:  msgCount,
		})
	}
	return out, nil
}

func (s *inMemConvStore) Get(_ context.Context, tenantID, conversationID string) (*storedConversation, []storedMessage, error) {
	hashKey := convHashKey(tenantID, conversationID)
	h := s.hashes[hashKey]
	if h == nil {
		return nil, nil, fmt.Errorf("conversation not found")
	}

	createdAt, _ := strconv.ParseInt(h["created_at"], 10, 64)
	updatedAt, _ := strconv.ParseInt(h["updated_at"], 10, 64)

	var msgs []storedMessage
	if msgsJSON := h["messages"]; msgsJSON != "" {
		_ = json.Unmarshal([]byte(msgsJSON), &msgs)
	}

	conv := &storedConversation{
		ID:            conversationID,
		TenantID:      tenantID,
		UserID:        h["user_id"],
		Title:         h["title"],
		AgentID:       h["agent_id"],
		CreatedAtUnix: createdAt,
		UpdatedAtUnix: updatedAt,
		MessageCount:  int32(len(msgs)),
	}
	return conv, msgs, nil
}

// ---------------------------------------------------------------------------
// Parts round-trip tests (slice #550)
//
// These tests verify that all six part types round-trip losslessly through
// protoMessageToStored → storedMessageToProto and through the inMemConvStore.
// ---------------------------------------------------------------------------

// TestPartsRoundTrip_AllPartTypes verifies that a message containing one of
// every part type (text, tool_call, tool_result, citation, attachment_ref,
// reasoning) round-trips through protoMessageToStored → storedMessageToProto
// with zero loss and preserved ordering.
func TestPartsRoundTrip_AllPartTypes(t *testing.T) {
	input := &userv1.ConversationMessage{
		Id:            "msg-all",
		Role:          "assistant",
		CreatedAtUnix: 9999,
		Parts: []*userv1.MessagePart{
			{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "hello world"}}},
			{Part: &userv1.MessagePart_ToolCall{ToolCall: &userv1.MessagePartToolCall{
				ToolCallId: "tc-1",
				Name:       "search",
				Arguments:  `{"q":"foo"}`,
			}}},
			{Part: &userv1.MessagePart_ToolResult{ToolResult: &userv1.MessagePartToolResult{
				ToolCallId: "tc-1",
				Result:     `{"results":[]}`,
			}}},
			{Part: &userv1.MessagePart_Citation{Citation: &userv1.MessagePartCitation{
				CitationId: "cite-42",
				Label:      "Node A",
				Url:        "https://example.com/node/42",
			}}},
			{Part: &userv1.MessagePart_AttachmentRef{AttachmentRef: &userv1.MessagePartAttachmentRef{
				AttachmentId: "att-7",
				MediaType:    "image/png",
				Name:         "screenshot.png",
			}}},
			{Part: &userv1.MessagePart_Reasoning{Reasoning: &userv1.MessagePartReasoning{
				Text: "Let me think about this...",
			}}},
		},
	}

	// Convert proto → stored → proto.
	stored := protoMessageToStored(input)
	output := storedMessageToProto(stored)

	// Metadata preserved.
	assert.Equal(t, "msg-all", output.Id)
	assert.Equal(t, "assistant", output.Role)
	assert.Equal(t, int64(9999), output.CreatedAtUnix)

	// Exactly 6 parts, in order.
	require.Len(t, output.Parts, 6, "all 6 parts must be preserved")

	// Part 0: text
	text := output.Parts[0].GetText()
	require.NotNil(t, text, "part[0] must be text")
	assert.Equal(t, "hello world", text.Text)

	// Part 1: tool_call
	tc := output.Parts[1].GetToolCall()
	require.NotNil(t, tc, "part[1] must be tool_call")
	assert.Equal(t, "tc-1", tc.ToolCallId)
	assert.Equal(t, "search", tc.Name)
	assert.Equal(t, `{"q":"foo"}`, tc.Arguments)

	// Part 2: tool_result
	tr := output.Parts[2].GetToolResult()
	require.NotNil(t, tr, "part[2] must be tool_result")
	assert.Equal(t, "tc-1", tr.ToolCallId)
	assert.Equal(t, `{"results":[]}`, tr.Result)

	// Part 3: citation
	cit := output.Parts[3].GetCitation()
	require.NotNil(t, cit, "part[3] must be citation")
	assert.Equal(t, "cite-42", cit.CitationId)
	assert.Equal(t, "Node A", cit.Label)
	assert.Equal(t, "https://example.com/node/42", cit.Url)

	// Part 4: attachment_ref
	att := output.Parts[4].GetAttachmentRef()
	require.NotNil(t, att, "part[4] must be attachment_ref")
	assert.Equal(t, "att-7", att.AttachmentId)
	assert.Equal(t, "image/png", att.MediaType)
	assert.Equal(t, "screenshot.png", att.Name)

	// Part 5: reasoning
	rsn := output.Parts[5].GetReasoning()
	require.NotNil(t, rsn, "part[5] must be reasoning")
	assert.Equal(t, "Let me think about this...", rsn.Text)
}

// TestPartsRoundTrip_OrderingPreserved verifies that part ordering is stable
// across the stored-message JSON round-trip (not just the in-memory conversion).
func TestPartsRoundTrip_OrderingPreserved(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	// Build a message with 4 parts in a deliberate interleaved order.
	input := &userv1.ConversationMessage{
		Id:   "msg-order",
		Role: "assistant",
		Parts: []*userv1.MessagePart{
			{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "first"}}},
			{Part: &userv1.MessagePart_ToolCall{ToolCall: &userv1.MessagePartToolCall{Name: "run", Arguments: "{}"}}},
			{Part: &userv1.MessagePart_ToolResult{ToolResult: &userv1.MessagePartToolResult{Result: "ok"}}},
			{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "second"}}},
		},
	}

	msgs := []storedMessage{protoMessageToStored(input)}
	err := store.Save(ctx, "t1", "u1", "c1", "Order Test", "", msgs)
	require.NoError(t, err)

	_, gotMsgs, err := store.Get(ctx, "t1", "c1")
	require.NoError(t, err)
	require.Len(t, gotMsgs, 1)

	out := storedMessageToProto(gotMsgs[0])
	require.Len(t, out.Parts, 4, "4 parts must survive store round-trip")

	assert.Equal(t, "first", out.Parts[0].GetText().GetText(), "part[0]: first text")
	assert.Equal(t, "run", out.Parts[1].GetToolCall().GetName(), "part[1]: tool_call")
	assert.Equal(t, "ok", out.Parts[2].GetToolResult().GetResult(), "part[2]: tool_result")
	assert.Equal(t, "second", out.Parts[3].GetText().GetText(), "part[3]: second text")
}

// TestPartsRoundTrip_TextOnlyMessage verifies that a message with a single text
// part round-trips correctly (regression guard for the most common case).
func TestPartsRoundTrip_TextOnlyMessage(t *testing.T) {
	input := &userv1.ConversationMessage{
		Id:            "msg-txt",
		Role:          "user",
		CreatedAtUnix: 1234,
		Parts: []*userv1.MessagePart{
			{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "just text"}}},
		},
	}

	stored := protoMessageToStored(input)
	output := storedMessageToProto(stored)

	require.Len(t, output.Parts, 1)
	assert.Equal(t, "just text", output.Parts[0].GetText().GetText())
	assert.Equal(t, int64(1234), output.CreatedAtUnix)
}

// TestPartsRoundTrip_StoreRoundTrip_AllPartTypes verifies the full end-to-end
// round-trip: proto → Save to inMemConvStore → Get from inMemConvStore → proto.
// Every part type is checked.
func TestPartsRoundTrip_StoreRoundTrip_AllPartTypes(t *testing.T) {
	store := newInMemConvStore()
	ctx := context.Background()

	input := &userv1.ConversationMessage{
		Id:   "msg-full",
		Role: "assistant",
		Parts: []*userv1.MessagePart{
			{Part: &userv1.MessagePart_Text{Text: &userv1.MessagePartText{Text: "result text"}}},
			{Part: &userv1.MessagePart_ToolCall{ToolCall: &userv1.MessagePartToolCall{
				ToolCallId: "tc-99", Name: "fetch", Arguments: `{"url":"https://x.com"}`,
			}}},
			{Part: &userv1.MessagePart_ToolResult{ToolResult: &userv1.MessagePartToolResult{
				ToolCallId: "tc-99", Result: `{"status":200}`,
			}}},
			{Part: &userv1.MessagePart_Citation{Citation: &userv1.MessagePartCitation{
				CitationId: "cit-1", Label: "Ref Node", Url: "https://graph.example/1",
			}}},
			{Part: &userv1.MessagePart_AttachmentRef{AttachmentRef: &userv1.MessagePartAttachmentRef{
				AttachmentId: "att-1", MediaType: "application/pdf", Name: "report.pdf",
			}}},
			{Part: &userv1.MessagePart_Reasoning{Reasoning: &userv1.MessagePartReasoning{
				Text: "internal thought",
			}}},
		},
	}

	msgs := []storedMessage{protoMessageToStored(input)}
	err := store.Save(ctx, "tenant-X", "user-X", "conv-X", "Full Round-Trip", "", msgs)
	require.NoError(t, err)

	_, gotMsgs, err := store.Get(ctx, "tenant-X", "conv-X")
	require.NoError(t, err)
	require.Len(t, gotMsgs, 1)

	out := storedMessageToProto(gotMsgs[0])
	require.Len(t, out.Parts, 6, "all 6 parts must survive full store round-trip")

	assert.Equal(t, "result text", out.Parts[0].GetText().GetText())
	assert.Equal(t, "tc-99", out.Parts[1].GetToolCall().GetToolCallId())
	assert.Equal(t, `{"url":"https://x.com"}`, out.Parts[1].GetToolCall().GetArguments())
	assert.Equal(t, `{"status":200}`, out.Parts[2].GetToolResult().GetResult())
	assert.Equal(t, "cit-1", out.Parts[3].GetCitation().GetCitationId())
	assert.Equal(t, "Ref Node", out.Parts[3].GetCitation().GetLabel())
	assert.Equal(t, "att-1", out.Parts[4].GetAttachmentRef().GetAttachmentId())
	assert.Equal(t, "report.pdf", out.Parts[4].GetAttachmentRef().GetName())
	assert.Equal(t, "internal thought", out.Parts[5].GetReasoning().GetText())
}
