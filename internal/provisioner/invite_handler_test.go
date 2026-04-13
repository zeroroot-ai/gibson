package provisioner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockAuthzForInvite struct {
	writeErr      error
	writtenTuples []authz.Tuple
	deletedTuples []authz.Tuple
}

func (m *mockAuthzForInvite) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (m *mockAuthzForInvite) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) Write(_ context.Context, tuples []authz.Tuple) error {
	m.writtenTuples = append(m.writtenTuples, tuples...)
	return m.writeErr
}
func (m *mockAuthzForInvite) Delete(_ context.Context, tuples []authz.Tuple) error {
	m.deletedTuples = append(m.deletedTuples, tuples...)
	return nil
}
func (m *mockAuthzForInvite) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) StoreID() string { return "" }
func (m *mockAuthzForInvite) ModelID() string { return "" }
func (m *mockAuthzForInvite) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestInviteHandler(t *testing.T, az authz.Authorizer, rc *redis.Client) *InviteHandler {
	t.Helper()
	h, err := NewInviteHandler(nil, az, rc, InviteHandlerConfig{
		SigningKey: []byte("test-signing-key-32-bytes-long!!"),
		BaseURL:   "https://app.example.com",
		TokenTTL:  24 * time.Hour,
	}, nil)
	require.NoError(t, err)
	return h
}

func newMiniRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// ---------------------------------------------------------------------------
// Tests: Invite (success and failure paths)
// ---------------------------------------------------------------------------

func TestInviteHandler_Invite_Success(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "alice@example.com",
		Role:     "admin",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, inv.Token)
	assert.NotEmpty(t, inv.InvitationURL)
	assert.Equal(t, "acme", inv.TenantID)
	assert.Contains(t, inv.InvitationURL, "/invite/accept?token=")

	// Verify FGA tuple was written with admin relation.
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "user:invite:alice@example.com", az.writtenTuples[0].User)
	assert.Equal(t, "admin", az.writtenTuples[0].Relation)
	assert.Equal(t, "tenant:acme", az.writtenTuples[0].Object)
}

func TestInviteHandler_Invite_OperatorRole_UsesMemberRelation(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "bob@example.com",
		Role:     "operator",
	})
	require.NoError(t, err)
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "member", az.writtenTuples[0].Relation)
}

func TestInviteHandler_Invite_FGAWriteFails_ReturnsError(t *testing.T) {
	az := &mockAuthzForInvite{writeErr: errors.New("fga write failed")}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "eve@example.com",
		Role:     "operator",
	})
	require.Error(t, err)
}

func TestInviteHandler_Invite_InvalidRole_ReturnsError(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "frank@example.com",
		Role:     "superuser", // invalid
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignupInput)
}

// ---------------------------------------------------------------------------
// Tests: Accept
// ---------------------------------------------------------------------------

func TestInviteHandler_Accept_ValidToken(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	// Create a real invitation first.
	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "grace@example.com",
		Role:     "operator",
	})
	require.NoError(t, err)

	// Accept it.
	result, err := h.Accept(context.Background(), inv.Token)
	require.NoError(t, err)
	assert.Equal(t, "acme", result.TenantID)
	assert.Equal(t, "operator", result.Role)
	assert.NotEmpty(t, result.PasswordSetURL)
}

func TestInviteHandler_Accept_AlreadyConsumed(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "henry@example.com",
		Role:     "viewer",
	})
	require.NoError(t, err)

	// Accept once.
	_, err = h.Accept(context.Background(), inv.Token)
	require.NoError(t, err)

	// Accept again should return ErrInvitationConsumed.
	_, err = h.Accept(context.Background(), inv.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvitationConsumed)
}

func TestInviteHandler_Accept_ExpiredToken(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)

	// Use a very short TTL to simulate expiry.
	h, err := NewInviteHandler(nil, az, rc, InviteHandlerConfig{
		SigningKey: []byte("test-signing-key-32-bytes-long!!"),
		BaseURL:   "https://app.example.com",
		TokenTTL:  1 * time.Millisecond,
	}, nil)
	require.NoError(t, err)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		Email:    "iris@example.com",
		Role:     "viewer",
	})
	require.NoError(t, err)

	// Wait for TTL to elapse.
	time.Sleep(50 * time.Millisecond)

	// The Redis key has expired; Accept should return an error.
	_, err = h.Accept(context.Background(), inv.Token)
	require.Error(t, err)
}

func TestInviteHandler_Accept_InvalidToken(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	_, err := h.Accept(context.Background(), "not.a.valid.jwt")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvitationInvalid)
}

// ---------------------------------------------------------------------------
// Tests: Resend
// ---------------------------------------------------------------------------

func TestInviteHandler_Resend_Success(t *testing.T) {
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, az, rc)

	inv, err := h.Resend(context.Background(), "acme", "user-333", "jack@example.com", "viewer")
	require.NoError(t, err)
	assert.NotEmpty(t, inv.Token)
	assert.Equal(t, "user-333", inv.UserID)
	assert.Equal(t, "acme", inv.TenantID)
}

// ---------------------------------------------------------------------------
// Tests: constructor validation
// ---------------------------------------------------------------------------

func TestNewInviteHandler_NilKeyRejected(t *testing.T) {
	rc := newMiniRedis(t)
	_, err := NewInviteHandler(
		nil,
		&mockAuthzForInvite{},
		rc,
		InviteHandlerConfig{SigningKey: []byte("short")}, // too short
		nil,
	)
	require.Error(t, err)
}
