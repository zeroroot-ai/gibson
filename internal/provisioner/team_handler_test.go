package provisioner

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// mockAuthzForTeam tracks FGA operations and controls Check behaviour.
type mockAuthzForTeam struct {
	writtenTuples  []authz.Tuple
	deletedTuples  []authz.Tuple
	checkResult    bool
	checkErr       error
	writeErr       error
	deleteErr      error
}

func (m *mockAuthzForTeam) Check(_ context.Context, _, _, _ string) (bool, error) {
	return m.checkResult, m.checkErr
}
func (m *mockAuthzForTeam) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthzForTeam) Write(_ context.Context, tuples []authz.Tuple) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writtenTuples = append(m.writtenTuples, tuples...)
	return nil
}
func (m *mockAuthzForTeam) Delete(_ context.Context, tuples []authz.Tuple) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedTuples = append(m.deletedTuples, tuples...)
	return nil
}
func (m *mockAuthzForTeam) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForTeam) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForTeam) StoreID() string { return "" }
func (m *mockAuthzForTeam) ModelID() string { return "" }
func (m *mockAuthzForTeam) Close() error    { return nil }

func newMiniRedisForTeam(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestTeamHandler_Create_Success(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	rec, err := h.Create(context.Background(), "acme", "Security Ops", "desc", "user-admin")
	require.NoError(t, err)
	assert.NotEmpty(t, rec.TeamID)
	assert.Equal(t, "acme", rec.TenantID)
	assert.Equal(t, "Security Ops", rec.Name)
	assert.Equal(t, "user-admin", rec.CreatedBy)

	// FGA parent tuple written.
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "parent", az.writtenTuples[0].Relation)
	assert.Contains(t, az.writtenTuples[0].User, "team:")
	assert.Equal(t, "tenant:acme", az.writtenTuples[0].Object)
}

func TestTeamHandler_Create_FGAFails_RollsBackRedis(t *testing.T) {
	az := &mockAuthzForTeam{writeErr: errors.New("fga unavailable")}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	_, err = h.Create(context.Background(), "acme", "Team Alpha", "", "user-admin")
	require.Error(t, err)

	// Verify Redis was cleaned up.
	listKey := teamListKey("acme")
	count, _ := rc.SCard(context.Background(), listKey).Result()
	assert.Equal(t, int64(0), count)
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestTeamHandler_List_Empty(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	teams, err := h.List(context.Background(), "acme")
	require.NoError(t, err)
	assert.Len(t, teams, 0)
}

func TestTeamHandler_List_ReturnsCreatedTeams(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	_, err = h.Create(context.Background(), "acme", "Alpha", "", "user-admin")
	require.NoError(t, err)
	_, err = h.Create(context.Background(), "acme", "Beta", "", "user-admin")
	require.NoError(t, err)

	teams, err := h.List(context.Background(), "acme")
	require.NoError(t, err)
	assert.Len(t, teams, 2)
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestTeamHandler_Delete_Success(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	rec, err := h.Create(context.Background(), "acme", "Delete Me", "", "user-admin")
	require.NoError(t, err)

	err = h.Delete(context.Background(), "acme", rec.TeamID)
	require.NoError(t, err)

	// Should be gone from the list.
	teams, err := h.List(context.Background(), "acme")
	require.NoError(t, err)
	assert.Len(t, teams, 0)
}

// ---------------------------------------------------------------------------
// Tests: AddMember
// ---------------------------------------------------------------------------

func TestTeamHandler_AddMember_Success(t *testing.T) {
	az := &mockAuthzForTeam{checkResult: true}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	err = h.AddMember(context.Background(), "acme", "team-001", "user-abc")
	require.NoError(t, err)

	// FGA: one parent write (from handler setup) plus one member write.
	// In this test Create is not called so writtenTuples has 1 entry (the member tuple).
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "member", az.writtenTuples[0].Relation)
	assert.Equal(t, "user:user-abc", az.writtenTuples[0].User)
	assert.Equal(t, "team:team-001", az.writtenTuples[0].Object)
}

func TestTeamHandler_AddMember_UserNotTenantMember_Rejected(t *testing.T) {
	az := &mockAuthzForTeam{checkResult: false}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	err = h.AddMember(context.Background(), "acme", "team-001", "user-xyz")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotTenantMember)
}

// ---------------------------------------------------------------------------
// Tests: RemoveMember
// ---------------------------------------------------------------------------

func TestTeamHandler_RemoveMember_Success(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	err = h.RemoveMember(context.Background(), "acme", "team-001", "user-abc")
	require.NoError(t, err)

	require.Len(t, az.deletedTuples, 1)
	assert.Equal(t, "member", az.deletedTuples[0].Relation)
}

// ---------------------------------------------------------------------------
// Tests: SetCrosstalk
// ---------------------------------------------------------------------------

func TestTeamHandler_SetCrosstalk_Enable(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	err = h.SetCrosstalk(context.Background(), "acme", "team-alpha", "team-beta", true)
	require.NoError(t, err)

	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "can_view_data_from", az.writtenTuples[0].Relation)
	assert.Equal(t, "team:team-alpha", az.writtenTuples[0].User)
	assert.Equal(t, "team:team-beta", az.writtenTuples[0].Object)
}

func TestTeamHandler_SetCrosstalk_Disable(t *testing.T) {
	az := &mockAuthzForTeam{}
	rc := newMiniRedisForTeam(t)
	h, err := NewTeamHandler(az, rc, nil)
	require.NoError(t, err)

	err = h.SetCrosstalk(context.Background(), "acme", "team-alpha", "team-beta", false)
	require.NoError(t, err)

	require.Len(t, az.deletedTuples, 1)
	assert.Equal(t, "can_view_data_from", az.deletedTuples[0].Relation)
}

// ---------------------------------------------------------------------------
// Tests: constructor
// ---------------------------------------------------------------------------

func TestNewTeamHandler_NilAuthzRejected(t *testing.T) {
	rc := newMiniRedisForTeam(t)
	_, err := NewTeamHandler(nil, rc, nil)
	require.Error(t, err)
}

func TestNewTeamHandler_NilRedisRejected(t *testing.T) {
	_, err := NewTeamHandler(&mockAuthzForTeam{}, nil, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: slugifyTeamName
// ---------------------------------------------------------------------------

func TestSlugifyTeamName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Security Ops", "security-ops"},
		{"ALPHA", "alpha"},
		{"Team 42!", "team-42"},
		{"  spaces  ", "spaces"},
		{"", "team"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, slugifyTeamName(c.in), "input: %q", c.in)
	}
}
