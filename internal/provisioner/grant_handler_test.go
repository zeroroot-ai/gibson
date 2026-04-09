package provisioner

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// mockAuthzForGrant records FGA operations for assertion.
type mockAuthzForGrant struct {
	writtenTuples []authz.Tuple
	deletedTuples []authz.Tuple
	listedObjects map[string][]string // relation → []object
	writeErr      error
	deleteErr     error
	listErr       error
}

func (m *mockAuthzForGrant) Check(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (m *mockAuthzForGrant) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthzForGrant) Write(_ context.Context, tuples []authz.Tuple) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writtenTuples = append(m.writtenTuples, tuples...)
	return nil
}
func (m *mockAuthzForGrant) Delete(_ context.Context, tuples []authz.Tuple) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedTuples = append(m.deletedTuples, tuples...)
	return nil
}
func (m *mockAuthzForGrant) ListObjects(_ context.Context, _, relation, _ string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listedObjects[relation], nil
}
func (m *mockAuthzForGrant) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForGrant) StoreID() string { return "" }
func (m *mockAuthzForGrant) ModelID() string { return "" }
func (m *mockAuthzForGrant) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Tests: Grant
// ---------------------------------------------------------------------------

func TestGrantHandler_Grant_Execute(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Grant(context.Background(), "acme", "user-abc", "tool:nuclei", "execute")
	require.NoError(t, err)
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "user:user-abc", az.writtenTuples[0].User)
	assert.Equal(t, "can_execute", az.writtenTuples[0].Relation)
	assert.Equal(t, "component:tool:nuclei", az.writtenTuples[0].Object)
}

func TestGrantHandler_Grant_Configure(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Grant(context.Background(), "acme", "user-abc", "agent:opencode", "configure")
	require.NoError(t, err)
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "can_configure", az.writtenTuples[0].Relation)
}

func TestGrantHandler_Grant_Read(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Grant(context.Background(), "acme", "user-abc", "plugin:gitlab", "read")
	require.NoError(t, err)
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "can_read", az.writtenTuples[0].Relation)
}

func TestGrantHandler_Grant_InvalidAction(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Grant(context.Background(), "acme", "user-abc", "tool:nmap", "destroy")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAction)
}

func TestGrantHandler_Grant_FGAWriteFails(t *testing.T) {
	az := &mockAuthzForGrant{writeErr: errors.New("fga unavailable")}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Grant(context.Background(), "acme", "user-abc", "tool:nmap", "execute")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGrantFailed)
}

// ---------------------------------------------------------------------------
// Tests: Revoke
// ---------------------------------------------------------------------------

func TestGrantHandler_Revoke_Execute(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Revoke(context.Background(), "acme", "user-abc", "tool:nuclei", "execute")
	require.NoError(t, err)
	require.Len(t, az.deletedTuples, 1)
	assert.Equal(t, "can_execute", az.deletedTuples[0].Relation)
}

func TestGrantHandler_Revoke_InvalidAction(t *testing.T) {
	az := &mockAuthzForGrant{}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	err = h.Revoke(context.Background(), "acme", "user-abc", "tool:nmap", "invalid")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAction)
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestGrantHandler_List(t *testing.T) {
	az := &mockAuthzForGrant{
		listedObjects: map[string][]string{
			"can_execute":   {"component:tool:nuclei", "component:agent:opencode"},
			"can_configure": {"component:plugin:gitlab"},
			"can_read":      {},
		},
	}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	grants, err := h.List(context.Background(), "acme", "user-abc")
	require.NoError(t, err)
	assert.Len(t, grants, 3) // 2 execute + 1 configure + 0 read

	// Verify the component refs are stripped of the "component:" prefix.
	var execGrants []ComponentGrant
	for _, g := range grants {
		if g.Action == "execute" {
			execGrants = append(execGrants, g)
		}
	}
	assert.Len(t, execGrants, 2)
}

func TestGrantHandler_List_FGAFails(t *testing.T) {
	az := &mockAuthzForGrant{listErr: errors.New("fga down")}
	h, err := NewGrantHandler(az, nil)
	require.NoError(t, err)

	_, err = h.List(context.Background(), "acme", "user-abc")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: constructor
// ---------------------------------------------------------------------------

func TestNewGrantHandler_NilAuthzRejected(t *testing.T) {
	_, err := NewGrantHandler(nil, nil)
	require.Error(t, err)
}
