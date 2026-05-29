package target_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/target"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// fakeStore is an in-memory target.Store for isolated service tests. It mirrors
// the global store's UUID-keyed semantics without Redis or RediSearch.
type fakeStore struct {
	byID map[types.ID]*types.Target
}

func newFakeStore() *fakeStore { return &fakeStore{byID: map[types.ID]*types.Target{}} }

func (f *fakeStore) Create(_ context.Context, t *types.Target) error {
	cp := *t
	f.byID[t.ID] = &cp
	return nil
}

func (f *fakeStore) Get(_ context.Context, id types.ID) (*types.Target, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *t
	return &cp, nil
}

func (f *fakeStore) List(_ context.Context, _ *types.TargetFilter) ([]*types.Target, error) {
	out := make([]*types.Target, 0, len(f.byID))
	for _, t := range f.byID {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeStore) Update(_ context.Context, t *types.Target) error {
	cp := *t
	f.byID[t.ID] = &cp
	return nil
}

func (f *fakeStore) Delete(_ context.Context, id types.ID) error {
	delete(f.byID, id)
	return nil
}

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
)

func TestCreate_MintsUUIDStampsTenant(t *testing.T) {
	svc := target.NewService(newFakeStore())

	// A client-supplied id must be ignored — the service mints its own.
	in := &types.Target{ID: types.ID("client-supplied-not-a-uuid"), Name: "prod-web"}
	got, err := svc.Create(context.Background(), tenantA, in)
	require.NoError(t, err)

	assert.NotEqual(t, types.ID("client-supplied-not-a-uuid"), got.ID)
	assert.NoError(t, got.ID.Validate(), "minted id must be a valid UUID")
	assert.Equal(t, tenantA, got.TenantID)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())

	// Defaults are applied so the daemon's Target.Validate passes for a
	// metadata-only caller (no type/status supplied).
	assert.Equal(t, "custom", got.Type, "type defaults to custom")
	assert.Equal(t, types.TargetStatusActive, got.Status, "status defaults to active")

	// Retrievable by its minted UUID within the same tenant.
	fetched, err := svc.Get(context.Background(), tenantA, got.ID.String())
	require.NoError(t, err)
	assert.Equal(t, "prod-web", fetched.Name)
}

func TestCreate_RequiresTenant(t *testing.T) {
	svc := target.NewService(newFakeStore())
	_, err := svc.Create(context.Background(), "", &types.Target{Name: "x"})
	assert.ErrorIs(t, err, target.ErrTenantRequired)
}

func TestGet_NonUUIDIsInvalid(t *testing.T) {
	svc := target.NewService(newFakeStore())
	_, err := svc.Get(context.Background(), tenantA, "scanme.nmap.org")
	assert.ErrorIs(t, err, target.ErrInvalidID)
}

func TestGet_CrossTenantIsNotFound(t *testing.T) {
	svc := target.NewService(newFakeStore())
	created, err := svc.Create(context.Background(), tenantA, &types.Target{Name: "owned-by-a"})
	require.NoError(t, err)

	// Tenant B cannot see tenant A's target — even with the exact UUID.
	_, err = svc.Get(context.Background(), tenantB, created.ID.String())
	assert.ErrorIs(t, err, target.ErrNotFound)
}

func TestList_ScopesToTenantAndPaginates(t *testing.T) {
	svc := target.NewService(newFakeStore())
	ctx := context.Background()
	for _, n := range []string{"a1", "a2", "a3"} {
		_, err := svc.Create(ctx, tenantA, &types.Target{Name: n})
		require.NoError(t, err)
	}
	_, err := svc.Create(ctx, tenantB, &types.Target{Name: "b1"})
	require.NoError(t, err)

	all, err := svc.List(ctx, tenantA, nil)
	require.NoError(t, err)
	assert.Len(t, all, 3, "only tenant A's targets")
	for _, tg := range all {
		assert.Equal(t, tenantA, tg.TenantID)
	}

	// Pagination is applied after tenant scoping.
	page, err := svc.List(ctx, tenantA, &types.TargetFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page, 2)

	offset, err := svc.List(ctx, tenantA, &types.TargetFilter{Offset: 2})
	require.NoError(t, err)
	assert.Len(t, offset, 1)

	none, err := svc.List(ctx, tenantB, nil)
	require.NoError(t, err)
	assert.Len(t, none, 1)
}

func TestUpdate_PreservesIdentityAndOwnership(t *testing.T) {
	svc := target.NewService(newFakeStore())
	ctx := context.Background()
	created, err := svc.Create(ctx, tenantA, &types.Target{Name: "before"})
	require.NoError(t, err)
	origID, origCreated := created.ID, created.CreatedAt

	// Caller tries to rename and (maliciously) re-tenant + re-id; service ignores.
	updated, err := svc.Update(ctx, tenantA, &types.Target{
		ID:       origID,
		Name:     "after",
		TenantID: tenantB,
	})
	require.NoError(t, err)
	assert.Equal(t, "after", updated.Name)
	assert.Equal(t, origID, updated.ID, "UUID is immutable")
	assert.Equal(t, tenantA, updated.TenantID, "ownership cannot be reassigned")
	assert.Equal(t, origCreated, updated.CreatedAt, "creation time preserved")
}

func TestUpdate_CrossTenantIsNotFound(t *testing.T) {
	svc := target.NewService(newFakeStore())
	ctx := context.Background()
	created, err := svc.Create(ctx, tenantA, &types.Target{Name: "owned-by-a"})
	require.NoError(t, err)

	_, err = svc.Update(ctx, tenantB, &types.Target{ID: created.ID, Name: "hijack"})
	assert.ErrorIs(t, err, target.ErrNotFound)
}

func TestDelete_RemovesWithinTenant(t *testing.T) {
	svc := target.NewService(newFakeStore())
	ctx := context.Background()
	created, err := svc.Create(ctx, tenantA, &types.Target{Name: "doomed"})
	require.NoError(t, err)

	require.NoError(t, svc.Delete(ctx, tenantA, created.ID.String()))
	_, err = svc.Get(ctx, tenantA, created.ID.String())
	assert.ErrorIs(t, err, target.ErrNotFound)
}

func TestDelete_CrossTenantIsNotFound(t *testing.T) {
	svc := target.NewService(newFakeStore())
	ctx := context.Background()
	created, err := svc.Create(ctx, tenantA, &types.Target{Name: "owned-by-a"})
	require.NoError(t, err)

	err = svc.Delete(ctx, tenantB, created.ID.String())
	assert.ErrorIs(t, err, target.ErrNotFound)

	// Still present for the rightful owner.
	_, err = svc.Get(ctx, tenantA, created.ID.String())
	assert.NoError(t, err)
}
