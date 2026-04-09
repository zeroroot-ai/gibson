package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// ---------------------------------------------------------------------------
// mockQuotaStore
// ---------------------------------------------------------------------------

type mockQuotaStore struct {
	getErr  error
	setErr  error
	stored  *storedQuota
}

func (m *mockQuotaStore) GetQuota(_ context.Context, _ string) (*storedQuota, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.stored != nil {
		return m.stored, nil
	}
	return &storedQuota{}, nil
}

func (m *mockQuotaStore) SetQuota(_ context.Context, _ string, q *storedQuota) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.stored = q
	return nil
}

// ---------------------------------------------------------------------------
// GetTenantQuota tests
// ---------------------------------------------------------------------------

func TestGetTenantQuota_EmptyTenantIDUsesContext_NilStore_Unavailable(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext which returns SystemTenant.
	// With nil quotaStore → Unavailable (not InvalidArgument).
	srv := blankServer()
	_, err := srv.GetTenantQuota(context.Background(), &GetTenantQuotaRequest{TenantId: ""})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestGetTenantQuota_NilStore_Unavailable(t *testing.T) {
	srv := blankServer()
	// authorizer is nil → requireTenantAdmin passes
	_, err := srv.GetTenantQuota(context.Background(), &GetTenantQuotaRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestGetTenantQuota_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.quotaStore = &mockQuotaStore{getErr: assert.AnError}
	_, err := srv.GetTenantQuota(context.Background(), &GetTenantQuotaRequest{TenantId: "acme"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestGetTenantQuota_ZeroValues_OK(t *testing.T) {
	srv := blankServer()
	srv.quotaStore = &mockQuotaStore{}
	resp, err := srv.GetTenantQuota(context.Background(), &GetTenantQuotaRequest{TenantId: "acme"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Quota)
	assert.Equal(t, int32(0), resp.Quota.MaxMissions)
	assert.Equal(t, int64(0), resp.Quota.MaxFindings)
}

func TestGetTenantQuota_ExistingQuota_ReturnedCorrectly(t *testing.T) {
	srv := blankServer()
	srv.quotaStore = &mockQuotaStore{
		stored: &storedQuota{
			MaxMissions: 10,
			MaxAgents:   5,
			MaxFindings: 1000,
			PlanTier:    "pro",
		},
	}
	resp, err := srv.GetTenantQuota(context.Background(), &GetTenantQuotaRequest{TenantId: "acme"})
	require.NoError(t, err)
	require.NotNil(t, resp.Quota)
	assert.Equal(t, int32(10), resp.Quota.MaxMissions)
	assert.Equal(t, int32(5), resp.Quota.MaxAgents)
	assert.Equal(t, int64(1000), resp.Quota.MaxFindings)
	assert.Equal(t, "pro", resp.Quota.PlanTier)
}

// ---------------------------------------------------------------------------
// SetTenantQuota tests
// ---------------------------------------------------------------------------

func TestSetTenantQuota_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SetTenantQuota(context.Background(), &SetTenantQuotaRequest{TenantId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSetTenantQuota_NilQuota_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SetTenantQuota(context.Background(), &SetTenantQuotaRequest{TenantId: "acme", Quota: nil})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSetTenantQuota_NilStore_Unavailable(t *testing.T) {
	srv := blankServer()
	_, err := srv.SetTenantQuota(context.Background(), &SetTenantQuotaRequest{
		TenantId: "acme",
		Quota:    &TenantQuota{MaxMissions: 5},
	})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestSetTenantQuota_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.quotaStore = &mockQuotaStore{setErr: assert.AnError}
	_, err := srv.SetTenantQuota(context.Background(), &SetTenantQuotaRequest{
		TenantId: "acme",
		Quota:    &TenantQuota{MaxMissions: 5},
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestSetTenantQuota_Success_ReturnsUpdatedQuota(t *testing.T) {
	srv := blankServer()
	store := &mockQuotaStore{}
	srv.quotaStore = store
	resp, err := srv.SetTenantQuota(context.Background(), &SetTenantQuotaRequest{
		TenantId: "acme",
		Quota: &TenantQuota{
			MaxMissions: 20,
			MaxAgents:   10,
			MaxFindings: 5000,
			PlanTier:    "enterprise",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Quota)
	assert.Equal(t, int32(20), resp.Quota.MaxMissions)
	assert.Equal(t, "enterprise", resp.Quota.PlanTier)
	// Verify persistence
	require.NotNil(t, store.stored)
	assert.Equal(t, int32(20), store.stored.MaxMissions)
}
