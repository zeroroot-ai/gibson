package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// mockAlertStore
// ---------------------------------------------------------------------------

type mockAlertStore struct {
	alerts       []*storedAlert
	listErr      error
	markReadErr  error
	markAllErr   error
	markAllCount int32
}

func (m *mockAlertStore) ListAlerts(_ context.Context, _, _ string, unreadOnly bool, _ int) ([]*storedAlert, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if !unreadOnly {
		return m.alerts, nil
	}
	var unread []*storedAlert
	for _, a := range m.alerts {
		if !a.Read {
			unread = append(unread, a)
		}
	}
	return unread, nil
}

func (m *mockAlertStore) MarkAlertRead(_ context.Context, _, _ string) error {
	return m.markReadErr
}

func (m *mockAlertStore) MarkAllAlertsRead(_ context.Context, _, _ string) (int32, error) {
	if m.markAllErr != nil {
		return 0, m.markAllErr
	}
	return m.markAllCount, nil
}

// ---------------------------------------------------------------------------
// ListAlerts tests
// ---------------------------------------------------------------------------

func TestListAlerts_EmptyTenantIDFallsBackToSystemTenant_NilStoreReturnsEmpty(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil alertStore, the handler returns an empty list successfully.
	srv := blankServer()
	resp, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{TenantId: "", UserId: "u1"})
	assert.NoError(t, err)
	assert.Empty(t, resp.Alerts)
}

func TestListAlerts_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{TenantId: "acme", UserId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListAlerts_NilStore_ReturnsEmpty(t *testing.T) {
	// Nil alertStore → returns empty list, not error.
	srv := blankServer()
	resp, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	assert.Empty(t, resp.Alerts)
}

func TestListAlerts_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{listErr: assert.AnError}
	_, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{TenantId: "acme", UserId: "u1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestListAlerts_Success_ReturnsMappedAlerts(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{
		alerts: []*storedAlert{
			{ID: "a1", TenantID: "acme", UserID: "u1", Title: "Test", Severity: "high", Read: false},
		},
	}
	resp, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	require.Len(t, resp.Alerts, 1)
	assert.Equal(t, "a1", resp.Alerts[0].Id)
	assert.Equal(t, "high", resp.Alerts[0].Severity)
}

func TestListAlerts_UnreadOnly_FiltersReadAlerts(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{
		alerts: []*storedAlert{
			{ID: "a1", Read: false},
			{ID: "a2", Read: true},
		},
	}
	resp, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{
		TenantId:   "acme",
		UserId:     "u1",
		UnreadOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, resp.Alerts, 1)
	assert.Equal(t, "a1", resp.Alerts[0].Id)
}

// ---------------------------------------------------------------------------
// MarkAlertRead tests
// ---------------------------------------------------------------------------

func TestMarkAlertRead_EmptyTenantIDFallsBackToSystemTenant_NilStoreNoError(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil alertStore, the handler is a no-op (returns success).
	srv := blankServer()
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{TenantId: "", AlertId: "a1"})
	assert.NoError(t, err)
}

func TestMarkAlertRead_MissingAlertID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{TenantId: "acme", AlertId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestMarkAlertRead_NilStore_NoError(t *testing.T) {
	// Nil alertStore → success (no-op).
	srv := blankServer()
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{TenantId: "acme", AlertId: "a1"})
	assert.NoError(t, err)
}

func TestMarkAlertRead_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markReadErr: assert.AnError}
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{TenantId: "acme", AlertId: "a1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestMarkAlertRead_Success(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{}
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{TenantId: "acme", AlertId: "a1"})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// MarkAllAlertsRead tests
// ---------------------------------------------------------------------------

func TestMarkAllAlertsRead_EmptyTenantIDFallsBackToSystemTenant_NilStoreReturnsZero(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil alertStore, the handler returns count=0 successfully.
	srv := blankServer()
	resp, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{TenantId: "", UserId: "u1"})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestMarkAllAlertsRead_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{TenantId: "acme", UserId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestMarkAllAlertsRead_NilStore_ReturnsZero(t *testing.T) {
	// Nil alertStore → success with count=0.
	srv := blankServer()
	resp, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestMarkAllAlertsRead_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markAllErr: assert.AnError}
	_, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{TenantId: "acme", UserId: "u1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestMarkAllAlertsRead_Success_ReturnsCount(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markAllCount: 7}
	resp, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{TenantId: "acme", UserId: "u1"})
	require.NoError(t, err)
	assert.Equal(t, int32(7), resp.Count)
}
