// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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

func (m *mockAlertStore) MarkAlertRead(_ context.Context, _, _, _ string) error {
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

func TestListAlerts_NoTenantInContext_NilStoreReturnsEmpty(t *testing.T) {
	// No tenant on the context: auth.TenantStringFromContext returns "" (no
	// SystemTenant fallback — see sdk auth.TenantFromContext's doc comment).
	// With nil alertStore, the handler returns an empty list.
	srv := blankServer()
	resp, err := srv.ListAlerts(context.Background(), &tenantv1.ListAlertsRequest{})
	assert.NoError(t, err)
	assert.Empty(t, resp.Alerts)
}

func TestListAlerts_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListAlerts(tenantCtxNoSubject("acme"), &tenantv1.ListAlertsRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListAlerts_NilStore_ReturnsEmpty(t *testing.T) {
	// Nil alertStore → returns empty list, not error.
	srv := blankServer()
	resp, err := srv.ListAlerts(tenantAndSubjectCtx("acme", "u1"), &tenantv1.ListAlertsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Alerts)
}

func TestListAlerts_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{listErr: assert.AnError}
	_, err := srv.ListAlerts(tenantAndSubjectCtx("acme", "u1"), &tenantv1.ListAlertsRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestListAlerts_Success_ReturnsMappedAlerts(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{
		alerts: []*storedAlert{
			{ID: "a1", TenantID: "acme", UserID: "u1", Title: "Test", Severity: "high", Read: false},
		},
	}
	resp, err := srv.ListAlerts(tenantAndSubjectCtx("acme", "u1"), &tenantv1.ListAlertsRequest{})
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
	resp, err := srv.ListAlerts(tenantAndSubjectCtx("acme", "u1"), &tenantv1.ListAlertsRequest{
		UnreadOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, resp.Alerts, 1)
	assert.Equal(t, "a1", resp.Alerts[0].Id)
}

// ---------------------------------------------------------------------------
// MarkAlertRead tests
// ---------------------------------------------------------------------------

func TestMarkAlertRead_NoTenantInContext_NilStoreNoError(t *testing.T) {
	// No tenant on the context: auth.TenantStringFromContext returns "" (no
	// SystemTenant fallback — see sdk auth.TenantFromContext's doc comment).
	// With nil alertStore, the handler is a no-op.
	srv := blankServer()
	_, err := srv.MarkAlertRead(context.Background(), &tenantv1.MarkAlertReadRequest{AlertId: "a1"})
	assert.NoError(t, err)
}

func TestMarkAlertRead_MissingAlertID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.MarkAlertRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAlertReadRequest{AlertId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestMarkAlertRead_MissingUserID_InvalidArgument(t *testing.T) {
	// Tenant present but no caller identity: alerts are per-user, so the
	// subject must come from the authenticated context, never a body field.
	srv := blankServer()
	_, err := srv.MarkAlertRead(tenantCtxNoSubject("acme"), &tenantv1.MarkAlertReadRequest{AlertId: "a1"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestMarkAlertRead_NilStore_NoError(t *testing.T) {
	// Nil alertStore → success (no-op).
	srv := blankServer()
	_, err := srv.MarkAlertRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAlertReadRequest{AlertId: "a1"})
	assert.NoError(t, err)
}

func TestMarkAlertRead_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markReadErr: assert.AnError}
	_, err := srv.MarkAlertRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAlertReadRequest{AlertId: "a1"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestMarkAlertRead_Success(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{}
	_, err := srv.MarkAlertRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAlertReadRequest{AlertId: "a1"})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// MarkAllAlertsRead tests
// ---------------------------------------------------------------------------

func TestMarkAllAlertsRead_NoTenantInContext_NilStoreReturnsZero(t *testing.T) {
	// No tenant on the context: auth.TenantStringFromContext returns "" (no
	// SystemTenant fallback — see sdk auth.TenantFromContext's doc comment).
	// With nil alertStore, the handler returns count=0.
	srv := blankServer()
	resp, err := srv.MarkAllAlertsRead(context.Background(), &tenantv1.MarkAllAlertsReadRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestMarkAllAlertsRead_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.MarkAllAlertsRead(tenantCtxNoSubject("acme"), &tenantv1.MarkAllAlertsReadRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestMarkAllAlertsRead_NilStore_ReturnsZero(t *testing.T) {
	// Nil alertStore → success with count=0.
	srv := blankServer()
	resp, err := srv.MarkAllAlertsRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAllAlertsReadRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Count)
}

func TestMarkAllAlertsRead_StoreError_Internal(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markAllErr: assert.AnError}
	_, err := srv.MarkAllAlertsRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAllAlertsReadRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestMarkAllAlertsRead_Success_ReturnsCount(t *testing.T) {
	srv := blankServer()
	srv.alertStore = &mockAlertStore{markAllCount: 7}
	resp, err := srv.MarkAllAlertsRead(tenantAndSubjectCtx("acme", "u1"), &tenantv1.MarkAllAlertsReadRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(7), resp.Count)
}

// ---------------------------------------------------------------------------
// redisAlertStore — absent-owner-field regression test (miniredis)
//
// The alert path stores its ownership field inside a JSON blob rather than a
// Redis hash field, so it does not share the conversation store's
// HGet-returns-redis.Nil-for-two-different-things ambiguity: a JSON blob
// missing "user_id" unmarshals UserID to the Go zero value (""), and
// MarkAlertRead's `a.UserID != callerUserID` catches that unconditionally —
// there is no separate "field present but empty" branch to skip. This test
// pins that already-correct behaviour against a real Redis client, matching
// the coverage added for the conversation store's four paths (which did have
// the bug) so every one of the isolation checks in this class has a
// same-shape regression test, not just the ones that needed fixing.
// ---------------------------------------------------------------------------

func TestRedisAlertStore_MarkAlertRead_AbsentOwnerField_Denies(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := &redisAlertStore{client: client, logger: testSlogLogger}

	ctx := context.Background()
	key := alertDataKey("tenant-x", "alert-corrupt")
	// Alert JSON with no "user_id" key at all (as opposed to `"user_id":""`,
	// which would behave identically here but is less representative of the
	// real corruption shape — a pre-ownership-field record).
	require.NoError(t, client.Set(ctx, key, `{"id":"alert-corrupt","title":"orphaned"}`, 0).Err())

	err := store.MarkAlertRead(ctx, "tenant-x", "someone", "alert-corrupt")
	require.Error(t, err, "MarkAlertRead must refuse an alert with no recorded owner")

	raw, getErr := client.Get(ctx, key).Result()
	require.NoError(t, getErr)
	assert.Contains(t, raw, `"orphaned"`, "the alert must be untouched")
	assert.NotContains(t, raw, `"read":true`, "the alert must not have been marked read")
}
