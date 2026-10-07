// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// The five list requests of gibson#995 page with page_size and page_token
// (ADR-0028, rule 3). Each test walks every page and checks that it sees each
// item once and that the last page has no next token.

func paginationRedis(t *testing.T) goredis.UniversalClient {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestListAlerts_PagesWithATokenAndKeepsTheUnreadFilter(t *testing.T) {
	client := paginationRedis(t)
	ctx := context.Background()
	// Seven alerts, newest last. Alerts 1, 3 and 5 are read.
	for i := range 7 {
		a := storedAlert{ID: fmt.Sprintf("a%d", i), TenantID: "acme", UserID: "u1", Read: i%2 == 1, CreatedAtUnix: int64(i)}
		raw, err := json.Marshal(a)
		require.NoError(t, err)
		require.NoError(t, client.Set(ctx, alertDataKey("acme", a.ID), raw, 0).Err())
		require.NoError(t, client.ZAdd(ctx, alertIndexKey("acme", "u1"), goredis.Z{Score: float64(i), Member: a.ID}).Err())
	}
	srv := &DaemonServer{logger: slog.Default(), alertStore: &redisAlertStore{client: client, logger: slog.Default()}}
	callCtx := tenantAndSubjectCtx("acme", "u1")

	var seen []string
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "the token must reach the last page")
		resp, err := srv.ListAlerts(callCtx, &tenantv1.ListAlertsRequest{UnreadOnly: true, PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, a := range resp.GetAlerts() {
			seen = append(seen, a.GetId())
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	assert.Equal(t, []string{"a6", "a4", "a2", "a0"}, seen, "each unread alert once, newest first")

	_, err := srv.ListAlerts(callCtx, &tenantv1.ListAlertsRequest{PageToken: "bad"})
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
}

func TestListConversations_PagesWithAToken(t *testing.T) {
	client := paginationRedis(t)
	store := NewRedisConversationStore(client, slog.Default())
	ctx := context.Background()
	for i := range 5 {
		require.NoError(t, store.Save(ctx, "acme", "u1", fmt.Sprintf("c%d", i), "title", "", nil))
	}
	srv := &DaemonServer{logger: slog.Default(), conversationStore: store}
	callCtx := tenantAndSubjectCtx("acme", "u1")

	seen := map[string]bool{}
	sizes := []int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "the token must reach the last page")
		resp, err := srv.ListConversations(callCtx, &tenantv1.ListConversationsRequest{PageSize: 2, PageToken: token})
		require.NoError(t, err)
		sizes = append(sizes, len(resp.GetConversations()))
		for _, c := range resp.GetConversations() {
			assert.False(t, seen[c.GetId()], "conversation %s on two pages", c.GetId())
			seen[c.GetId()] = true
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	assert.Equal(t, []int{2, 2, 1}, sizes)
	assert.Len(t, seen, 5)

	_, err := srv.ListConversations(callCtx, &tenantv1.ListConversationsRequest{PageToken: "bad"})
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
}

func TestAdminListPendingRegistrations_PagesWithAToken(t *testing.T) {
	store := newMemStore()
	for i := range 3 {
		id := fmt.Sprintf("reg-%d", i)
		store.rows[id] = &memRow{
			SignupVerification: SignupVerification{ID: id, Email: id + "@example.com"},
			status:             signupStatusPendingApproval,
		}
	}
	srv := &DaemonServer{logger: slog.Default(), signupVerifications: store}

	first, err := srv.AdminListPendingRegistrations(adminCtx("admin-1"), &tenantv1.AdminListPendingRegistrationsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetRegistrations(), 2)
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetRegistrations(), 1)
	assert.Equal(t, "reg-2", second.GetRegistrations()[0].GetRegistrationId())
	assert.Empty(t, second.GetNextPageToken())

	_, err = srv.AdminListPendingRegistrations(adminCtx("admin-1"), &tenantv1.AdminListPendingRegistrationsRequest{PageToken: "bad"})
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
}

// cursorLoki records the cursor and page size it receives and answers with a
// fixed next cursor.
type cursorLoki struct {
	got  audit.AuditFilter
	next string
}

func (c *cursorLoki) QueryAuditEvents(_ context.Context, f audit.AuditFilter) ([]audit.AuditEntry, string, error) {
	c.got = f
	return nil, c.next, nil
}

func TestListAuditEvents_PageTokenIsTheCursor(t *testing.T) {
	loki := &cursorLoki{next: "1791229382900091716"}
	srv := &DaemonServer{
		logger:      slog.Default(),
		authorizer:  newFakeAuthorizer().allow("user:admin1", "admin", "tenant:acme"),
		lokiQuerier: loki,
	}
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	resp, err := srv.ListAuditEvents(ctx, &tenantv1.ListAuditEventsRequest{PageSize: 20, PageToken: "1791229382900000000"})
	require.NoError(t, err)
	assert.Equal(t, "1791229382900000000", loki.got.Cursor)
	assert.Equal(t, 20, loki.got.Limit)
	assert.Equal(t, "1791229382900091716", resp.GetNextPageToken())

	_, err = srv.ListAuditEvents(ctx, &tenantv1.ListAuditEventsRequest{PageSize: 5000})
	require.NoError(t, err)
	assert.Equal(t, 500, loki.got.Limit, "the page size is capped at 500")
}
