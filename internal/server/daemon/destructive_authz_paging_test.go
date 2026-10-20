// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	destructiveauthzv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/destructiveauthz/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// testPageKeys returns a key source with a fixed KEK, for the paging tests.
func testPageKeys(t *testing.T) *pagetoken.Keys {
	t.Helper()
	keys, err := pagetoken.NewKeys(bytes.Repeat([]byte{5}, 32))
	require.NoError(t, err)
	return keys
}

func requestAction(t *testing.T, reg *brain.Registry, tenant, id string) {
	t.Helper()
	q := reg.For(tenant).DestructiveAuthorizationQueue()
	_, err := q.Request(tenant, brain.DestructiveAuthorizationRequest{HypothesisID: id})
	require.NoError(t, err)
}

// A walk with new actions between the pages gives each first action once.
func TestListPendingDestructiveActions_WalkWithRequestsBetweenPages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewDestructiveAuthorizationServer(reg, nil, testPageKeys(t))
	first := []string{"h1", "h3", "h5", "h7", "h9"}
	for _, id := range first {
		requestAction(t, reg, "acme", id)
	}
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitPending(tctx, t, srv, len(first))

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "the token must reach the last page")
		resp, err := srv.ListPendingDestructiveActions(tctx, &destructiveauthzv1.ListPendingDestructiveActionsRequest{PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, a := range resp.GetActions() {
			seen[a.GetActionId()]++
		}
		// One action sorts before the cursor, and one after it.
		requestAction(t, reg, "acme", "h0"+string(rune('a'+pages)))
		requestAction(t, reg, "acme", "hz"+string(rune('a'+pages)))
		awaitPending(tctx, t, srv, len(first)+2*(pages+1))
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	for _, id := range first {
		assert.Equal(t, 1, seen[id], "action %s", id)
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "action %s", id)
	}
}

func TestListPendingDestructiveActions_RefusesAForgedAndACrossTenantToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewDestructiveAuthorizationServer(reg, nil, testPageKeys(t))
	for _, id := range []string{"h1", "h2", "h3"} {
		requestAction(t, reg, "acme", id)
	}
	acme := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitPending(acme, t, srv, 3)
	page, err := srv.ListPendingDestructiveActions(acme, &destructiveauthzv1.ListPendingDestructiveActionsRequest{PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())

	globex := auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))
	for _, tc := range []struct {
		ctx   context.Context
		token string
	}{{globex, page.GetNextPageToken()}, {acme, "forged.token"}} {
		_, err = srv.ListPendingDestructiveActions(tc.ctx, &destructiveauthzv1.ListPendingDestructiveActionsRequest{PageToken: tc.token})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
	}
}

func TestListPendingDestructiveActions_WithoutKeysTheListFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewDestructiveAuthorizationServer(brain.NewRegistry(ctx, braintest.StoreFactory()), nil, nil)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := srv.ListPendingDestructiveActions(tctx, &destructiveauthzv1.ListPendingDestructiveActionsRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
}
