// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// Tests for the four mission-draft handlers in mission_draft.go.
// Spec: mission-draft-dashboard-wiring.

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/missiondraft"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// draftTestSubject is the caller identity used by every mission-draft test
// below that exercises the happy path. requireTenantAdmin now fails closed
// with no authorizer wired (see server_audit.go), so — unlike before — these
// tests must wire a real (fake) authorizer and an identity-bearing context
// rather than relying on the nil-authorizer bypass.
const draftTestSubject = "draft-admin"

// newDraftTestServer wires a mission-draft store plus a fakeAuthorizer that
// grants draftTestSubject the tenant admin relation on both "tenant-a" and
// "tenant-b" — the two tenants exercised across this file's tests — so
// requireTenantAdmin's FGA Check passes for the happy-path assertions below.
func newDraftTestServer(t *testing.T) *DaemonServer {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &DaemonServer{logger: logger}
	srv.WithMissionDraftStore(missiondraft.New(client, logger))
	srv.WithAuthorizer(newFakeAuthorizer().
		allow("user:"+draftTestSubject, "admin", "tenant:tenant-a").
		allow("user:"+draftTestSubject, "admin", "tenant:tenant-b"))
	return srv
}

// draftCtx returns a context carrying draftTestSubject as the caller
// identity, satisfying requireTenantAdmin's auth.IdentityFromContext lookup.
// The tenant scope for these RPCs comes from the request body (or
// auth.TenantStringFromContext as a fallback), not from this context, so no
// tenant needs to be set here.
func draftCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: draftTestSubject})
}

func draftCode(t *testing.T, err error) codes.Code {
	t.Helper()
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}

// TestMissionDraft_SaveListGetDelete exercises the create→list→get→delete
// lifecycle in a single tenant, asserting each handler returns real data
// and that delete actually removes the draft.
func TestMissionDraft_SaveListGetDelete(t *testing.T) {
	srv := newDraftTestServer(t)
	ctx := draftCtx()

	const tenant = "tenant-a"

	// Save: new draft (empty draft_id).
	saveResp, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		TenantId: tenant, Name: "first", CueSource: "name: test\n",
	})
	require.NoError(t, err, "SaveMissionDraft must succeed when store is wired")
	require.NotEmpty(t, saveResp.GetDraftId())
	draftID := saveResp.GetDraftId()

	// Save: overwrite (same draft_id) — must reuse the same id.
	saveResp2, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		TenantId: tenant, Name: "first-edit", CueSource: "name: test\nedited: true\n",
		DraftId: draftID,
	})
	require.NoError(t, err)
	require.Equal(t, draftID, saveResp2.GetDraftId(), "overwrite must reuse the existing draft_id")

	// List: must include exactly the one draft we saved, with the latest name.
	listResp, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: tenant})
	require.NoError(t, err)
	require.Len(t, listResp.GetDrafts(), 1)
	assert.Equal(t, draftID, listResp.Drafts[0].GetId())
	assert.Equal(t, "first-edit", listResp.Drafts[0].GetName())
	// List responses deliberately omit YAML (proto MissionDraft has no yaml field).

	// Get: must return the full draft including YAML.
	getResp, err := srv.GetMissionDraft(ctx, &tenantv1.GetMissionDraftRequest{
		TenantId: tenant, DraftId: draftID,
	})
	require.NoError(t, err)
	require.NotNil(t, getResp.GetDraft())
	assert.Equal(t, draftID, getResp.Draft.GetId())
	assert.Equal(t, "first-edit", getResp.Draft.GetName())
	assert.Equal(t, "name: test\nedited: true\n", getResp.Draft.GetCueSource())

	// Delete: must succeed.
	_, err = srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{
		TenantId: tenant, DraftId: draftID,
	})
	require.NoError(t, err)

	// List: must now be empty.
	listAfter, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: tenant})
	require.NoError(t, err)
	assert.Empty(t, listAfter.GetDrafts())
}

// TestMissionDraft_GetMissing returns codes.NotFound for a draft that was
// never saved.
func TestMissionDraft_GetMissing(t *testing.T) {
	srv := newDraftTestServer(t)
	_, err := srv.GetMissionDraft(draftCtx(), &tenantv1.GetMissionDraftRequest{
		TenantId: "tenant-a", DraftId: "does-not-exist",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, draftCode(t, err))
}

// TestMissionDraft_DeleteIdempotent verifies that deleting a non-existent
// draft returns OK (not NotFound) — required by the spec acceptance criteria
// because the dashboard's "Delete" button must not show an error if the
// draft already expired between list and delete.
func TestMissionDraft_DeleteIdempotent(t *testing.T) {
	srv := newDraftTestServer(t)
	ctx := draftCtx()

	_, err := srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{
		TenantId: "tenant-a", DraftId: "never-existed",
	})
	require.NoError(t, err, "DeleteMissionDraft must be idempotent on a missing draft")

	// And once more, after-the-fact, asserting no state was created.
	_, err = srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{
		TenantId: "tenant-a", DraftId: "never-existed",
	})
	require.NoError(t, err)
}

// TestMissionDraft_TenantIsolation asserts a draft saved under tenant A
// is invisible to a Get/List from tenant B. This is the security-critical
// invariant: the store keys on tenantID, and the handlers must not allow
// any cross-tenant read.
func TestMissionDraft_TenantIsolation(t *testing.T) {
	srv := newDraftTestServer(t)
	ctx := draftCtx()

	// Save under tenant-a.
	saveResp, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		TenantId: "tenant-a", Name: "secret", CueSource: "name: a\n",
	})
	require.NoError(t, err)
	draftID := saveResp.GetDraftId()

	// Get from tenant-b — must be NotFound.
	_, err = srv.GetMissionDraft(ctx, &tenantv1.GetMissionDraftRequest{
		TenantId: "tenant-b", DraftId: draftID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, draftCode(t, err),
		"draft saved under tenant-a must NOT be visible to tenant-b")

	// List from tenant-b — must be empty.
	listResp, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-b"})
	require.NoError(t, err)
	assert.Empty(t, listResp.GetDrafts(),
		"tenant-b's draft list must be empty even when tenant-a has drafts")

	// Delete from tenant-b targeting tenant-a's draft — Delete is idempotent
	// and tenant-scoped: returns OK but does NOT remove tenant-a's draft.
	_, err = srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{
		TenantId: "tenant-b", DraftId: draftID,
	})
	require.NoError(t, err)

	// Confirm tenant-a's draft is still present.
	getResp, err := srv.GetMissionDraft(ctx, &tenantv1.GetMissionDraftRequest{
		TenantId: "tenant-a", DraftId: draftID,
	})
	require.NoError(t, err, "tenant-a's draft must still exist after tenant-b's cross-tenant delete attempt")
	assert.Equal(t, draftID, getResp.Draft.GetId())
}

// TestMissionDraft_StoreNotConfigured returns codes.Unavailable when the
// missionDraftStore is nil (chart misconfiguration / startup-order bug).
func TestMissionDraft_StoreNotConfigured(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &DaemonServer{logger: logger}
	// missionDraftStore intentionally nil.

	_, err := srv.SaveMissionDraft(context.Background(), &tenantv1.SaveMissionDraftRequest{
		TenantId: "tenant-a", Name: "x", CueSource: "x",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, draftCode(t, err))
}

// TestMissionDraft_RequiresTenantID returns codes.InvalidArgument when
// tenant_id is empty in both the request and the ctx.
func TestMissionDraft_RequiresTenantID(t *testing.T) {
	srv := newDraftTestServer(t)
	ctx := context.Background()

	_, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		Name: "x", CueSource: "x",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, draftCode(t, err))

	_, err = srv.GetMissionDraft(ctx, &tenantv1.GetMissionDraftRequest{DraftId: "abc"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, draftCode(t, err))

	_, err = srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{DraftId: "abc"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, draftCode(t, err))
}

// TestMissionDraft_NoAuthorizer_FailsClosed pins the requireTenantAdmin fix
// (server_audit.go): a DaemonServer with a mission-draft store wired but NO
// authorizer must refuse every mission-draft RPC with Unavailable, not allow
// through. Before the fix, a nil authorizer made requireTenantAdmin an
// unconditional pass, so these four RPCs' `gibsoncheck:allow
// tenant-from-request — guarded by requireTenantAdmin` suppressions were
// describing a guard that could silently do nothing.
func TestMissionDraft_NoAuthorizer_FailsClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv := &DaemonServer{logger: logger}
	srv.WithMissionDraftStore(missiondraft.New(client, logger))
	// authorizer intentionally left nil.

	ctx := draftCtx()

	_, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		TenantId: "tenant-a", Name: "x", CueSource: "x",
	})
	require.Error(t, err, "SaveMissionDraft must refuse when no authorizer is wired")
	assert.Equal(t, codes.Unavailable, draftCode(t, err))

	_, err = srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-a"})
	require.Error(t, err, "ListMissionDrafts must refuse when no authorizer is wired")
	assert.Equal(t, codes.Unavailable, draftCode(t, err))

	_, err = srv.GetMissionDraft(ctx, &tenantv1.GetMissionDraftRequest{TenantId: "tenant-a", DraftId: "d1"})
	require.Error(t, err, "GetMissionDraft must refuse when no authorizer is wired")
	assert.Equal(t, codes.Unavailable, draftCode(t, err))

	_, err = srv.DeleteMissionDraft(ctx, &tenantv1.DeleteMissionDraftRequest{TenantId: "tenant-a", DraftId: "d1"})
	require.Error(t, err, "DeleteMissionDraft must refuse when no authorizer is wired")
	assert.Equal(t, codes.Unavailable, draftCode(t, err))
}

// TestMissionDraft_NonAdminCaller_PermissionDenied proves the guard now does
// real work, not just "wired but never denies": a caller the authorizer does
// NOT recognize as tenant admin must be refused with PermissionDenied.
func TestMissionDraft_NonAdminCaller_PermissionDenied(t *testing.T) {
	srv := newDraftTestServer(t)
	// draftTestSubject is admin on tenant-a/tenant-b; this caller is not
	// granted admin on any tenant by the fakeAuthorizer wired in
	// newDraftTestServer.
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "not-an-admin"})

	_, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
		TenantId: "tenant-a", Name: "x", CueSource: "x",
	})
	require.Error(t, err, "SaveMissionDraft must refuse a caller who is not tenant admin")
	assert.Equal(t, codes.PermissionDenied, draftCode(t, err))
}
