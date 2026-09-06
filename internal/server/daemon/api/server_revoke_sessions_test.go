// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func revokeServer(az authzIface, idpC *fakeIDPClient) *DaemonServer {
	return &DaemonServer{logger: slog.Default(), authorizer: az, idpAdminClient: idpC}
}

func TestRevokeUserSessions_Self(t *testing.T) {
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 2, GrantsRevoked: 2}}
	// No authorizer needed for self; ensure it is not consulted by passing nil.
	srv := revokeServer(nil, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "alice")

	resp, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "alice"})
	if err != nil {
		t.Fatalf("self revoke: %v", err)
	}
	if resp.GetSessionsTerminated() != 2 || resp.GetGrantsRevoked() != 2 {
		t.Fatalf("unexpected counts: %+v", resp)
	}
	if len(idpC.revokedUsers) != 1 || idpC.revokedUsers[0] != "alice" {
		t.Fatalf("expected idp revoke for alice, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_TenantAdminOverMember(t *testing.T) {
	az := newFakeAuthorizer().
		allow("user:admin1", "admin", "tenant:acme").
		allow("user:bob", "member", "tenant:acme")
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 1, GrantsRevoked: 1}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("tenant admin revoke: %v", err)
	}
	if len(idpC.revokedUsers) != 1 {
		t.Fatalf("expected idp revoke, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_TeamAdminOverTeamMember(t *testing.T) {
	az := newFakeAuthorizer().
		withObjects("user:lead", "admin", "team", "team:red").
		allow("user:carol", "member", "team:red")
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 1, GrantsRevoked: 1}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "lead")

	if _, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "carol"}); err != nil {
		t.Fatalf("team admin revoke: %v", err)
	}
	if len(idpC.revokedUsers) != 1 {
		t.Fatalf("expected idp revoke, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_UnrelatedPeerDenied(t *testing.T) {
	// caller is neither tenant admin nor a team admin over the target.
	az := newFakeAuthorizer()
	idpC := &fakeIDPClient{}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "mallory")

	_, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "victim"})
	if status_grpc.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if len(idpC.revokedUsers) != 0 {
		t.Fatalf("idp must NOT be called when denied, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_MissingTarget(t *testing.T) {
	srv := revokeServer(newFakeAuthorizer(), &fakeIDPClient{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "alice")
	_, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// gibson#627 Slice 2: FGA active_session stamp tests
// ---------------------------------------------------------------------------

// conditionalFakeAuthorizer extends fakeAuthorizer to also implement
// authz.ConditionalWriter so RevokeUserSessions can type-assert and stamp
// the active_session tuple. Tests that only care about the existing
// authzIface methods continue to use fakeAuthorizer (which does NOT
// implement ConditionalWriter — verifying the type assertion is optional).
type conditionalFakeAuthorizer struct {
	*fakeAuthorizer
	mu                sync.Mutex
	conditionalWrites []authz.ConditionalTuple
}

func newConditionalFakeAuthorizer() *conditionalFakeAuthorizer {
	return &conditionalFakeAuthorizer{fakeAuthorizer: newFakeAuthorizer()}
}

func (c *conditionalFakeAuthorizer) WriteConditional(_ context.Context, t authz.ConditionalTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conditionalWrites = append(c.conditionalWrites, t)
	return nil
}

func (c *conditionalFakeAuthorizer) UpdateConditionalTuple(_ context.Context, t authz.ConditionalTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conditionalWrites = append(c.conditionalWrites, t)
	return nil
}

func (c *conditionalFakeAuthorizer) written() []authz.ConditionalTuple {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]authz.ConditionalTuple, len(c.conditionalWrites))
	copy(out, c.conditionalWrites)
	return out
}

// TestRevokeUserSessions_StampsActivSessionFGATuple verifies that after a
// successful IdP revoke, RevokeUserSessions type-asserts the authorizer to
// authz.ConditionalWriter and calls UpdateConditionalTuple with:
//   - user = "user:<targetUserID>"
//   - relation = "active_session"
//   - object = "tenant:<tenantSlug>"
//   - condition = "token_not_revoked" with revoked_at ≈ now
//
// The test uses a conditionalFakeAuthorizer that satisfies both authzIface
// and authz.ConditionalWriter. The existing fakeAuthorizer (used by all other
// tests) does NOT implement ConditionalWriter, so those tests implicitly verify
// that the type assertion fails gracefully (block is skipped) — no panic.
func TestRevokeUserSessions_StampsActivSessionFGATuple(t *testing.T) {
	az := newConditionalFakeAuthorizer()
	az.fakeAuthorizer.
		allow("user:admin1", "admin", "tenant:acme").
		allow("user:bob", "member", "tenant:acme")

	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{
		SessionsTerminated: 1, GrantsRevoked: 1,
	}}

	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	// RFC 3339 truncates to second precision; truncate bounds to match.
	before := time.Now().UTC().Truncate(time.Second)
	if _, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{
		TargetUserId: "bob",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after := time.Now().UTC().Add(time.Second).Truncate(time.Second)

	// gibson#1244: RevokeUserSessions now stamps BOTH the user-scoped tuple
	// (user:bob, active_session, user:bob) — which gates tenant-less requests —
	// AND the per-tenant tuple (user:bob, active_session, tenant:acme).
	written := az.written()
	if len(written) != 2 {
		t.Fatalf("expected 2 conditional writes (user-scoped + per-tenant), got %d: %v", len(written), written)
	}
	byObject := map[string]authz.ConditionalTuple{}
	for _, w := range written {
		byObject[w.Object] = w
	}

	// The user-scoped stamp is the one that closes gibson#1244 — a tenant-less
	// request has only this object to check.
	userTuple, ok := byObject["user:bob"]
	if !ok {
		t.Fatalf("expected a user-scoped stamp on object user:bob, got objects %v", objectsOf(written))
	}
	if userTuple.User != "user:bob" {
		t.Errorf("user-scoped User = %q, want user:bob", userTuple.User)
	}
	if userTuple.Relation != "active_session" {
		t.Errorf("user-scoped Relation = %q, want active_session", userTuple.Relation)
	}

	got, ok := byObject["tenant:acme"]
	if !ok {
		t.Fatalf("expected a per-tenant stamp on object tenant:acme, got objects %v", objectsOf(written))
	}
	if got.User != "user:bob" {
		t.Errorf("User = %q, want user:bob", got.User)
	}
	if got.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", got.Relation)
	}
	if got.Object != "tenant:acme" {
		t.Errorf("Object = %q, want tenant:acme", got.Object)
	}
	// Both stamps must carry a non-epoch revoked_at within the call window.
	assertRevokedAtInWindow(t, userTuple, before, after)
	if got.ConditionName != authz.ConditionTokenNotRevoked {
		t.Errorf("ConditionName = %q, want %q", got.ConditionName, authz.ConditionTokenNotRevoked)
	}
	rawAt, ok := got.ConditionContext[authz.ConditionParamRevokedAt]
	if !ok {
		t.Fatal("ConditionContext missing revoked_at key")
	}
	revokedAt, ok := rawAt.(string)
	if !ok {
		t.Fatalf("revoked_at is %T, want string", rawAt)
	}
	// revoked_at must NOT be the epoch (would mean "never revoked").
	if revokedAt == authz.EpochRevokedAt {
		t.Errorf("revoked_at must not be epoch %q — should be current time", authz.EpochRevokedAt)
	}
	// revoked_at must parse as RFC 3339 and fall within the call window.
	// RFC 3339 truncates to second precision — bounds are expanded to [before, after] (both second-aligned).
	ts, err := time.Parse(time.RFC3339, revokedAt)
	if err != nil {
		t.Fatalf("revoked_at %q is not RFC 3339: %v", revokedAt, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("revoked_at %q is outside [%s, %s]", revokedAt, before, after)
	}
}

// TestRevokeUserSessions_FGAStampSkippedWhenNonConditionalAuthorizer
// verifies that RevokeUserSessions does NOT panic or error when the authorizer
// does NOT implement authz.ConditionalWriter (the plain fakeAuthorizer case).
// This tests the type-assertion guard:
//
//	if cw, ok := s.authorizer.(authz.ConditionalWriter); ok { ... }
func TestRevokeUserSessions_FGAStampSkippedWhenNonConditionalAuthorizer(t *testing.T) {
	// fakeAuthorizer does NOT implement ConditionalWriter — type assertion returns nil, false.
	az := newFakeAuthorizer().
		allow("user:admin1", "admin", "tenant:acme").
		allow("user:bob", "member", "tenant:acme")

	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{
		SessionsTerminated: 1, GrantsRevoked: 1,
	}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	// Must succeed without panic — no FGA stamp occurs, but IdP revoke did.
	resp, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{
		TargetUserId: "bob",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.GetSessionsTerminated() != 1 {
		t.Fatalf("expected 1 session terminated, got %d", resp.GetSessionsTerminated())
	}
}

// TestRevokeUserSessions_FGAStampError_NonFatal verifies that when
// UpdateConditionalTuple returns an error, RevokeUserSessions still
// returns success (the IdP revoke already occurred, FGA is best-effort).
func TestRevokeUserSessions_FGAStampError_NonFatal(t *testing.T) {
	az := &conditionalFakeAuthorizerWithError{
		conditionalFakeAuthorizer: newConditionalFakeAuthorizer(),
		updateErr:                 errors.New("FGA unreachable"),
	}
	az.fakeAuthorizer.
		allow("user:admin1", "admin", "tenant:acme").
		allow("user:bob", "member", "tenant:acme")

	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{
		SessionsTerminated: 1, GrantsRevoked: 1,
	}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	// Must succeed even though FGA stamp failed.
	resp, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{
		TargetUserId: "bob",
	})
	if err != nil {
		t.Fatalf("expected nil error when FGA stamp fails (non-fatal), got: %v", err)
	}
	if resp.GetSessionsTerminated() != 1 {
		t.Errorf("SessionsTerminated = %d, want 1", resp.GetSessionsTerminated())
	}
}

// conditionalFakeAuthorizerWithError is a conditionalFakeAuthorizer variant
// whose UpdateConditionalTuple method returns a fixed error.
type conditionalFakeAuthorizerWithError struct {
	*conditionalFakeAuthorizer
	updateErr error
}

func (c *conditionalFakeAuthorizerWithError) UpdateConditionalTuple(ctx context.Context, t authz.ConditionalTuple) error {
	// Record the attempt but return the configured error.
	_, _ = ctx, t
	return c.updateErr
}

// objectsOf returns the Object field of each conditional tuple, for assertion
// messages that need to show which objects were stamped.
func objectsOf(tuples []authz.ConditionalTuple) []string {
	out := make([]string, len(tuples))
	for i, t := range tuples {
		out[i] = t.Object
	}
	return out
}

// assertRevokedAtInWindow asserts the tuple's revoked_at is a non-epoch RFC 3339
// timestamp inside [before, after]. RFC 3339 truncates to second precision, so
// callers should pass second-aligned bounds.
func assertRevokedAtInWindow(t *testing.T, tuple authz.ConditionalTuple, before, after time.Time) {
	t.Helper()
	rawAt, ok := tuple.ConditionContext[authz.ConditionParamRevokedAt]
	if !ok {
		t.Fatalf("tuple on %q: ConditionContext missing revoked_at key", tuple.Object)
	}
	revokedAt, ok := rawAt.(string)
	if !ok {
		t.Fatalf("tuple on %q: revoked_at is %T, want string", tuple.Object, rawAt)
	}
	if revokedAt == authz.EpochRevokedAt {
		t.Errorf("tuple on %q: revoked_at must not be epoch %q — should be current time", tuple.Object, authz.EpochRevokedAt)
	}
	ts, err := time.Parse(time.RFC3339, revokedAt)
	if err != nil {
		t.Fatalf("tuple on %q: revoked_at %q is not RFC 3339: %v", tuple.Object, revokedAt, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("tuple on %q: revoked_at %q is outside [%s, %s]", tuple.Object, revokedAt, before, after)
	}
}
