// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
)

// stubAuthorizer is a minimal authz.Authorizer for the write tests:
// BatchCheck reports tuples present iff `present[user|relation|object]==true`,
// and Write/Delete record the tuples in `wrote` / `deleted` for assertions.
//
// checkErrFor / batchCheckErr let a test inject a failure from a specific
// Check call (keyed by the same tupleKey used for `present`) or from every
// BatchCheck call, to exercise the fail-closed error-propagation branches
// that a purely present/absent stub can't reach.
type stubAuthorizer struct {
	present map[string]bool
	wrote   []authz.Tuple
	deleted []authz.Tuple

	// listUsersOfType, when non-nil, canned-answers both ListUsers and
	// ListUsersOfType, keyed on ALL of objectType, object, relation, AND the
	// subject type (userType). ListUsers hardcodes userType to "user"; a
	// caller that reaches ListUsers with the wrong subject type for a
	// relation (e.g. "parent" on team, which model.fga types [tenant], not
	// [user]) must see an EMPTY result here too, exactly like the real FGA
	// server does (it does not error on a type mismatch — see
	// internal/platform/authz/client_methods.go's ListUsers doc comment).
	//
	// A stub that ignored objectType/relation/userType (as this one used to,
	// keyed on object alone) would answer a squat-guard lookup correctly
	// even when the production code queried the wrong axis — which is
	// exactly how TestCreateTeam_RejectsSquattedTeamID passed against a
	// broken guard in an earlier round. Honouring all four keeps the test
	// wired to the real FGA contract.
	listUsersOfType map[string][]string

	// listUsersOfTypeErr, when non-nil, is returned by ListUsersOfType instead
	// of a canned answer — for pinning the fail-closed path when the FGA call
	// itself errors (as opposed to the authorizer not supporting the typed
	// method at all, covered by fakeAuthorizerCatalog).
	listUsersOfTypeErr error

	checkErrFor   map[string]error
	batchCheckErr error
}

func tupleKey(t authz.Tuple) string {
	return t.User + "|" + t.Relation + "|" + t.Object
}

// listUsersOfTypeKey builds the stubAuthorizer.listUsersOfType lookup key.
func listUsersOfTypeKey(objectType, object, relation, userType string) string {
	return objectType + "|" + object + "|" + relation + "|" + userType
}

// Check consults the same `present` map BatchCheck does, so tests can seed
// single-Check call sites (e.g. AddTeamMember's tenant-parent and
// tenant-membership checks) the same way they seed BatchCheck-based ones.
// A tupleKey present in checkErrFor makes this specific Check call fail
// instead, for tests that need to exercise a Check-error path without
// masking an earlier, unrelated Check call in the same handler.
func (s *stubAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	key := tupleKey(authz.Tuple{User: user, Relation: relation, Object: object})
	if err, ok := s.checkErrFor[key]; ok {
		return false, err
	}
	return s.present[key], nil
}
func (s *stubAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if s.batchCheckErr != nil {
		return nil, s.batchCheckErr
	}
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = s.present[tupleKey(authz.Tuple{User: c.User, Relation: c.Relation, Object: c.Object})]
	}
	return out, nil
}
func (s *stubAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	s.wrote = append(s.wrote, tuples...)
	return nil
}
func (s *stubAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	s.deleted = append(s.deleted, tuples...)
	return nil
}
func (s *stubAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}

// ListUsers mirrors the real fgaAuthorizer's hardcoded userType="user"
// filter — see the production doc comment for why a relation typed for a
// different subject returns an empty slice here, not an error.
func (s *stubAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	if s.listUsersOfType == nil {
		return nil, nil
	}
	return s.listUsersOfType[listUsersOfTypeKey(objectType, object, relation, "user")], nil
}

func (s *stubAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, userType string) ([]string, error) {
	if s.listUsersOfTypeErr != nil {
		return nil, s.listUsersOfTypeErr
	}
	if s.listUsersOfType == nil {
		return nil, nil
	}
	return s.listUsersOfType[listUsersOfTypeKey(objectType, object, relation, userType)], nil
}

func (s *stubAuthorizer) StoreID() string { return "test" }
func (s *stubAuthorizer) ModelID() string { return "test" }
func (s *stubAuthorizer) Close() error    { return nil }

type stubLookup struct {
	records map[string]identity.PrincipalRecord
}

func (s *stubLookup) Resolve(_ context.Context, principalID string) (identity.PrincipalRecord, error) {
	rec, ok := s.records[principalID]
	if !ok {
		return identity.PrincipalRecord{}, identity.ErrPrincipalNotFound
	}
	return rec, nil
}

// adminCallerSubject is the bare caller subject used by adminCtx, matching
// production Identity semantics: auth.Identity.Subject is the bare
// principal ID ext-authz forwards (e.g. a Zitadel sub), never pre-prefixed
// with "user:" — handler code adds that FGA-object-reference prefix itself
// (see e.g. GetMyPermissions, GrantComponentPermissions). WriteAgentGrants'
// caller-access intersection check (identity-assertion-gaps finding 4) is
// the first code path in this file to actually build an FGA ref from this
// test's identity, which is what surfaces the convention here.
const adminCallerSubject = "admin-1"

func adminCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: adminCallerSubject, Tenant: tid})
}

func newWriteServer(t *testing.T, az *stubAuthorizer, lookup *stubLookup) *GrantsAdminServer {
	t.Helper()
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader:     noopReader{},
		Authorizer: az,
		Lookup:     lookup,
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv
}

type noopReader struct{}

func (noopReader) ListActive(_ context.Context, _ auth.TenantID) ([]GrantInfo, error) {
	return nil, nil
}

func TestWriteAgentGrants_HappyPath(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{
		// Caller-access intersection (identity-assertion-gaps finding 4): the
		// caller must already hold each requested relation on the object
		// before it can be forwarded to the target agent principal.
		"user:" + adminCallerSubject + "|can_read|component:gitlab":      true,
		"user:" + adminCallerSubject + "|can_configure|component:gitlab": true,
	}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_configure"},
		},
	})
	if err != nil {
		t.Fatalf("WriteAgentGrants: %v", err)
	}
	if resp.GetWritten() != 2 || resp.GetAlreadyPresent() != 0 {
		t.Errorf("counts = (%d, %d), want (2, 0)", resp.GetWritten(), resp.GetAlreadyPresent())
	}
	if len(az.wrote) != 2 {
		t.Errorf("wrote %d tuples, want 2", len(az.wrote))
	}
}

func TestWriteAgentGrants_IdempotentAlreadyPresent(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{
		"agent_principal:abc|can_read|component:gitlab": true,
		// Caller-access intersection (identity-assertion-gaps finding 4).
		"user:" + adminCallerSubject + "|can_read|component:gitlab":    true,
		"user:" + adminCallerSubject + "|can_execute|component:gitlab": true,
	}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_execute"},
		},
	})
	if err != nil {
		t.Fatalf("WriteAgentGrants: %v", err)
	}
	if resp.GetWritten() != 1 || resp.GetAlreadyPresent() != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", resp.GetWritten(), resp.GetAlreadyPresent())
	}
}

func TestWriteAgentGrants_AgentCannotGetCanInvoke(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "plugin:gitlab", Relation: "can_invoke"},
		},
	})
	if err == nil {
		t.Fatal("expected InvalidArgument; got nil")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0 (validation should reject before write)", len(az.wrote))
	}
}

// TestWriteAgentGrants_CrossTenantIsIndistinguishableFromNonexistent is the
// regression for GHSA-9q4v-xwmv-gg26.
//
// A cross-tenant principal used to answer PermissionDenied while an unknown id
// answered NotFound. Both refuse the write, so the guard was never the problem
// — the DIFFERENCE was: it tells a caller which ids exist elsewhere in the
// install, one probe at a time, with no grant on any of them. The two replies
// must now be identical in code AND message.
func TestWriteAgentGrants_CrossTenantIsIndistinguishableFromNonexistent(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:other": {
			PrincipalID: "agent_principal:other",
			TenantID:    "OTHER-TENANT",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	call := func(target string) error {
		_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
			TargetPrincipalId: target,
			Grants: []*tenantv1.GrantTuple{
				{Object: "component:gitlab", Relation: "can_read"},
			},
		})
		return err
	}

	// Exists, but in another tenant.
	existing := call("agent_principal:other")
	// Does not exist anywhere.
	absent := call("agent_principal:no-such-principal-anywhere")

	if existing == nil || absent == nil {
		t.Fatalf("both writes must be refused; got (%v, %v)", existing, absent)
	}
	if status.Code(existing) != status.Code(absent) {
		t.Errorf("codes differ: cross-tenant = %v, nonexistent = %v — the difference is the oracle",
			status.Code(existing), status.Code(absent))
	}
	if existing.Error() != absent.Error() {
		t.Errorf("messages differ:\n  cross-tenant = %q\n  nonexistent  = %q", existing.Error(), absent.Error())
	}
	// The reply must also not name the id back, which would reintroduce a
	// per-id difference through the message.
	if strings.Contains(existing.Error(), "agent_principal:other") {
		t.Errorf("reply echoes the probed id: %q", existing.Error())
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0", len(az.wrote))
	}
}

// TestDeleteAgentGrants_CrossTenantIsIndistinguishableFromNonexistent pins the
// same property on the delete half. Both RPCs route through
// validateTargetAndTenant, and a single shared error value is what keeps them
// from drifting apart again.
func TestDeleteAgentGrants_CrossTenantIsIndistinguishableFromNonexistent(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:other": {
			PrincipalID: "agent_principal:other",
			TenantID:    "OTHER-TENANT",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	call := func(target string) error {
		_, err := srv.DeleteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.DeleteAgentGrantsRequest{
			TargetPrincipalId: target,
			Grants: []*tenantv1.GrantTuple{
				{Object: "component:gitlab", Relation: "can_read"},
			},
		})
		return err
	}

	existing := call("agent_principal:other")
	absent := call("agent_principal:no-such-principal-anywhere")
	if existing == nil || absent == nil {
		t.Fatalf("both deletes must be refused; got (%v, %v)", existing, absent)
	}
	if status.Code(existing) != status.Code(absent) || existing.Error() != absent.Error() {
		t.Errorf("replies differ: cross-tenant = %v, nonexistent = %v", existing, absent)
	}
}

// TestWriteAgentGrants_CallerAccessIntersectionRejected is the regression
// test for identity-assertion-gaps finding 4: a caller who does NOT hold the
// requested relation on the requested object must not be able to grant an
// agent/tool principal in their own tenant access to it anyway.
// validateTargetAndTenant only binds the RECIPIENT to the caller's tenant —
// it says nothing about whether the caller can reach the object being
// granted — so before the fix this request succeeded even though the caller
// (admin-1) has zero access to component:secret-vault.
func TestWriteAgentGrants_CallerAccessIntersectionRejected(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}} // caller has NO relation on the target object
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:secret-vault", Relation: "can_read"},
		},
	})
	if err == nil {
		t.Fatal("REGRESSION (identity-assertion-gaps finding 4): expected PermissionDenied when the caller " +
			"has no relation on the granted object; got nil (privilege escalation via WriteAgentGrants)")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0 (caller-access intersection must reject before any write)", len(az.wrote))
	}
}

// TestWriteAgentGrants_NoIdentityInContext covers the identity-resolution
// guard the caller-access intersection check (identity-assertion-gaps
// finding 4) depends on: WriteAgentGrants cannot check the CALLER's access
// without a caller identity in context.
func TestWriteAgentGrants_NoIdentityInContext(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	// ctxNoIdentity carries no auth.Identity at all (as if the interceptor
	// were bypassed), but validateTargetAndTenant needs a tenant, so we
	// build a context with a tenant but no identity by constructing the
	// zero Identity directly rather than via adminCtx.
	ctx := auth.WithTenant(context.Background(), mustTenant(t, "zeroroot-ai"))

	_, err := srv.WriteAgentGrants(ctx, &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
		},
	})
	if err == nil {
		t.Fatal("expected PermissionDenied when no identity is in context; got nil")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0", len(az.wrote))
	}
}

// TestWriteAgentGrants_CallerAccessBatchCheckFailure covers the fail-closed
// path when the caller-access intersection BatchCheck itself errors (e.g.
// an FGA outage) — must reject with Internal and write nothing, not fall
// back to permissive behavior.
func TestWriteAgentGrants_CallerAccessBatchCheckFailure(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}, batchCheckErr: errors.New("fga unavailable")}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
		},
	})
	if err == nil {
		t.Fatal("expected Internal error when the caller-access BatchCheck fails; got nil")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
	if len(az.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0 (must not write when caller-access could not be verified)", len(az.wrote))
	}
}

func TestWriteAgentGrants_InvalidRelation(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	_, err := srv.WriteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.WriteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:foo", Relation: "owner"},
		},
	})
	if err == nil {
		t.Fatal("expected InvalidArgument; got nil")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
}

func TestDeleteAgentGrants_HappyPath(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{
		"agent_principal:abc|can_read|component:gitlab": true,
	}}
	lookup := &stubLookup{records: map[string]identity.PrincipalRecord{
		"agent_principal:abc": {
			PrincipalID: "agent_principal:abc",
			TenantID:    "zeroroot-ai",
			Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		},
	}}
	srv := newWriteServer(t, az, lookup)

	resp, err := srv.DeleteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.DeleteAgentGrantsRequest{
		TargetPrincipalId: "agent_principal:abc",
		Grants: []*tenantv1.GrantTuple{
			{Object: "component:gitlab", Relation: "can_read"},
			{Object: "component:gitlab", Relation: "can_execute"}, // not present
		},
	})
	if err != nil {
		t.Fatalf("DeleteAgentGrants: %v", err)
	}
	if resp.GetDeleted() != 1 || resp.GetNotPresent() != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", resp.GetDeleted(), resp.GetNotPresent())
	}
}
