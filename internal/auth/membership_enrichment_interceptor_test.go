package auth

import (
	"context"
	"errors"
	"testing"

	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson/internal/membership"
)

// --- Fake membership store --------------------------------------------------

// fakeMembershipStore is a minimal in-memory MembershipStore for the
// enrichment interceptor tests. Only GetMember and ListUserTenants are
// exercised; the other methods are no-op/not-implemented so the tests
// don't need the full Redis backend.
type fakeMembershipStore struct {
	// members is keyed by "tenantID|userID" for O(1) GetMember lookups.
	members map[string]*membership.Membership
	// byUser is keyed by userID for ListUserTenants.
	byUser map[string][]membership.Membership
	// simulateListErr, when non-nil, is returned from ListUserTenants.
	simulateListErr error
	// simulateGetErr, when non-nil, is returned from GetMember.
	simulateGetErr error
}

func newFakeMembershipStore() *fakeMembershipStore {
	return &fakeMembershipStore{
		members: map[string]*membership.Membership{},
		byUser:  map[string][]membership.Membership{},
	}
}

func (f *fakeMembershipStore) add(tenantID, userID, role string) {
	m := &membership.Membership{
		TenantID: tenantID,
		UserID:   userID,
		Role:     role,
	}
	f.members[tenantID+"|"+userID] = m
	f.byUser[userID] = append(f.byUser[userID], *m)
}

func (f *fakeMembershipStore) GetMember(ctx context.Context, tenantID, userID string) (*membership.Membership, error) {
	if f.simulateGetErr != nil {
		return nil, f.simulateGetErr
	}
	m, ok := f.members[tenantID+"|"+userID]
	if !ok {
		return nil, membership.ErrMemberNotFound
	}
	return m, nil
}

func (f *fakeMembershipStore) ListUserTenants(ctx context.Context, userID string) ([]membership.Membership, error) {
	if f.simulateListErr != nil {
		return nil, f.simulateListErr
	}
	return f.byUser[userID], nil
}

// The other MembershipStore methods are not exercised by this test file
// but still need to exist for the interface to be satisfied.
func (f *fakeMembershipStore) AddMember(ctx context.Context, tenantID, userID, email, role, addedBy string) error {
	return nil
}
func (f *fakeMembershipStore) RemoveMember(ctx context.Context, tenantID, userID string) error {
	return nil
}
func (f *fakeMembershipStore) UpdateRole(ctx context.Context, tenantID, userID, newRole, changedBy string) error {
	return nil
}
func (f *fakeMembershipStore) ListTenantMembers(ctx context.Context, tenantID string) ([]membership.Membership, error) {
	return nil, nil
}
func (f *fakeMembershipStore) TransferOwnership(ctx context.Context, tenantID, fromUserID, toUserID, changedBy string) error {
	return nil
}

// --- Test helpers ------------------------------------------------------------

// newEnrichmentInterceptor builds the interceptor with the real schema
// registry (so IsCrossTenantCaller works) and the supplied fake store.
func newEnrichmentInterceptor(t *testing.T, store membership.MembershipStore) *MembershipEnrichmentInterceptor {
	t.Helper()
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	return NewMembershipEnrichmentInterceptor(store, reg, nil)
}

// ctxWithIdentityAndTenant prepares a request context containing a
// Gibson Identity plus an explicit tenant selection.
func ctxWithIdentityAndTenant(subject string, roles []string, tenant string) (context.Context, *Identity) {
	ctx := context.Background()
	identity := &Identity{
		Identity: sdkauth.Identity{Subject: subject},
		Roles:    roles,
	}
	ctx = ContextWithIdentity(ctx, identity)
	if tenant != "" {
		ctx = ContextWithTenant(ctx, tenant)
	}
	return ctx, identity
}

// runUnary invokes the interceptor's unary wrapper against a stub
// handler and returns the resulting Identity (post-enrichment) and
// tenant context, plus any error.
func runUnary(i *MembershipEnrichmentInterceptor, ctx context.Context) (*Identity, string) {
	var capturedIdentity *Identity
	var capturedTenant string
	handler := func(innerCtx context.Context, req any) (any, error) {
		if id, ok := GibsonIdentityFromContext(innerCtx); ok {
			capturedIdentity = id
		}
		capturedTenant = TenantFromContext(innerCtx)
		return nil, nil
	}
	_, _ = i.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/Test/Method"}, handler)
	return capturedIdentity, capturedTenant
}

// --- Tests -------------------------------------------------------------------

// TestEnrichment_TenantScopedUser_AppendsRole is the primary signup-flow
// case: a freshly authenticated user with an explicit tenant in ctx
// (from the JWT tenant claim or a switch header) gets their member role
// appended to identity.Roles.
func TestEnrichment_TenantScopedUser_AppendsRole(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("zero-day-ai", "user-uuid", "owner")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, "zero-day-ai")

	id, tenant := runUnary(interceptor, ctx)

	if id == nil {
		t.Fatal("identity should still be in context after enrichment")
	}
	if tenant != "zero-day-ai" {
		t.Errorf("tenant = %q, want zero-day-ai", tenant)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "owner" {
		t.Errorf("id.Roles = %v, want [owner]", id.Roles)
	}
}

// TestEnrichment_SystemFallback_InfersSingleTenant is the fresh-signup
// boot path: user signs in, JWT has no tenant_id claim, daemon defaults
// ctx to SystemTenant, this interceptor promotes them to their sole
// tenant membership and appends the role.
func TestEnrichment_SystemFallback_InfersSingleTenant(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("zero-day-ai", "user-uuid", "owner")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, SystemTenant)

	id, tenant := runUnary(interceptor, ctx)

	if tenant != "zero-day-ai" {
		t.Errorf("tenant should be promoted to zero-day-ai, got %q", tenant)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "owner" {
		t.Errorf("id.Roles = %v, want [owner]", id.Roles)
	}
}

// TestEnrichment_SystemFallback_MultiTenantFallsThrough ensures the
// inference step refuses to guess when the user has more than one
// membership. The caller will still get denied downstream by the
// authz interceptor, which is the correct behavior: the dashboard
// should be sending an explicit tenant switch header in this case.
func TestEnrichment_SystemFallback_MultiTenantFallsThrough(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("tenant-a", "user-uuid", "owner")
	store.add("tenant-b", "user-uuid", "viewer")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, SystemTenant)

	id, tenant := runUnary(interceptor, ctx)

	// Tenant should stay at SystemTenant (no promotion).
	if tenant != SystemTenant {
		t.Errorf("tenant = %q, want SystemTenant fallback to remain", tenant)
	}
	// Roles should stay empty (no enrichment).
	if len(id.Roles) != 0 {
		t.Errorf("id.Roles = %v, want empty", id.Roles)
	}
}

// TestEnrichment_CrossTenantCaller_PreservesOriginalRoles confirms a
// platform-operator (cross_tenant=true role from helm oidc bindings)
// landing on SystemTenant stays on SystemTenant — the tenant inference
// step skips them — and keeps their helm-assigned role intact.
func TestEnrichment_CrossTenantCaller_PreservesOriginalRoles(t *testing.T) {
	store := newFakeMembershipStore()
	// Platform-operator user happens to also be a member of tenant-a.
	// Without the inference skip, we'd promote them to tenant-a which
	// would be wrong (they're an operator of the platform, not tenant-a).
	store.add("tenant-a", "admin-uuid", "admin")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("admin-uuid", []string{"platform-operator"}, SystemTenant)

	id, tenant := runUnary(interceptor, ctx)

	if tenant != SystemTenant {
		t.Errorf("cross-tenant caller should stay on SystemTenant, got %q", tenant)
	}
	// platform-operator should still be the only role (SystemTenant
	// lookup returns ErrMemberNotFound so nothing gets appended).
	if len(id.Roles) != 1 || id.Roles[0] != "platform-operator" {
		t.Errorf("id.Roles = %v, want [platform-operator]", id.Roles)
	}
}

// TestEnrichment_CrossTenantCaller_AppendsRoleInRealTenant confirms
// that a cross-tenant caller explicitly operating inside a real tenant
// (e.g. platform-operator querying tenant-a from an admin UI) DOES get
// their tenant member role appended on top of their platform role.
// Append semantics, not replace.
func TestEnrichment_CrossTenantCaller_AppendsRoleInRealTenant(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("tenant-a", "admin-uuid", "admin")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("admin-uuid", []string{"platform-operator"}, "tenant-a")

	id, tenant := runUnary(interceptor, ctx)

	if tenant != "tenant-a" {
		t.Errorf("tenant = %q, want tenant-a", tenant)
	}
	// platform-operator should be preserved AND admin appended.
	if len(id.Roles) != 2 {
		t.Fatalf("id.Roles = %v, want 2 roles", id.Roles)
	}
	if !containsString(id.Roles, "platform-operator") {
		t.Error("platform-operator should be preserved")
	}
	if !containsString(id.Roles, "admin") {
		t.Error("admin should be appended")
	}
}

// TestEnrichment_CrossTenantRPC_Skipped verifies that RPCs with no
// tenant in ctx (cross-tenant RPCs like ProvisionTenant or
// ListUserTenants) are a no-op for the enrichment interceptor.
func TestEnrichment_CrossTenantRPC_Skipped(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("zero-day-ai", "user-uuid", "owner")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, "")

	id, tenant := runUnary(interceptor, ctx)

	if tenant != "" {
		t.Errorf("tenant = %q, want empty", tenant)
	}
	// No enrichment because no tenant in ctx — the authz interceptor
	// will handle bootstrap RPCs (ListUserTenants has empty required
	// permissions so this is fine).
	if len(id.Roles) != 0 {
		t.Errorf("id.Roles = %v, want empty", id.Roles)
	}
}

// TestEnrichment_NoIdentity_NoOp ensures the interceptor doesn't crash
// or mutate state when there's no identity in context (should be
// impossible in production but belt and suspenders).
func TestEnrichment_NoIdentity_NoOp(t *testing.T) {
	store := newFakeMembershipStore()
	interceptor := newEnrichmentInterceptor(t, store)

	ctx := ContextWithTenant(context.Background(), "zero-day-ai")
	// No identity set.
	_, _ = runUnary(interceptor, ctx)

	// Just asserting no panic. If runUnary returned without error, pass.
}

// TestEnrichment_NotAMember_NoAppend verifies the interceptor handles
// a legitimate case where the caller isn't a member of the current
// tenant: nothing is appended, and the authz interceptor denies
// downstream.
func TestEnrichment_NotAMember_NoAppend(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("tenant-a", "other-uuid", "owner")
	// user-uuid is NOT a member of tenant-a.

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, "tenant-a")

	id, _ := runUnary(interceptor, ctx)

	if len(id.Roles) != 0 {
		t.Errorf("id.Roles = %v, want empty (not a member)", id.Roles)
	}
}

// TestEnrichment_ListError_SoftFail verifies a transient Redis error
// during tenant inference doesn't crash the request: the call proceeds
// with whatever Roles it already had, and the authz interceptor
// decides accordingly.
func TestEnrichment_ListError_SoftFail(t *testing.T) {
	store := newFakeMembershipStore()
	store.simulateListErr = errors.New("redis timeout")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, _ := ctxWithIdentityAndTenant("user-uuid", []string{}, SystemTenant)

	id, tenant := runUnary(interceptor, ctx)

	if tenant != SystemTenant {
		t.Errorf("tenant = %q, want SystemTenant (no promotion)", tenant)
	}
	if len(id.Roles) != 0 {
		t.Errorf("id.Roles = %v, want empty", id.Roles)
	}
}

// TestEnrichment_DoubleCall_Idempotent ensures calling the interceptor
// twice (which could happen if two interceptors share state) doesn't
// duplicate the role.
func TestEnrichment_DoubleCall_Idempotent(t *testing.T) {
	store := newFakeMembershipStore()
	store.add("zero-day-ai", "user-uuid", "owner")

	interceptor := newEnrichmentInterceptor(t, store)
	ctx, identity := ctxWithIdentityAndTenant("user-uuid", []string{}, "zero-day-ai")

	// Pipe through the interceptor twice.
	runUnary(interceptor, ctx)
	runUnary(interceptor, ctx)

	if len(identity.Roles) != 1 {
		t.Errorf("id.Roles = %v, want single [owner] after two enrichment passes", identity.Roles)
	}
}
