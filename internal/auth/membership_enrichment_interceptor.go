package auth

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson/internal/membership"
)

// MembershipEnrichmentInterceptor closes the bootstrap gap between Keycloak
// authentication and per-tenant authorization in the declarative-rbac-framework.
//
// Problem this solves
// -------------------
// The OIDC auth validator populates identity.Roles ONLY from helm's
// auth.oidc[].roleBindings map (Keycloak realm role -> Gibson role). Freshly
// signed-up tenant users have no realm roles mapped to Gibson roles —
// their Gibson role (owner / admin / operator / viewer) lives in the
// Redis membership store, not in Keycloak. As a result, every daemon
// call from such a user arrives with identity.Roles=[] and the
// RPCAuthzInterceptor denies everything with
// "missing_permission: X (caller_roles=[])".
//
// The same user's JWT also lacks a tenant_id claim (signup doesn't set
// the Keycloak user attribute), so the tenant extractor falls back to
// DefaultTenant (_system in the kind SaaS deploy). Looking up
// member(_system, subject) returns not-found, so even a naive "look up
// member, copy role" enrichment would still resolve to no role.
//
// What this interceptor does
// --------------------------
// Runs AFTER UnaryAuthInterceptor (which sets identity + tenant in ctx)
// and BEFORE RPCAuthzInterceptor (which reads identity.Roles to decide).
//
// For each request:
//
//  1. If the current tenant context is SystemTenant AND the caller is
//     NOT a cross-tenant role holder (platform-operator / provisioner /
//     *-executor), infer the real tenant from the user's memberships:
//     if the user is a member of exactly one tenant, promote that
//     tenant into ctx. Multi-member users fall through (the dashboard
//     should eventually switch-tenant via a header, not implemented
//     here). Zero-member users fall through (they will get denied
//     downstream, which is correct).
//
//  2. If there IS a real (non-system, non-wildcard) tenant in ctx,
//     look up member(tenant, subject) in the membership store and
//     APPEND the member's role to identity.Roles. Append, not replace,
//     so cross-tenant callers retain their helm-mapped role AND pick up
//     their tenant membership role on top.
//
// No-op paths
// -----------
//   - No identity in context (unauthenticated RPC, or the auth chain
//     was misconfigured) — skip.
//   - Cross-tenant RPC with no tenant in ctx — skip, the OIDC helm
//     bindings already set identity.Roles to whatever realm role the
//     caller holds.
//   - Caller is already a cross-tenant role holder AND current tenant
//     is SystemTenant — skip the inference step (they are operating
//     intentionally against _system), but still do the role lookup
//     in case they are also a member of _system.
//
// Mutation semantics
// ------------------
// identity is a pointer retrieved from context. The auth validator
// builds a fresh *Identity on every request (oidc.go / k8s.go /
// apikey.go all allocate a new struct), so mutating it for the
// duration of this request is safe and does not leak across requests.
// The interceptor uses containsString to avoid double-appending the
// same role if it is already present (e.g. a platform-operator who is
// also a tenant member via helm bindings).
type MembershipEnrichmentInterceptor struct {
	store    membership.MembershipStore
	registry *SchemaRegistry
	logger   *slog.Logger
}

// NewMembershipEnrichmentInterceptor constructs the interceptor.
// registry is required so the interceptor can ask "is this role a
// cross-tenant role?" via the schema-driven cross_tenant flag, matching
// the same logic used elsewhere in the daemon. store is required for
// the lookups. logger may be nil (defaults to slog.Default).
func NewMembershipEnrichmentInterceptor(
	store membership.MembershipStore,
	registry *SchemaRegistry,
	logger *slog.Logger,
) *MembershipEnrichmentInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	return &MembershipEnrichmentInterceptor{
		store:    store,
		registry: registry,
		logger:   logger,
	}
}

// Unary returns a grpc.UnaryServerInterceptor. Install AFTER the auth
// interceptor and BEFORE the RPCAuthzInterceptor in the chain.
func (i *MembershipEnrichmentInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = i.enrich(ctx)
		return handler(ctx, req)
	}
}

// Stream returns a grpc.StreamServerInterceptor with the same contract
// as Unary. The stream context is wrapped so downstream interceptors
// and the handler see the enriched values.
func (i *MembershipEnrichmentInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &enrichedStream{
			ServerStream: ss,
			ctx:          i.enrich(ss.Context()),
		}
		return handler(srv, wrapped)
	}
}

// enrichedStream wraps grpc.ServerStream so Context() returns the
// enriched context instead of the original.
type enrichedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *enrichedStream) Context() context.Context { return s.ctx }

// enrich is the shared implementation for both unary and stream paths.
// Returns the (possibly updated) context; always safe to call.
func (i *MembershipEnrichmentInterceptor) enrich(ctx context.Context) context.Context {
	if i.store == nil {
		return ctx
	}

	identity, ok := GibsonIdentityFromContext(ctx)
	if !ok || identity == nil || identity.Subject == "" {
		// Unauthenticated or bootstrap RPC — nothing to enrich.
		return ctx
	}

	tenant := TenantFromContext(ctx)

	// Step 1: tenant inference.
	// If the caller landed on the SystemTenant fallback because their
	// JWT has no tenant_id claim, AND they don't hold a cross-tenant
	// role already, try to promote them to their sole tenant membership.
	if tenant == SystemTenant && !i.isCrossTenant(identity.Roles) {
		memberships, err := i.store.ListUserTenants(ctx, identity.Subject)
		if err != nil {
			i.logger.Warn("membership_enrichment: ListUserTenants failed",
				"subject", identity.Subject,
				"err", err.Error(),
			)
		} else if len(memberships) == 1 {
			tenant = memberships[0].TenantID
			ctx = ContextWithTenant(ctx, tenant)
			// Since we just read the membership record, append the role
			// directly instead of re-fetching it below.
			if !containsString(identity.Roles, memberships[0].Role) {
				identity.Roles = append(identity.Roles, memberships[0].Role)
			}
			return ctx
		}
		// Multi-tenant or zero-tenant case: fall through. The caller
		// will get a deny downstream if the current tenant context
		// doesn't grant them the required permission.
	}

	// Step 2: membership role lookup.
	// If we have a real tenant in ctx (not empty, not _system, not "*"),
	// look up the user's role in that tenant and append it.
	if tenant == "" || tenant == SystemTenant || tenant == "*" {
		return ctx
	}
	member, err := i.store.GetMember(ctx, tenant, identity.Subject)
	if err != nil {
		if !errors.Is(err, membership.ErrMemberNotFound) {
			i.logger.Warn("membership_enrichment: GetMember failed",
				"tenant", tenant,
				"subject", identity.Subject,
				"err", err.Error(),
			)
		}
		return ctx
	}
	if member != nil && !containsString(identity.Roles, member.Role) {
		identity.Roles = append(identity.Roles, member.Role)
	}
	return ctx
}

// isCrossTenant reports whether any of the given role names is flagged
// cross_tenant=true in the loaded permissions schema. When the registry
// is nil (e.g. in tests that don't load the full schema), defaults to
// false so tenant inference still runs.
func (i *MembershipEnrichmentInterceptor) isCrossTenant(roles []string) bool {
	if i.registry == nil {
		return false
	}
	return i.registry.IsCrossTenantCaller(roles)
}
