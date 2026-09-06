// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Canonical FGA object derivation (gibson#694).
//
// This file is the single source of truth for how gibson code derives the FGA
// object reference for components and plugins. Before it existed, four call
// sites used four different forms (bare, kind-qualified-colon, kind-qualified-
// dash, tenant-qualified) and a can_execute check could silently never match
// the seeded tuple. The canonical forms are:
//
//	component:<name>          — a component (agent | tool | plugin) in the
//	                            registry. Tenant-LESS: tenant isolation comes
//	                            from the model's in_tenant_catalog gate
//	                            (tenant_enabled tuples) plus the tenant-scoped
//	                            membership of the checking subject, and from
//	                            the data plane keying every registry lookup and
//	                            dispatch by (tenant, name).
//	plugin:<tenant>:<name>    — the plugin-invocation object checked by the
//	                            PluginInvoke can_invoke annotation
//	                            (object_deriver: tenant_and_field('PluginName'))
//	                            and seeded by the tenant-operator
//	                            PluginCanInvokeTuple. Tenant-qualified.
//
// NOT an FGA reference: the capability-grant JWT subject
// "component:<kind>:<name>" (minted in internal/harness mintCGForWork). That
// string is an identity-namespace value carried in the token's sub claim; the
// FGA reference derived from a capability name is always the bare
// ComponentObject form (see capabilitygrant.parseCapabilityName).
//
// The (tool source → object, relation) mapping for the SearchTools catalog
// filter lives in internal/catalog.FGAAuthorizer and is built on these
// helpers:
//
//	mcp:<connector>:<tool> → Check(subject, can_execute, ConnectorComponentObject(connector))
//	native:<tool>          → Check(subject, can_execute, ComponentObject(tool))

// Component kinds. The single FGA `component` object type carries all four
// kinds (ADR-0046/0067); the kind is part of the object id, never a separate
// FGA type. These are the canonical kind qualifiers (ADR-0015).
const (
	KindAgent     = "agent"
	KindTool      = "tool"
	KindPlugin    = "plugin"
	KindConnector = "connector"
)

// ComponentObject returns the canonical FGA object reference for a component:
// "component:<kind>/<name>" (ADR-0015). The kind is one of KindAgent/Tool/
// Plugin/Connector; the name is the bare component name, never tenant-qualified.
// Kind-prefixing keeps an agent and a tool of the same name distinct objects.
func ComponentObject(kind, name string) string {
	return "component:" + kind + "/" + name
}

// ConnectorKindPrefix is the "connector/" object-id prefix, kept for callers
// that build the connector segment by hand.
const ConnectorKindPrefix = KindConnector + "/"

// ConnectorComponentObject returns the canonical FGA object reference for a
// connector component: "component:connector/<catalog-id>". One object per
// catalog entry, shared across tenants; per-tenant state lives in relations
// (owner, tenant_enabled), never in the id. The "/" inside the id is safe:
// only a third ":" is rejected by OpenFGA (see TenantQualifiedSep, gibson#1024).
func ConnectorComponentObject(catalogID string) string {
	return ComponentObject(KindConnector, catalogID)
}

// TenantQualifiedSep joins the tenant and field segments of a tenant-qualified
// FGA object id (e.g. plugin:<tenant><sep><name>). It MUST NOT be a colon:
// OpenFGA v1.8.4 rejects a THIRD colon at the structural type-id boundary —
// i.e. "type:tenant:name" is parsed as a 3-part string and fails with "invalid
// 'object' field format" on both Write and Check. The id portion may contain
// colons in the body (e.g. a ref like "cred:openai-prod"), but the separator
// between the tenant slug and the rest of the id must not be ":". We use "/"
// instead, which OpenFGA accepts and which cannot appear in a tenant slug or
// component name ([a-z0-9-]). See gibson#1024. Every producer of a tenant-
// qualified object — the daemon (PluginObject + the secret writers), ext-authz's
// tenant_and_field deriver, and the tenant-operator FGA clients — MUST use this
// same separator or Check will never match Write.
const TenantQualifiedSep = "/"

// PluginObject returns the canonical FGA object reference for plugin
// invocation: "plugin:<tenant>/<name>". The tenant-qualified id must match
// what the PluginInvoke RPC's tenant_and_field('PluginName') deriver produces
// at check time and what the tenant-operator seeds at enrollment.
func PluginObject(tenant, name string) string {
	return "plugin:" + tenant + TenantQualifiedSep + name
}

// SecretObject returns the canonical FGA object reference for a tenant-scoped
// secret: "secret:tenant-<tenant>/<ref>". The "tenant-" prefix is a fixed part
// of the secret object id convention (not a type qualifier) — it distinguishes
// the tenant-namespace segment from the ref and is consistent with the
// tenant-operator's SecretCanResolveTuple and the daemon's plugin_admin writers.
//
// The tenant-slug and ref are joined with "/" (TenantQualifiedSep, not ":").
// The id must additionally contain NO colon anywhere: OpenFGA (verified
// against the platform's pinned v1.15.1) rejects a colon in the id portion
// with "invalid 'object' field format" on both Write and Check — NOT only at
// the structural type-id boundary as an earlier note assumed for v1.8.4. A
// secret ref is category-prefixed with a colon (e.g. "cred:openai-prod",
// "provider_config:foo"), so the ref is folded through refToObjectSegment,
// which replaces the category colon with "@" (reversible) to keep the id colon-free.
//
// The object id is opaque: it is only ever compared for equality between a
// writer and a checker, and every one of them goes through SecretObject (the
// plugin_admin binding writer, the daemon credential checks in
// callback_credential_authz + service_credential_authz, and the ext-authz
// deriver via SecretObjectFromDeriver), so the fold is consistent by
// construction. This path had ZERO tuples on any cluster when the fold
// landed (no can_resolve secret tuple could ever be written on v1.15.1
// before it), so there is nothing to migrate.
//
// Usage:
//
//	tupleObj = authz.SecretObject(tenant.String(), ref)   // for FGA writes
//	// ext-authz tenant_and_field deriver uses SecretObjectFromDeriver
//
// SecretObject is the canonical form: all secret FGA tuple writers, the authz
// deriver, and uriToRef must agree on this exact format (gibson#1035).
func SecretObject(tenant, ref string) string {
	return "secret:tenant-" + tenant + TenantQualifiedSep + refToObjectSegment(ref)
}

// secretRefColonEscape stands in for the colon that a secret ref carries as
// its category separator ("cred:", "provider_config:"). OpenFGA v1.15.1
// rejects a colon anywhere in an object id (verified live) but accepts "@",
// which never appears in a broker secret ref — so the mapping is a clean,
// REVERSIBLE substitution. refToObjectSegment applies it; RefFromObjectSegment
// (used by uriToRef) inverts it to recover the exact ref for display and
// broker lookup.
const secretRefColonEscape = "@"

// refToObjectSegment encodes a secret ref into an OpenFGA-legal object-id
// segment by replacing its category colon with secretRefColonEscape. Applied
// identically wherever a secret object is built (writers, checkers, deriver),
// so write and check always agree.
func refToObjectSegment(ref string) string {
	return strings.ReplaceAll(ref, ":", secretRefColonEscape)
}

// RefFromObjectSegment inverts refToObjectSegment: it recovers the original
// secret ref from the id segment after the tenant prefix. Reversible because
// "@" cannot occur in a broker secret ref.
func RefFromObjectSegment(segment string) string {
	return strings.ReplaceAll(segment, secretRefColonEscape, ":")
}

// SecretObjectFromDeriver returns the FGA object a tenant_and_field('Name')
// deriver should produce for a secret can_resolve check. It takes the tenant
// slug as carried in identity.Tenant (the raw JWT claim, e.g. "acme") and the
// ref field from the request metadata. This is the ext-authz-side mirror of
// SecretObject — they must produce identical strings for the same (tenant, ref).
func SecretObjectFromDeriver(tenant, ref string) string {
	return SecretObject(tenant, ref)
}

// --- team objects (gibson#1231) ---------------------------------------------

// TeamObjectMaxIDLen caps each segment of a team object id. OpenFGA accepts an
// object of up to 256 bytes; the type prefix, the tenant segment and the
// separator all come out of that budget, so neither segment may use it all.
const TeamObjectMaxIDLen = 96

// ErrInvalidTeamSegment is returned by TeamObject for a segment that cannot
// safely appear in a team object id. Callers on an RPC boundary map it to
// InvalidArgument; it is a plain error here so this package stays free of gRPC.
var ErrInvalidTeamSegment = errors.New("invalid team object segment")

// TeamObject returns the canonical FGA object reference for a team:
// "team:<tenant>/<team_id>".
//
// Team object ids used to be global ("team:<id>"), and `team.parent` is a plain
// [tenant] relation with no cardinality constraint, so two tenants could each
// hold a parent tuple on the SAME object. Every team RPC gates on that parent
// edge, so a second parent handed the squatter the victim's roster and, through
// `admin: [user] or admin from parent`, administration of it. Team ids are
// caller-chosen human slugs (gibson#1231).
//
// The tenant segment MUST come from the authenticated context, never from the
// request — that is what makes another tenant's team unnameable rather than
// merely guarded. Every producer of a team object (the tenant-admin handlers,
// ModelAccessService grants, the budget team resolver) calls this function; a
// second derivation that disagreed would mean Check never matches Write, the
// gibson#1024 failure mode.
//
// Both segments are validated. The separator is TenantQualifiedSep for the same
// reason plugin and secret objects use it: OpenFGA rejects a second colon at the
// structural type-id boundary, and "/" is the separator this repo has already
// proven against a live server (see object_format_integration_test.go).
func TeamObject(tenant, teamID string) (string, error) {
	if err := validateTeamSegment("tenant", tenant); err != nil {
		return "", err
	}
	if err := validateTeamSegment("team_id", teamID); err != nil {
		return "", err
	}
	return "team:" + tenant + TenantQualifiedSep + teamID, nil
}

// TeamIDFromObject is the inverse of TeamObject: it returns the bare team id
// for an object belonging to tenant, and false for anything else.
//
// "Anything else" has to stay silent-proof in two directions. An object in
// another tenant's namespace must never be reported as one of this tenant's
// teams. An object with no tenant segment — a legacy global "team:<id>" written
// before gibson#1231 — is not this tenant's team either: it is unattributable by
// construction, which is precisely what the namespace removes. Callers log and
// skip rather than guess.
func TeamIDFromObject(tenant, object string) (string, bool) {
	if tenant == "" {
		return "", false
	}
	id, ok := strings.CutPrefix(object, "team:"+tenant+TenantQualifiedSep)
	if !ok || id == "" || strings.Contains(id, TenantQualifiedSep) {
		return "", false
	}
	return id, true
}

// teamObjectForbidden are the runes that would make a team object id mean
// something other than one team:
//
//   - ':' introduces a second type prefix, which OpenFGA rejects outright at the
//     structural boundary (gibson#1024).
//   - '#' turns the object into a userset. The component-access relations
//     genuinely take "team:<id>#member" subjects, so an id ending in "#member"
//     is a live confusion, not a theoretical one.
//   - '/' is the namespace separator; allowing it in a segment would make
//     "team:a/b/c" ambiguous about where the tenant ends.
const teamObjectForbidden = ":#" + TenantQualifiedSep

// validateTeamSegment rejects a segment that cannot safely appear in a team
// object id. Whitespace is rejected separately: OpenFGA refuses it, and it would
// surface as an opaque validation error rather than a caller error.
func validateTeamSegment(label, seg string) error {
	switch {
	case seg == "":
		return fmt.Errorf("%w: %s required", ErrInvalidTeamSegment, label)
	case len(seg) > TeamObjectMaxIDLen:
		return fmt.Errorf("%w: %s must be at most %d bytes", ErrInvalidTeamSegment, label, TeamObjectMaxIDLen)
	case strings.ContainsAny(seg, teamObjectForbidden):
		return fmt.Errorf("%w: %s must not contain any of %q", ErrInvalidTeamSegment, label, teamObjectForbidden)
	case strings.ContainsFunc(seg, unicode.IsSpace):
		return fmt.Errorf("%w: %s must not contain whitespace", ErrInvalidTeamSegment, label)
	}
	return nil
}

// --- active_session helpers (gibson#627 Slice 2) ----------------------------

// ConditionTokenNotRevoked is the FGA condition name used by the
// active_session relation (defined in model.fga). Both the write path
// (WriteConditional / UpdateConditionalTuple) and the check path
// (ext-authz, Slice 3) must reference this exact name.
const ConditionTokenNotRevoked = "token_not_revoked"

// ConditionParamRevokedAt is the name of the revoked_at condition parameter
// consumed by token_not_revoked. OpenFGA expects RFC 3339 timestamp strings
// for parameters declared as type=timestamp.
const ConditionParamRevokedAt = "revoked_at"

// EpochRevokedAt is the RFC 3339 value written as revoked_at when a user's
// active_session tuple is first seeded (provisioning / backfill). The epoch
// timestamp predates any real token_issued_at, so the condition
// `token_issued_at > revoked_at` evaluates to true for every valid token —
// meaning the session is effectively "never revoked".
const EpochRevokedAt = "1970-01-01T00:00:00Z"

// ActiveSessionObject returns the canonical FGA object reference for the
// active_session relation: "tenant:<slug>".
func ActiveSessionObject(tenantSlug string) string {
	return "tenant:" + tenantSlug
}

// ActiveSessionUser returns the canonical FGA user reference for the
// active_session relation: "user:<userID>".
func ActiveSessionUser(userID string) string {
	return "user:" + userID
}

// ActiveSessionTuple builds the ConditionalTuple for seeding a user's
// active_session relation during provisioning or backfill. The revoked_at
// is set to the epoch, meaning the session is valid for all real tokens.
func ActiveSessionTuple(userID, tenantSlug string) ConditionalTuple {
	return ConditionalTuple{
		User:          ActiveSessionUser(userID),
		Relation:      "active_session",
		Object:        ActiveSessionObject(tenantSlug),
		ConditionName: ConditionTokenNotRevoked,
		ConditionContext: map[string]any{
			ConditionParamRevokedAt: EpochRevokedAt,
		},
	}
}

// RevokedSessionTuple builds the ConditionalTuple for marking a user's
// session as revoked. revokedAt must be an RFC 3339 timestamp; once written,
// any token with token_issued_at <= revokedAt will be denied by ext-authz.
func RevokedSessionTuple(userID, tenantSlug, revokedAt string) ConditionalTuple {
	return ConditionalTuple{
		User:          ActiveSessionUser(userID),
		Relation:      "active_session",
		Object:        ActiveSessionObject(tenantSlug),
		ConditionName: ConditionTokenNotRevoked,
		ConditionContext: map[string]any{
			ConditionParamRevokedAt: revokedAt,
		},
	}
}

// ActiveSessionUserObject returns the canonical FGA object reference for the
// USER-SCOPED active_session relation (gibson#1244): "user:<userID>". The
// user-scoped active_session tuple is self-referential — subject and object
// are both the user — so it gates a request that names no tenant, which has no
// `type tenant` object to check.
func ActiveSessionUserObject(userID string) string {
	return "user:" + userID
}

// ActiveSessionUserTuple builds the ConditionalTuple that seeds a user's
// USER-SCOPED active_session relation during provisioning or backfill
// (gibson#1244). Written alongside ActiveSessionTuple by every writer that
// seeds the per-tenant tuple. The revoked_at is the epoch, meaning the session
// is valid for every real token until RevokeUserSessions advances it.
//
// Idempotent by construction: it is keyed on the user object alone, so a user
// who is a member of several tenants gets one such tuple regardless of how many
// per-tenant tuples exist (WriteConditional treats the duplicate as a no-op).
func ActiveSessionUserTuple(userID string) ConditionalTuple {
	return ConditionalTuple{
		User:          ActiveSessionUser(userID),
		Relation:      "active_session",
		Object:        ActiveSessionUserObject(userID),
		ConditionName: ConditionTokenNotRevoked,
		ConditionContext: map[string]any{
			ConditionParamRevokedAt: EpochRevokedAt,
		},
	}
}

// RevokedSessionUserTuple builds the ConditionalTuple that stamps a user's
// USER-SCOPED active_session tuple with revoked_at=now (gibson#1244). Advanced
// by RevokeUserSessions on the SAME revocation path as RevokedSessionTuple so a
// tenant-less request is gated by the same revocation event as a tenant-scoped
// one. revokedAt must be an RFC 3339 timestamp.
func RevokedSessionUserTuple(userID, revokedAt string) ConditionalTuple {
	return ConditionalTuple{
		User:          ActiveSessionUser(userID),
		Relation:      "active_session",
		Object:        ActiveSessionUserObject(userID),
		ConditionName: ConditionTokenNotRevoked,
		ConditionContext: map[string]any{
			ConditionParamRevokedAt: revokedAt,
		},
	}
}

// componentKinds are the component-kind qualifiers on the single FGA
// `component` object type. CanonicalComponentResource prefixes them onto the
// object id: the FGA object is "component:<kind>/<name>" (ADR-0015).
var componentKinds = map[string]bool{
	KindAgent:     true,
	KindTool:      true,
	KindPlugin:    true,
	KindConnector: true,
}

// IsComponentKind reports whether kind is one of the four canonical component
// kinds (agent/tool/plugin/connector), i.e. a valid kind segment in a
// "component:<kind>/<name>" object id.
func IsComponentKind(kind string) bool { return componentKinds[kind] }

// CanonicalComponentResource maps a caller-provided component resource string
// to the canonical FGA object reference "component:<kind>/<name>" (ADR-0015).
// Accepted inputs and their mappings:
//
//	"tool:nmap"                → "component:tool/nmap"   (kind-qualified)
//	"component:tool:nmap"      → "component:tool/nmap"   (legacy colon object)
//	"component:agent/zerocool" → unchanged               (already canonical)
//	"plugin:acme/gitlab"       → unchanged               (plugin-TYPE object, not a component)
//	"mission:abc"              → unchanged               (non-component typed reference)
//
// A kind-LESS component reference — bare "nmap" or the legacy "component:nmap" —
// can no longer be resolved to an object, because the object id carries the
// kind. It returns an error and the caller must fail closed (ADR-0015): a
// kind-less string is never silently assigned a kind.
func CanonicalComponentResource(resource string) (string, error) {
	parts := strings.SplitN(resource, ":", 3)
	switch len(parts) {
	case 1:
		// No colon. Accept the object-minus-prefix slash form "<kind>/<name>" —
		// what the FGA object (component:<kind>/<name>) looks like without its
		// "component:" prefix, and the natural thing to type. Only a genuinely
		// kind-less name (no known kind qualifier at all) fails closed.
		if kind, name, ok := strings.Cut(resource, TenantQualifiedSep); ok && componentKinds[kind] && name != "" {
			return ComponentObject(kind, name), nil
		}
		return "", fmt.Errorf(
			"component resource %q is kind-less; qualify it with a component kind (%s/%s/%s/%s) — e.g. %s:%s or %s/%s",
			resource, KindAgent, KindTool, KindPlugin, KindConnector, KindTool, resource, KindTool, resource)
	case 2:
		typ, rest := parts[0], parts[1]
		if typ == "component" {
			if strings.Contains(rest, TenantQualifiedSep) {
				// "component:<kind>/<name>" — already canonical; validate the kind.
				kind, _, _ := strings.Cut(rest, TenantQualifiedSep)
				if componentKinds[kind] {
					return resource, nil
				}
				return "", fmt.Errorf("component object %q has unknown kind %q", resource, kind)
			}
			// "component:<name>" — legacy kind-less object. Fail closed.
			return "", fmt.Errorf("component object %q is kind-less; expected component:<kind>/<name>", resource)
		}
		if typ == KindPlugin && strings.Contains(rest, TenantQualifiedSep) {
			// "plugin:<tenant>/<name>" — a plugin-TYPE object (a plugin
			// principal, gibson#1024), NOT a component. Never rewritten.
			return resource, nil
		}
		if componentKinds[typ] {
			// "<kind>:<name>" → "component:<kind>/<name>".
			return ComponentObject(typ, rest), nil
		}
		// Other typed reference (mission:abc, …) — unchanged.
		return resource, nil
	default:
		if parts[0] == "component" && componentKinds[parts[1]] {
			// Legacy colon object "component:<kind>:<name>" → "component:<kind>/<name>".
			return ComponentObject(parts[1], parts[2]), nil
		}
		// A 3-segment typed object (e.g. legacy "plugin:<tenant>:<name>") — unchanged.
		return resource, nil
	}
}
