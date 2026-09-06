// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// sessionGateDeniedCounter is incremented whenever a human JWT-bearing request
// is denied by the active_session gate — that is, the token's iat is not after
// the principal's revoked_at timestamp in FGA (or the tuple is absent).
// Distinct from extauthz_denied_total so revocations are visible in isolation.
// Labels: reason={revoked,absent} (revoked = FGA deny on condition; absent = no
// tuple). In practice the FGA model returns the same deny for both, so label
// "revoked" covers both; the distinction is documented here for future work if
// the model grows explicit tuple-absent handling.
var sessionGateDeniedCounter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "extauthz_session_gate_denied_total",
	Help: "Requests denied by the active_session FGA gate (instant revocation, gibson#627). " +
		"Incremented for human JWT-bearing requests whose token iat is at or before revoked_at, " +
		"or whose active_session tuple is absent (fail-closed). Machine principals skip this gate.",
})

// ErrObjectUnresolvable reports that a registry entry's object deriver had no
// value to derive its object from — the tenant is missing, or the rule names a
// request field the gateway cannot see. Check turns it into a deny; it is not
// an infrastructure error and must never be answered with a broader object.
var ErrObjectUnresolvable = errors.New("fga: object unresolvable")

// Prometheus counter incremented when an entry's object could not be derived,
// so the request was denied without an FGA call.
var objectUnresolvableCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "extauthz_object_unresolvable_total",
		Help: "Requests denied because the registry entry's FGA object could not be derived.",
	},
	[]string{"method"},
)

// handlerEnforcedPassthroughCounter is incremented whenever a field-derived
// (handler-enforced) rule is passed through at the gateway after its coarse
// checks, leaving the exact-object decision to the daemon handler (gibson#1245).
var handlerEnforcedPassthroughCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "extauthz_handler_enforced_passthrough_total",
		Help: "Requests passed through at the gateway because the rule's FGA object " +
			"derives from a request body field the gateway cannot see; the daemon " +
			"handler makes the exact-object decision (gibson#1245).",
	},
	[]string{"method"},
)

// Prometheus counter incremented for every RPC that has no registry entry.
var unmappedRPCCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "extauthz_unmapped_rpc_total",
		Help: "Number of RPCs that had no FGA registry entry (default-denied).",
	},
	[]string{"method"},
)

// Prometheus counter incremented when a caller's identity class is not in
// the entry's AllowedIdentities bitfield.
var identityClassDeniedCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "extauthz_identity_class_denied_total",
		Help: "Requests denied because the caller's identity class is not in AllowedIdentities.",
	},
	[]string{"method"},
)

// Prometheus counter incremented for every self-mode decision.
// label result={allow,deny}. Spec: self-mode-authz.
var selfModeDecisionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "extauthz_self_mode_decisions_total",
		Help: "Decisions made by the self-mode authz path (skips FGA Check).",
	},
	[]string{"result"},
)

// entryMode returns a string tag identifying the authorization mode for an
// Entry. Used in structured-log entry_mode fields. Spec: self-mode-authz.
func entryMode(e Entry) string {
	switch {
	case e.Self:
		return "self"
	case e.Unauthenticated:
		return "unauthenticated"
	default:
		return "rule"
	}
}

// handlerEnforced reports whether an entry's FGA object is derived from a
// request BODY field the gateway cannot see — the `from_field('x')` and
// `tenant_and_field('x')` derivers. Envoy's ext_authz check carries the request
// line and headers, not the decoded protobuf body, so the field has no value at
// the gateway and the exact-object question cannot be formed here.
//
// For these rules ext-authz runs only the coarse checks (identity class here;
// tenant cross-check and revocation in the server) and passes the request
// through; the daemon handler holds the decoded body and makes the per-resource
// decision in exactly one place (gibson#1245, owner decision option 1).
//
// The marker is the GENERATED deriver kind itself — the same string
// authz-registry-gen emits from the proto annotation. There is no separate
// registry field and nothing is hand-annotated: a rule is handler-enforced iff
// its object is body-field-derived, which is a property of the deriver, not a
// flag that could drift from it.
func handlerEnforced(entry Entry) bool {
	return strings.HasPrefix(entry.ObjectDeriver, "from_field") ||
		strings.HasPrefix(entry.ObjectDeriver, "tenant_and_field")
}

// FGAClient is the narrow interface the Checker needs from the OpenFGA SDK client.
// Declared as an interface so tests can inject a stub without standing up a real
// FGA server. *fgaclient.OpenFgaClient satisfies this interface.
type FGAClient interface {
	Check(ctx context.Context) fgaclient.SdkClientCheckRequestInterface
}

// Checker performs OpenFGA authorization checks for incoming RPCs.
type Checker struct {
	fga FGAClient
	reg *Registry
}

// NewChecker constructs a Checker. Both fgaClient and reg are required.
func NewChecker(fgaClient FGAClient, reg *Registry) *Checker {
	if fgaClient == nil {
		panic("fga.NewChecker: fgaClient must not be nil")
	}
	if reg == nil {
		panic("fga.NewChecker: registry must not be nil")
	}
	return &Checker{fga: fgaClient, reg: reg}
}

// callerClass derives the caller's IdentityClass from the Identity's
// CredentialType string. The mapping is:
//
//   - "oidc-user"            → IdentityUser (1)
//   - "client-credentials"   → IdentityService (2)
//   - "capability-grant"     → IdentityComponent (4)
//   - "platform-operator"    → IdentityPlatformOperator (8)
//
// Unknown types map to 0 (NONE), which will fail the bitfield check for
// any annotated RPC — safe fail-closed behaviour.
func callerClass(identity headers.Identity) IdentityClass {
	switch identity.CredentialType {
	case headers.CredentialOIDCUser:
		return IdentityUser
	case headers.CredentialClientCredentials:
		return IdentityService
	case headers.CredentialCapabilityGrant:
		// A component authenticated by its self-signed CG-JWT (ADR-0045).
		return IdentityComponent
	case "platform-operator":
		return IdentityPlatformOperator
	default:
		return 0 // NONE — deny-all
	}
}

// checkIdentityClass validates that callerCls is permitted by allowed.
// Returns a non-nil error (suitable for structured log emission) on denial.
//
// Treats allowed == 0 defensively as deny-all per Req 2.3: the SDK codegen
// guarantees this never happens for annotated RPCs, but the runtime layer is
// defensive. Single source of truth called from both rule-mode and self-mode
// paths. Spec: self-mode-authz.
func (c *Checker) checkIdentityClass(method string, callerCls, allowed IdentityClass) error {
	if allowed == 0 {
		return fmt.Errorf("identity-class not in allowed_identities: AllowedIdentities=0 (deny-all) for %q", method)
	}
	if allowed&callerCls == 0 {
		return fmt.Errorf("identity-class not in allowed_identities: caller=%s allowed=%s method=%q",
			callerCls.String(), allowed.String(), method)
	}
	return nil
}

// Check performs an OpenFGA authorization check for the given gRPC method and
// identity. requestMetadata carries key/value pairs extracted from the incoming
// request (e.g. "tenant", "mission_definition_id") for use by object resolvers.
//
// Returns:
//   - (true, nil)  — FGA allowed the request.
//   - (false, nil) — FGA denied, or the RPC has no registry entry (default-deny),
//     or the caller's identity class is not in AllowedIdentities.
//   - (false, err) — FGA returned an infrastructure error.
//
// When the method is not in the registry a Prometheus counter is incremented and
// (false, nil) is returned immediately without calling FGA.
func (c *Checker) Check(ctx context.Context, method string, identity headers.Identity, requestMetadata map[string]string) (bool, error) {
	entry, found := c.reg.Lookup(method)
	if !found {
		unmappedRPCCounter.WithLabelValues(method).Inc()
		return false, nil
	}

	// Unauthenticated RPCs pass through without an FGA call.
	if entry.Unauthenticated {
		slog.Debug("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
		)
		return true, nil
	}

	// Self-mode: authenticated user reading their own data. Skip FGA.
	// Three-step enforcement: empty subject → Unauthenticated;
	// identity-class mismatch → PermissionDenied; else → OK.
	// Spec: self-mode-authz Req 3.2, 3.3, 3.4.
	if entry.Self {
		if identity.Subject == "" {
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "empty subject",
			)
			selfModeDecisionsTotal.WithLabelValues("deny").Inc()
			return false, nil
		}
		callerCls := callerClass(identity)
		if err := c.checkIdentityClass(method, callerCls, entry.AllowedIdentities); err != nil {
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "identity-class not in allowed_identities",
				"caller_class", callerCls.String(),
				"allowed", entry.AllowedIdentities.String(),
			)
			identityClassDeniedCounter.WithLabelValues(method).Inc()
			selfModeDecisionsTotal.WithLabelValues("deny").Inc()
			return false, nil
		}
		slog.Debug("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
		)
		selfModeDecisionsTotal.WithLabelValues("allow").Inc()
		return true, nil
	}

	// AllowedIdentities bitfield enforcement (Req 2.1, 2.3, 2.4).
	// This check runs before FGA so a mis-classed caller can never
	// exploit a matching FGA tuple for a different identity class.
	callerCls := callerClass(identity)
	if err := c.checkIdentityClass(method, callerCls, entry.AllowedIdentities); err != nil {
		slog.Info("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "deny",
			"reason", "identity-class not in allowed_identities",
		)
		identityClassDeniedCounter.WithLabelValues(method).Inc()
		return false, nil
	}

	// Handler-enforced rules: the object derives from a request body field the
	// gateway cannot see. The coarse checks above (identity class) and around
	// this call (tenant cross-check, revocation) have run; the exact-object
	// decision is the daemon handler's, which holds the decoded body. Pass
	// through here rather than deny-unresolvable so the decision is made in
	// exactly one place (gibson#1245). Placed AFTER the identity-class check so
	// a mis-classed caller is still denied at the edge.
	if handlerEnforced(entry) {
		handlerEnforcedPassthroughCounter.WithLabelValues(method).Inc()
		slog.Info("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
			"reason", "handler-enforced (field-derived object); daemon handler decides",
			"deriver", entry.ObjectDeriver,
		)
		return true, nil
	}

	// Derive the FGA user string. SPIFFE IDs include "://" which OpenFGA's
	// user-ID validator rejects ("malformed user field"); strip the scheme so
	// "spiffe://zeroroot.ai/platform/dashboard" becomes
	// "user:zeroroot.ai/platform/dashboard". Non-SPIFFE issuers (e.g. UUID
	// subjects from the configured OIDC IdP) are passed through unchanged.
	// The matching transformation runs in the fga-init Job that seeds
	// platform_operator tuples.
	user := "user:" + strings.TrimPrefix(identity.Subject, "spiffe://")
	if callerCls == IdentityComponent {
		// A component's Subject is already the typed FGA principal ref the
		// daemon asserted in the key descriptor (e.g. "agent_principal:<acct>",
		// ADR-0045) — the model rejects the `user:` type for these principals,
		// so use it verbatim as the FGA user.
		user = identity.Subject
	}

	// Derive the FGA object from the registry entry's resolver and request metadata.
	// A rule whose object cannot be resolved has no question to ask FGA, and an
	// unanswerable question is a deny — never a broader object that might match a
	// tuple the rule did not intend.
	object, err := resolveObject(entry, identity, requestMetadata)
	if err != nil {
		if errors.Is(err, ErrObjectUnresolvable) {
			objectUnresolvableCounter.WithLabelValues(method).Inc()
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "object unresolvable",
				"deriver", entry.ObjectDeriver,
				"err", err.Error(),
			)
			return false, nil
		}
		return false, fmt.Errorf("fga: object resolution failed for %q: %w", method, err)
	}

	resp, err := c.fga.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     user,
		Relation: entry.Relation,
		Object:   object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga: Check RPC failed for %q: %w", method, err)
	}

	if resp.Allowed == nil {
		slog.Debug("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "deny",
			"reason", "fga nil allowed",
		)
		return false, nil
	}
	result := "deny"
	if *resp.Allowed {
		result = "allow"
	}
	slog.Debug("authz decision",
		"method", method,
		"entry_mode", entryMode(entry),
		"result", result,
	)
	return *resp.Allowed, nil
}

// CanInvokeTool checks whether agentID holds the can_invoke relation on toolID
// within the given tenant. This is a direct FGA check that bypasses the RPC
// registry — it is used by the Capability Grant minter, which is an internal
// operation rather than an inbound gRPC method.
//
// Returns (true, nil) on ALLOW, (false, nil) on DENY, and (false, err) on
// infrastructure failure.
func (c *Checker) CanInvokeTool(ctx context.Context, agentID, toolID, tenant string) (bool, error) {
	if agentID == "" || toolID == "" || tenant == "" {
		return false, fmt.Errorf("fga.CanInvokeTool: agentID, toolID, and tenant are all required")
	}

	resp, err := c.fga.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     "agent:" + agentID,
		Relation: "can_invoke",
		Object:   "tool:" + toolID,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga.CanInvokeTool: FGA Check RPC failed: %w", err)
	}
	if resp.Allowed == nil {
		return false, nil
	}
	return *resp.Allowed, nil
}

// CheckPlatformOperator checks whether subject holds the platform_operator
// relation on system_tenant:_system. This is a direct FGA query that bypasses
// the RPC registry and identity-class bitfield — it is used exclusively by
// the tenant cross-check gate in the ext-authz server (Req 4.2) to verify
// that a headerOnly cross-tenant request comes from an authorised operator.
//
// Returns (true, nil) on ALLOW, (false, nil) on DENY, and (false, err) on
// infrastructure failure.
func (c *Checker) CheckPlatformOperator(ctx context.Context, subject string) (bool, error) {
	if subject == "" {
		return false, fmt.Errorf("fga.CheckPlatformOperator: subject must not be empty")
	}
	user := "user:" + strings.TrimPrefix(subject, "spiffe://")
	resp, err := c.fga.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     user,
		Relation: "platform_operator",
		Object:   "system_tenant:_system",
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga.CheckPlatformOperator: FGA Check RPC failed: %w", err)
	}
	if resp.Allowed == nil {
		return false, nil
	}
	return *resp.Allowed, nil
}

// CheckPlatformOperator delegates to the inner Checker's CheckPlatformOperator.
// The result is NOT cached (cross-tenant operator checks are rare and their
// invalidation would need separate tooling; correctness trumps perf here).
func (c *CachedChecker) CheckPlatformOperator(ctx context.Context, subject string) (bool, error) {
	return c.inner.CheckPlatformOperator(ctx, subject)
}

// CheckActiveSession performs the instant-revocation gate for a human
// JWT-bearing request (gibson#627 slice 3). It checks:
//
//	(user:<subject>, active_session, tenant:<tenant>)
//
// with condition context {"token_issued_at": <RFC3339 UTC>}, relying on the
// OpenFGA model condition:
//
//	condition token_not_revoked(token_issued_at: timestamp, revoked_at: timestamp) {
//	    token_issued_at > revoked_at
//	}
//
// The result is NOT cached. Caching is intentionally omitted for this check:
// the condition is evaluated per RFC3339-serialised iat value (token-specific),
// so two requests from the same user with different tokens would require
// distinct cache keys. More importantly, correctness requires that a revocation
// propagates within the FGA cache TTL (≤30 s) — caching the gate's "allowed"
// result at the ext-authz level would let a revoked token continue to pass for
// up to another TTL window after the next slice's push-invalidation arrives.
// The FGA network round-trip for this uncached call is within budget: the
// per-call timeout floor from platform-clients applies, and active_session is a
// hot path that benefits from FGA's in-process LRU.
//
// ENFORCEMENT CONTRACT: this method assumes the backfill from slice 2 has run
// (every active user has a (user:X, active_session, tenant:Y) tuple with the
// epoch revoked_at). Deny-on-absent is intentional: a missing tuple means the
// user has not been provisioned through the new path and the request should fail
// closed. The safe rollout order is: run slice 2 backfill BEFORE this code is
// deployed.
//
// Returns (true, nil) on ALLOW, (false, nil) on DENY, and (false, err) on
// infrastructure failure.
func (c *Checker) CheckActiveSession(ctx context.Context, subject, tenant string, tokenIssuedAt time.Time) (bool, error) {
	if subject == "" || tenant == "" {
		return false, errors.New("fga.CheckActiveSession: subject and tenant are required")
	}
	user := "user:" + strings.TrimPrefix(subject, "spiffe://")
	// RFC3339 with UTC timezone is the condition parameter format agreed with
	// the FGA model (slice 1). The model receives it as a `timestamp` type and
	// compares > with revoked_at. Using UTC ensures no timezone-offset ambiguity.
	iatStr := tokenIssuedAt.UTC().Format(time.RFC3339)
	condCtx := map[string]interface{}{
		"token_issued_at": iatStr,
	}
	resp, err := c.fga.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     user,
		Relation: "active_session",
		Object:   "tenant:" + tenant,
		Context:  &condCtx,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga.CheckActiveSession: FGA Check RPC failed: %w", err)
	}
	if resp.Allowed == nil {
		sessionGateDeniedCounter.Inc()
		slog.Info("extauthz.session_gate_denied",
			"subject", subject,
			"tenant", tenant,
			"token_issued_at", iatStr,
			"reason", "fga_nil_allowed",
		)
		return false, nil
	}
	if !*resp.Allowed {
		sessionGateDeniedCounter.Inc()
		slog.Info("extauthz.session_gate_denied",
			"subject", subject,
			"tenant", tenant,
			"token_issued_at", iatStr,
			"reason", "fga_deny",
		)
	}
	return *resp.Allowed, nil
}

// CheckActiveSession delegates to the inner Checker's CheckActiveSession.
// The result is deliberately NOT cached — see Checker.CheckActiveSession for
// the full rationale. Every human-JWT request pays one uncached FGA round-trip
// for the session gate; the per-call timeout from platform-clients applies.
func (c *CachedChecker) CheckActiveSession(ctx context.Context, subject, tenant string, tokenIssuedAt time.Time) (bool, error) {
	return c.inner.CheckActiveSession(ctx, subject, tenant, tokenIssuedAt)
}

// userSessionProbeIAT is a token_issued_at value far enough in the future that
// it post-dates every real revoked_at. CheckUserSession uses it to probe
// whether the user-scoped active_session tuple EXISTS at all, independent of
// revocation: a present tuple always satisfies `probe_iat > revoked_at` (allow),
// an absent tuple never does (deny). That is what lets the gate tell a
// genuinely-first sign-in (no tuple → bootstrap → allow) apart from a revoked
// session (tuple present, real iat fails the condition → deny).
const userSessionProbeIAT = "9999-12-31T23:59:59Z"

// CheckUserSession performs the USER-SCOPED instant-revocation gate for a
// tenant-less human JWT request (gibson#1244). It checks:
//
//	(user:<subject>, active_session, user:<subject>)
//
// against the same token_not_revoked condition as CheckActiveSession, but with
// INVERTED absent-tuple semantics:
//
//   - Tuple present, condition satisfied (iat > revoked_at) → ALLOW (valid).
//   - Tuple present, condition failed (iat <= revoked_at)   → DENY  (revoked).
//   - Tuple ABSENT                                          → ALLOW (bootstrap).
//
// The absent-tuple ALLOW is the crucial difference from the tenant-scoped gate,
// which fails closed on absence. A tenant-less request is the sign-in bootstrap
// window: a user who has not been provisioned into any tenant yet legitimately
// has no user-scoped tuple, and denying them would make sign-in unrecoverable
// (exactly why the residual was left open before this change). A caller who
// DOES have a tuple and presents a token issued at or before revoked_at is
// denied — that is the exposure gibson#1244 closes.
//
// OpenFGA's Check cannot itself distinguish "absent" from "condition-false":
// both return allowed=false. CheckUserSession disambiguates with a second Check
// that re-evaluates the same tuple under a far-future iat (userSessionProbeIAT).
// The common valid-session path takes ONE round-trip (the first Check allows);
// only a revoked or a bootstrap request pays the second, disambiguating call.
//
// The result is NOT cached, for the same reasons as CheckActiveSession.
//
// Returns (true, nil) on ALLOW, (false, nil) on DENY, (false, err) on
// infrastructure failure.
func (c *Checker) CheckUserSession(ctx context.Context, subject string, tokenIssuedAt time.Time) (bool, error) {
	if subject == "" {
		return false, errors.New("fga.CheckUserSession: subject is required")
	}
	user := "user:" + strings.TrimPrefix(subject, "spiffe://")

	// 1. Evaluate the real token against the user-scoped tuple.
	allowed, err := c.checkUserSessionAt(ctx, user, tokenIssuedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	if allowed {
		// Tuple present and not revoked → valid session.
		return true, nil
	}

	// 2. Ambiguous deny. Distinguish an absent tuple (bootstrap → allow) from a
	//    present-but-revoked tuple (→ deny) by probing existence under a
	//    far-future iat that post-dates any real revoked_at.
	present, err := c.checkUserSessionAt(ctx, user, userSessionProbeIAT)
	if err != nil {
		return false, err
	}
	if present {
		// Tuple exists and the real token failed the condition → REVOKED.
		sessionGateDeniedCounter.Inc()
		slog.Info("extauthz.user_session_gate_denied",
			"subject", subject,
			"object", user,
			"token_issued_at", tokenIssuedAt.UTC().Format(time.RFC3339),
			"reason", "user_scoped_revoked",
		)
		return false, nil
	}
	// No user-scoped tuple → not yet provisioned → sign-in bootstrap → ALLOW.
	return true, nil
}

// checkUserSessionAt issues a single OpenFGA Check of the user-scoped
// active_session tuple with the given token_issued_at condition context. It is
// the shared primitive behind CheckUserSession's real-token check and its
// far-future existence probe.
func (c *Checker) checkUserSessionAt(ctx context.Context, user, iatStr string) (bool, error) {
	condCtx := map[string]interface{}{
		"token_issued_at": iatStr,
	}
	resp, err := c.fga.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     user,
		Relation: "active_session",
		Object:   user,
		Context:  &condCtx,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("fga.CheckUserSession: FGA Check RPC failed: %w", err)
	}
	if resp.Allowed == nil {
		return false, nil
	}
	return *resp.Allowed, nil
}

// CheckUserSession delegates to the inner Checker's CheckUserSession. The
// result is deliberately NOT cached — see Checker.CheckUserSession.
func (c *CachedChecker) CheckUserSession(ctx context.Context, subject string, tokenIssuedAt time.Time) (bool, error) {
	return c.inner.CheckUserSession(ctx, subject, tokenIssuedAt)
}

// resolveObject derives the FGA object string for the given entry.
//
// Note on the field derivers (from_field / tenant_and_field): Check and
// CachedChecker.Check short-circuit those rules via handlerEnforced BEFORE
// calling resolveObject, so their branch here is not reached on the gateway
// path — the daemon handler makes the per-resource decision (gibson#1245). The
// branch is retained as the fail-closed answer for any direct caller: a
// field-derived object the gateway cannot form is ErrObjectUnresolvable (a
// deny), never a widened tenant-scoped object.
//
// Object derivers from the SDK annotation:
//   - "tenant_from_identity"   — "<object_type>:" + tenant from identity
//   - "system_tenant"          — "<object_type>:_system"  (object_type
//     is typically "system_tenant" or "component")
//   - "from_field('<name>')"   — "<object_type>:" + req.<name>
//   - "tenant_and_field('<name>')" — "<object_type>:" + tenant + "/" + req.<name>
//     (tenant and field are joined with "/", never ":" — OpenFGA rejects a
//     colon inside an object id; see gibson#1024 and authz.TenantQualifiedSep)
//   - "component_from_identity" — "<object_type>:" + the component named by the
//     caller's own VERIFIED component_scope claim
//
// Spec: unified-identity-and-authorization Component B (object_deriver
// grammar) and Requirement 4.4.
func resolveObject(entry Entry, identity headers.Identity, meta map[string]string) (string, error) {
	switch entry.ObjectDeriver {
	case "tenant_from_identity":
		tenant := meta["tenant"]
		if tenant == "" {
			tenant = identity.Tenant
		}
		if tenant == "" {
			return "", fmt.Errorf("%w: tenant is empty for method %q (deriver=%q)",
				ErrObjectUnresolvable, entry.Method, entry.ObjectDeriver)
		}
		// Defensive de-prefix: an upstream caller (stale dashboard cookie,
		// older membership response, hand-crafted curl) may have already
		// FGA-prefixed the tenant value (`tenant:zeroroot-ai`). Adding the
		// prefix again gives `tenant:tenant:zeroroot-ai`, which OpenFGA
		// rejects with `validation_error: invalid 'object' field format` —
		// surfaces to ext-authz as a SDK-swallowed deny, no auditable trace
		// in the deny log line. Strip first; prepend always.
		tenant = strings.TrimPrefix(tenant, entry.ObjectType+":")
		return entry.ObjectType + ":" + tenant, nil

	case "component_from_identity":
		// The object is the component the caller IS — named by the
		// component_scope claim on its own Capability-Grant JWT, which
		// ext-authz signature-verified before this point (ADR-0045).
		//
		// The value comes from headers.Identity.ComponentScope and from
		// nowhere else: not from meta, not from a request header. Reading it
		// from the request would let a component nominate the object it is
		// authorized against, which is the same as having no check.
		//
		// Fail closed on absent, empty or malformed. There is deliberately no
		// fallback to "<object_type>:_system" — that global sentinel is the
		// over-broad object this deriver exists to replace, and falling back
		// to it would silently restore the behaviour. There is no fallback to
		// the tenant either: a tenant-wide object is one tuple covering every
		// component in the tenant (same reasoning as the field derivers
		// below).
		scope := identity.ComponentScope
		if scope == "" {
			return "", fmt.Errorf("%w: method %q (deriver=%q) needs a verified component_scope "+
				"claim, which this identity does not carry",
				ErrObjectUnresolvable, entry.Method, entry.ObjectDeriver)
		}
		// The claim is minted as "component:<name>" (capabilitygrant service)
		// whatever the row's object type is, so strip either spelling of the
		// type prefix before re-prefixing — the same defensive de-prefix
		// tenant_from_identity does above.
		name := strings.TrimPrefix(scope, entry.ObjectType+":")
		if name == scope {
			name = strings.TrimPrefix(name, componentScopeClaimPrefix)
		}
		if !validObjectID(name) {
			// The rejected value is NOT echoed into the error: it lands in
			// the deny log line, and an object id is exactly the kind of
			// value that should never be pasted into a log unvalidated.
			return "", fmt.Errorf("%w: method %q (deriver=%q) got a component_scope that is not "+
				"a usable object id", ErrObjectUnresolvable, entry.Method, entry.ObjectDeriver)
		}
		return entry.ObjectType + ":" + name, nil

	case "system_tenant":
		// Cross-tenant platform-operator rules. The codegen allowlist
		// (sdk/cmd/authz-registry-gen) only permits this single spelling;
		// emits "<object_type>:_system", which fga-init seeds tuples
		// against (e.g. "system_tenant:_system").
		return entry.ObjectType + ":_system", nil

	default:
		// from_field('name') and tenant_and_field('name') name a REQUEST
		// FIELD. The object is that field's value, so without the value
		// there is no object and no decision to make: this returns
		// ErrObjectUnresolvable and the caller denies.
		//
		// It must not fall back to the tenant-wide object. The three rules
		// that use a field deriver are the per-resource ones — a credential
		// by name, a plugin by name — and answering them with
		// "<type>:<tenant>" asks a question nobody wrote a tuple for
		// (writers use authz.SecretObject / authz.PluginObject, which are
		// tenant-QUALIFIED: "secret:tenant-<t>/<ref>", "plugin:<t>/<name>").
		// A tenant-wide answer is therefore either a deny in disguise or,
		// if such a tuple were ever written, one grant covering every
		// resource of that type in the tenant.
		tenant := meta["tenant"]
		if tenant == "" {
			tenant = identity.Tenant
		}
		if tenant == "" {
			return "", fmt.Errorf("%w: tenant is empty for method %q (deriver=%q)",
				ErrObjectUnresolvable, entry.Method, entry.ObjectDeriver)
		}
		field := strings.Trim(strings.TrimPrefix(strings.TrimPrefix(entry.ObjectDeriver, "tenant_and_field"), "from_field"), "()'\"")
		if v := meta[field]; v != "" {
			if strings.HasPrefix(entry.ObjectDeriver, "tenant_and_field") {
				// Join tenant and field using authz.TenantQualifiedSep — NOT ":".
				// OpenFGA rejects an object id that contains a colon ("invalid
				// 'object' field format") on both Write and Check, so
				// "type:tenant:field" is invalid. TenantQualifiedSep is the
				// single canonical separator shared by all writers and derivers
				// (gibson#1024). Using the canonical helpers here ensures deriver
				// and writers always agree.
				//
				// Secret objects use the "tenant-<slug>" convention (the "tenant-"
				// prefix is a fixed part of the object id, matching
				// authz.SecretObject and the daemon/operator writers — gibson#1035).
				// Plugin objects use the bare slug directly (authz.PluginObject).
				if entry.ObjectType == "secret" {
					return authz.SecretObjectFromDeriver(tenant, v), nil
				}
				return entry.ObjectType + ":" + tenant + authz.TenantQualifiedSep + v, nil
			}
			return entry.ObjectType + ":" + v, nil
		}
		return "", fmt.Errorf("%w: method %q (deriver=%q) needs request field %q, which is not "+
			"available to the gateway", ErrObjectUnresolvable, entry.Method, entry.ObjectDeriver, field)
	}
}

// componentScopeClaimPrefix is the canonical prefix the daemon mints onto a
// component_scope claim ("component:<name>", capabilitygrant.Service).
const componentScopeClaimPrefix = "component:"

// maxObjectIDLen bounds the id half of an FGA object reference. OpenFGA's own
// limit is larger; this is short enough that a component id stays a component
// id and cannot become a payload.
const maxObjectIDLen = 128

// validObjectID reports whether s is safe to use verbatim as the id half of an
// FGA object reference ("<type>:<id>").
//
// This is an allowlist, not a denylist: ASCII letters, digits, '.', '_', '-'
// and authz.TenantQualifiedSep ('/'). Everything else is rejected, which
// covers the characters that would change the MEANING of the reference rather
// than its value:
//
//   - ':' would inject a second type prefix — "component:" + "other:thing"
//     parses as a reference to a different type, and OpenFGA rejects the
//     three-part form outright ("invalid 'object' field format").
//   - '#' would turn the object into a userset reference ("type:id#relation").
//   - whitespace and control characters are rejected by OpenFGA and are the
//     usual log-injection vector on the way to the deny line.
//   - bytes >= 0x80 fail the ASCII ranges, so no non-ASCII homoglyph can
//     stand in for an allowed character.
func validObjectID(s string) bool {
	if s == "" || len(s) > maxObjectIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '/':
		default:
			return false
		}
	}
	return true
}
