package fga

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
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
	object, err := resolveObject(entry, identity, requestMetadata)
	if err != nil {
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

// resolveObject derives the FGA object string for the given entry.
//
// Object derivers from the SDK annotation:
//   - "tenant_from_identity"   — "<object_type>:" + tenant from identity
//   - "system_tenant"          — "<object_type>:_system"  (object_type
//     is typically "system_tenant" or "component")
//   - "from_field('<name>')"   — "<object_type>:" + req.<name>
//   - "tenant_and_field('<name>')" — "<object_type>:" + tenant + ":" + req.<name>
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
			return "", fmt.Errorf("tenant is empty for method %q (deriver=%q)", entry.Method, entry.ObjectDeriver)
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

	case "system_tenant":
		// Cross-tenant platform-operator rules. The codegen allowlist
		// (sdk/cmd/authz-registry-gen) only permits this single spelling;
		// emits "<object_type>:_system", which fga-init seeds tuples
		// against (e.g. "system_tenant:_system").
		return entry.ObjectType + ":_system", nil

	default:
		// from_field('name') and tenant_and_field('name') derivers
		// require the request body field; ext-authz needs the proto
		// descriptor to extract it. Until the descriptor-aware
		// derivation lands, fall back to tenant-from-identity for
		// from_field-style derivers so default-deny is not
		// trivially defeated. tenant_and_field appends the field
		// when present; otherwise it degrades to tenant-only.
		tenant := meta["tenant"]
		if tenant == "" {
			tenant = identity.Tenant
		}
		if tenant == "" {
			return "", fmt.Errorf("tenant is empty for method %q (deriver=%q)", entry.Method, entry.ObjectDeriver)
		}
		// from_field('x') and tenant_and_field('x') extract `x` from
		// requestMetadata when the caller provides it; the gateway is
		// responsible for populating these from the request body when
		// available (the existing pipeline forwards x-gibson-* headers
		// to this metadata).
		field := strings.Trim(strings.TrimPrefix(strings.TrimPrefix(entry.ObjectDeriver, "tenant_and_field"), "from_field"), "()'\"")
		if v := meta[field]; v != "" {
			if strings.HasPrefix(entry.ObjectDeriver, "tenant_and_field") {
				// Join tenant and field with "/" — NOT ":". OpenFGA rejects an
				// object id that contains a colon ("invalid 'object' field
				// format") on both Write and Check, so "type:tenant:field" is
				// invalid. Must match authz.PluginObject and the daemon/operator
				// writers (authz.TenantQualifiedSep). See gibson#1024.
				return entry.ObjectType + ":" + tenant + "/" + v, nil
			}
			return entry.ObjectType + ":" + v, nil
		}
		// No field in metadata — fall back to tenant scoping rather
		// than fail-open.
		return entry.ObjectType + ":" + tenant, nil
	}
}
