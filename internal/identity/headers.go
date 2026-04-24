// Package identity reads and verifies the canonical x-gibson-identity-* header
// set that the Envoy ext_authz sidecar signs on every authenticated request.
//
// # Canonical HMAC string (must mirror core/ext-authz/internal/headers/signer.go)
//
//	subject + "\n" + issuer + "\n" + credential-type + "\n" + tenant + "\n" + issued-at-unix-seconds
//
// tenant is empty string when not set; field always present. issued-at is decimal
// Unix seconds. Signature is lowercase hex HMAC-SHA256.
//
// # Tenant context helpers
//
// TenantFromContext and ContextWithTenant are the sole tenant-resolution API
// for the daemon after the auth package is removed. All code that previously
// called auth.TenantFromContext / auth.ContextWithTenant now uses these.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"
)

// identityTraceEnabled gates the [identity-debug] printf statements.
// Set GIBSON_IDENTITY_TRACE=1 to enable; default is off so production logs
// are not polluted.  The e2e test and `make signup-trace` set this env var
// for the daemon pod so the log tailer can capture the structured output.
var identityTraceEnabled = os.Getenv("GIBSON_IDENTITY_TRACE") == "1"

// SystemTenant is the reserved tenant identifier for platform-hosted shared
// components. API keys scoped to SystemTenant grant access to the _system
// component namespace (plugins available to every tenant).
const SystemTenant = "_system"

// crossTenantIssuers lists the identity issuers whose callers are permitted to
// operate across tenant boundaries. "spire" identifies platform-operator
// workloads authenticated by SPIFFE/SPIRE X.509 SVIDs.
var crossTenantIssuers = []string{"spire"}

// tenantContextKey is the unexported context key for the active tenant.
type tenantContextKey struct{}

// actingUserContextKey is the unexported context key for the acting user ID
// (the end-user on whose behalf the dashboard is acting).
type actingUserContextKey struct{}

// TenantFromContext resolves the active tenant for the current request.
//
// Precedence (highest to lowest):
//  1. Explicit tenant stored in context via ContextWithTenant.
//  2. Identity.Tenant field from the verified HMAC header set.
//  3. SystemTenant (platform/service identities that carry no tenant).
func TenantFromContext(ctx context.Context) string {
	if ctx == nil {
		return SystemTenant
	}
	if v, ok := ctx.Value(tenantContextKey{}).(string); ok && v != "" {
		return v
	}
	if id, err := IdentityFromContext(ctx); err == nil && id.Tenant != "" {
		return id.Tenant
	}
	return SystemTenant
}

// ContextWithTenant stores tenantID in ctx for later retrieval by TenantFromContext.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// ActingUserFromContext returns the acting user ID stored by ContextWithActingUser,
// and true if set. The acting user is the end user on whose behalf the dashboard
// (a platform-service caller) is acting.
func ActingUserFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(actingUserContextKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// ContextWithActingUser stores the acting user ID in ctx.
func ContextWithActingUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actingUserContextKey{}, userID)
}

// initiatorUserContextKey is the unexported context key for the mission
// initiator: the user who triggered the mission. Stable across the entire
// mission lifetime — including sub-agent delegation, scheduled runs, and
// checkpoint/resume — so span attribution follows the spend, not the code.
type initiatorUserContextKey struct{}

// executorUserContextKey is the unexported context key for the currently
// executing agent's owner. Differs from the initiator when a parent agent
// delegates to a sub-agent whose component is owned by a different user.
type executorUserContextKey struct{}

// InitiatorUserFromContext returns the mission initiator's user ID stored by
// ContextWithInitiatorUser, and true if set. The initiator is the human (or
// API-key owner) who triggered the mission; it remains stable across every
// span in the mission tree — including sub-agent delegation.
func InitiatorUserFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(initiatorUserContextKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// ContextWithInitiatorUser stores the initiator user ID in ctx. Called once
// at mission start from MissionAuthzState.UserID so every descendant span
// inherits it via context.
func ContextWithInitiatorUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, initiatorUserContextKey{}, userID)
}

// ExecutorUserFromContext returns the executing agent's owner user ID stored
// by ContextWithExecutorUser, and true if set. May differ from the initiator
// when a parent agent delegates to a sub-agent owned by a different user.
func ExecutorUserFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(executorUserContextKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// ContextWithExecutorUser stores the executing agent's owner user ID in ctx.
// Set at sub-agent dispatch time to preserve attribution through delegation.
func ContextWithExecutorUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, executorUserContextKey{}, userID)
}

// IsCrossTenantCaller returns true when the identity belongs to a workload
// that is permitted to operate across tenant boundaries. The signal is the
// identity issuer: "spire" identifies platform-operator services authenticated
// via SPIFFE/SPIRE X.509 SVIDs.
func IsCrossTenantCaller(id Identity) bool {
	return slices.Contains(crossTenantIssuers, id.Issuer)
}

// TenantScopedRedisKey generates a tenant-scoped Redis key in the canonical
// format "tenant:{tenant}:{key}".
func TenantScopedRedisKey(tenant, key string) string {
	return fmt.Sprintf("tenant:%s:%s", tenant, key)
}

// componentScopeContextKey is the context key for the component scope string.
type componentScopeContextKey struct{}

// ContextWithComponentScope stores the component scope in ctx. The scope
// identifies the agent/tool that submitted the request via capability grant.
func ContextWithComponentScope(ctx context.Context, scope string) context.Context {
	if scope == "" {
		return ctx
	}
	return context.WithValue(ctx, componentScopeContextKey{}, scope)
}

// ComponentScopeFromContext returns the component scope (e.g.,
// "component:agent-abc123") if the request was authenticated via a capability
// grant, or empty string otherwise. The FGA batch-check branches on this value
// to use the component-scoped relation variants.
func ComponentScopeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(componentScopeContextKey{}).(string); ok {
		return v
	}
	return ""
}

const (
	hSubject        = "x-gibson-identity-subject"
	hIssuer         = "x-gibson-identity-issuer"
	hCredentialType = "x-gibson-identity-credential-type"
	hTenant         = "x-gibson-identity-tenant"
	hIssuedAt       = "x-gibson-identity-issued-at"
	hSignature      = "x-gibson-identity-signature"
)

// Identity carries the verified identity fields injected by the Envoy filter chain.
type Identity struct {
	Subject        string
	Issuer         string    // "zitadel" | "spire" | "apikey" | "capability-grant"
	CredentialType string    // "oidc" | "mtls" | "apikey"
	Tenant         string    // empty for non-zitadel issuers
	IssuedAt       time.Time // second precision
}

type ctxKey struct{}

func require(h http.Header, name string) (string, error) {
	if v := h.Get(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("identity: missing %s", name)
}

// IdentityFromHeaders reads x-gibson-identity-* headers, HMAC-verifies them,
// and returns a typed Identity. secret MUST NOT be logged by the caller.
func IdentityFromHeaders(secret []byte, h http.Header) (Identity, error) {
	subject, err := require(h, hSubject)
	if err != nil {
		return Identity{}, err
	}
	issuer, err := require(h, hIssuer)
	if err != nil {
		return Identity{}, err
	}
	credType, err := require(h, hCredentialType)
	if err != nil {
		return Identity{}, err
	}
	issuedAtRaw, err := require(h, hIssuedAt)
	if err != nil {
		return Identity{}, err
	}
	gotSig, err := require(h, hSignature)
	if err != nil {
		return Identity{}, err
	}
	issuedAtSec, err := strconv.ParseInt(issuedAtRaw, 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: malformed %s: %w", hIssuedAt, err)
	}
	tenant := h.Get(hTenant)
	canonical := subject + "\n" + issuer + "\n" + credType + "\n" + tenant + "\n" + strconv.FormatInt(issuedAtSec, 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(gotSig), []byte(expected)) != 1 {
		if identityTraceEnabled {
			// DEBUG: dump raw inputs to diagnose ext-authz vs daemon mismatch.
			// Gated behind GIBSON_IDENTITY_TRACE=1 so production logs stay clean.
			// The e2e test sets this env var on the daemon pod and scrapes these
			// lines via daemon_log_tailer.go to assert B15/B16 are not regressing.
			fmt.Printf("[identity-debug] HMAC mismatch:\n"+
				"  subject=%q issuer=%q credType=%q tenant=%q issuedAt=%d\n"+
				"  canonical_hex=%x\n"+
				"  gotSig=%s\n  expected=%s (REDACTED — presence only)\n"+
				"  secret_len=%d\n",
				subject, issuer, credType, tenant, issuedAtSec,
				canonical,
				gotSig, "[redacted]",
				len(secret))
		}
		return Identity{}, errors.New("identity: HMAC signature mismatch")
	}
	if issuer == "zitadel" && tenant == "" {
		return Identity{}, errors.New("identity: tenant required when issuer is zitadel")
	}
	return Identity{Subject: subject, Issuer: issuer, CredentialType: credType, Tenant: tenant, IssuedAt: time.Unix(issuedAtSec, 0).UTC()}, nil
}

// IdentityFromContext retrieves the Identity placed by the interceptor.
// Returns an error if called outside the interceptor chain.
func IdentityFromContext(ctx context.Context) (Identity, error) {
	if v, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return v, nil
	}
	return Identity{}, errors.New("identity: not present in context")
}

// WithIdentity stores id on ctx. Called by the interceptor.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}
