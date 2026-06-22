// Package headers carries the Identity type and the helper that emits
// the canonical x-gibson-identity-* header set ext-authz adds to
// every authenticated upstream request.
//
// Channel security between Envoy and the daemon is provided by
// SPIFFE-pinned mTLS — the daemon's listener accepts only Envoy's
// specific peer SVID, so plain identity headers are trustworthy by
// virtue of the channel. HMAC signing has been removed (Req 8.2,
// zero-trust-hardening spec).
package headers

import (
	"net/http"
	"strconv"
	"time"
)

// Identity carries the verified claims emitted by ext-authz. The
// Tenant field is empty for non-OIDC-IdP issuers (system services that
// don't have a tenant scope by themselves).
type Identity struct {
	Subject        string
	Issuer         string // "oidc" (previously "zitadel" before the wire-format rename)
	CredentialType string // "oidc-user" | "client-credentials"
	Tenant         string
	IssuedAt       time.Time
}

// Header names emitted on every allowed request. They mirror the
// SDK's auth package constants; the SDK and ext-authz are pinned via
// SDK go.mod so a name change in the SDK propagates here on bump.
const (
	HeaderSubject        = "x-gibson-identity-subject"
	HeaderIssuer         = "x-gibson-identity-issuer"
	HeaderCredentialType = "x-gibson-identity-credential-type"
	HeaderTenant         = "x-gibson-identity-tenant"
	HeaderIssuedAt       = "x-gibson-identity-issued-at"
)

// Credential type values emitted in the HeaderCredentialType header.
// Mirror the SDK's auth.CredentialOIDCUser / auth.CredentialClientCredentials
// constants — kept as locally-defined strings to avoid widening the SDK
// import surface across the ext-authz package boundary.
const (
	CredentialOIDCUser          = "oidc-user"
	CredentialClientCredentials = "client-credentials"
	// CredentialCapabilityGrant is a component (agent/tool/plugin) that
	// authenticated with its self-signed Capability-Grant JWT (ADR-0045).
	// Mirrors the SDK's auth.CredentialCapabilityGrant.
	CredentialCapabilityGrant = "capability-grant"
)

// Issuer values emitted in the HeaderIssuer header. Mirror the SDK's
// auth.IssuerOIDC / auth.IssuerCapabilityGrant constants — the SDK's
// `auth/headers.go` accepts only this closed enum and rejects anything
// else with `auth: identity header invalid: unknown issuer`. The
// security-hardening R13 issuer-allowlist check belongs in ext-authz
// (verifying the JWT iss is on the allowlist BEFORE allowing the
// request), but the forwarded header value MUST be the canonical
// wire constant so the daemon SDK accepts it. See ext-authz#26.
const (
	IssuerOIDC            = "oidc"
	IssuerCapabilityGrant = "capability-grant"
)

// Emit returns the canonical x-gibson-identity-* header set for id.
// Used by the Envoy ext_authz Check handler to attach identity to the
// upstream request. Headers are NOT signed — channel trust is provided
// by SPIFFE mTLS between Envoy and the daemon.
func Emit(id Identity) http.Header {
	h := http.Header{}
	h.Set(HeaderSubject, id.Subject)
	h.Set(HeaderIssuer, id.Issuer)
	h.Set(HeaderCredentialType, id.CredentialType)
	h.Set(HeaderTenant, id.Tenant)
	h.Set(HeaderIssuedAt, strconv.FormatInt(id.IssuedAt.Unix(), 10))
	return h
}
