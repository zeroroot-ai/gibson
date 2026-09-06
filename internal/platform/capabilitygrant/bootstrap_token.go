// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Capability-Grant bootstrap token (epic unified-cg-identity, ADR-0045,
// gibson#648).
//
// A freshly-enrolled component holds no Ed25519 host key and no daemon-acceptable
// token, yet it must authenticate its FIRST Capability-Grant registration. The
// bootstrap token solves that: enrollment mints a short-lived, daemon-signed JWT
// carrying the principal's identity, and the register endpoint verifies it with
// the daemon's own CG key. It is stateless (no DB lookup) and self-identifying —
// exactly what the SDK's single-`Authorization: Bearer <bootstrap>` register
// protocol needs. One credential mechanism for agent, tool, AND plugin.
const (
	// bootstrapTokenType is the JWS `typ` header distinguishing a bootstrap token
	// from a per-RPC CG-JWT (typ "JWT") or a host/agent registration JWT.
	bootstrapTokenType = "cg-bootstrap+jwt"

	// BootstrapTokenType is the exported JWS `typ` of a bootstrap token, so the
	// register endpoint can route by credential type (host+jwt vs bootstrap vs a
	// SPIFFE JWT-SVID, ADR-0066) before verification.
	BootstrapTokenType = bootstrapTokenType

	// bootstrapTokenAudience is the fixed `aud` for bootstrap tokens, so a
	// per-RPC CG-JWT can never be replayed at the register endpoint.
	bootstrapTokenAudience = "gibson:capabilitygrant:bootstrap"

	// defaultBootstrapTTL is the lifetime of a minted bootstrap token. Long
	// enough to enroll on one machine and register on another, short enough to
	// bound replay of a leaked one-time credential.
	defaultBootstrapTTL = time.Hour

	// maxBootstrapTTL caps a caller-requested TTL.
	maxBootstrapTTL = 24 * time.Hour

	// bootstrapScopeRegister is the one operation an enrollment credential
	// exists to authorize: a single capability-grant registration. Every minted
	// credential carries it and verification requires it, so a bootstrap
	// credential cannot be spent at some other daemon surface that also accepts
	// an EdDSA token signed by this key — the audience says where it may go, the
	// scope says what it may do once it arrives.
	bootstrapScopeRegister = "capabilitygrant:register"
)

// BootstrapClaims is the verified identity a bootstrap token carries. It is the
// full set the register endpoint needs to call RegisterCapabilityGrant without
// any further lookup.
type BootstrapClaims struct {
	// TenantID is the tenant the principal belongs to.
	TenantID string
	// OwnerUserID is the human owner whose FGA capabilities the grant resolves
	// against (the `sub` of the enrolling admin).
	OwnerUserID string
	// PrincipalID is the FGA principal id (e.g. "agent_principal:<userid>").
	PrincipalID string
	// Kind is the component kind: "agent", "tool", or "plugin".
	Kind string
	// Name is the component name.
	Name string
	// CapabilityCeiling is the OPTIONAL list of capability names
	// ("<verb>:<component>") this credential may produce grants for. It is the
	// credential's own ceiling, applied at registration ON TOP of the FGA
	// resolution — a capability absent from a non-empty ceiling is not granted
	// even when the principal and its enroller both hold it.
	//
	// An empty ceiling means "whatever the FGA resolution yields", which is the
	// component principal's own per-component grants intersected with its
	// enroller's reach (see ResolveComponentCapabilities). That is the safe
	// default; the ceiling exists so an enroller can issue a credential that is
	// narrower than its own reach, and so that widening the enroller's grants
	// after minting cannot widen a credential already in flight.
	//
	// bootstrapScopeRegister is structural and is NOT carried here: minting adds
	// it and verification requires it, so this field holds only the ceiling.
	CapabilityCeiling []string
}

// MintBootstrapToken signs a bootstrap token for the given principal.
//
// ttl <= 0 means "unspecified" and takes defaultBootstrapTTL. A ttl beyond
// maxBootstrapTTL is an ERROR, not a silent adjustment: the caller that asked
// for it goes on to tell its own caller when the credential expires, and a
// quietly shortened lifetime made that answer wrong — the credential died
// hours before the API said it would, with no way for anyone to see why.
//
// The minted credential always carries a `scope` claim: bootstrapScopeRegister,
// plus c.CapabilityCeiling when the caller sets one. A credential that says
// nothing about what it may become is one that becomes whatever its bearer's
// enroller can reach at the moment it is spent; the scope claim is where that
// stops being open-ended.
func (m *Minter) MintBootstrapToken(c BootstrapClaims, ttl time.Duration) (string, error) {
	if c.TenantID == "" || c.OwnerUserID == "" || c.PrincipalID == "" {
		return "", errors.New("capabilitygrant: MintBootstrapToken: tenant, owner, and principal are required")
	}
	if ttl > maxBootstrapTTL {
		return "", fmt.Errorf("capabilitygrant: MintBootstrapToken: ttl %s exceeds the %s maximum",
			ttl, maxBootstrapTTL)
	}
	if ttl <= 0 {
		ttl = defaultBootstrapTTL
	}
	// A space-delimited scope cannot represent an entry containing whitespace,
	// and an empty entry would round-trip as nothing at all. Both are refused at
	// the mint rather than silently dropped, so the ceiling the caller asked for
	// is the ceiling the credential carries.
	scope := make([]string, 0, len(c.CapabilityCeiling)+1)
	scope = append(scope, bootstrapScopeRegister)
	for _, entry := range c.CapabilityCeiling {
		if entry == "" || strings.ContainsAny(entry, " \t\r\n") {
			return "", fmt.Errorf("capabilitygrant: MintBootstrapToken: capability ceiling entry %q is empty or contains whitespace", entry)
		}
		scope = append(scope, entry)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":    m.issuer,
		"aud":    bootstrapTokenAudience,
		"sub":    c.PrincipalID,
		"tenant": c.TenantID,
		"owner":  c.OwnerUserID,
		"kind":   c.Kind,
		"name":   c.Name,
		"scope":  strings.Join(scope, " "),
		"iat":    now.Unix(),
		"exp":    now.Add(ttl).Unix(),
		"jti":    uuid.NewString(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = m.keyID()
	tok.Header["typ"] = bootstrapTokenType
	signed, err := tok.SignedString(m.keys.Current.priv)
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: MintBootstrapToken: sign: %w", err)
	}
	return signed, nil
}

// VerifyBootstrapToken validates a bootstrap token against the daemon's CG public
// key and returns its claims. It enforces the EdDSA algorithm, the bootstrap typ
// and audience, expiry, the presence of a jti, and the register scope — so
// neither a per-RPC CG-JWT nor a forged token is accepted at the register
// endpoint.
//
// Verification says the credential is authentic, never that it is still
// unspent. Single use is enforced where the identity is written, by consuming
// the credential in the same transaction as the host and agent rows: a check
// here would be a read that a concurrent registration could race past.
//
// Which key verifies is decided by the token's kid, resolved against the
// daemon's signing key set. During a rotation window that resolves the
// outgoing key too, so a bootstrap token minted before the rotation is still
// spendable for the rest of its life. A kid that is in neither slot — retired,
// or never ours — resolves to nothing and the token is refused.
func (m *Minter) VerifyBootstrapToken(tokenStr string) (*BootstrapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience(bootstrapTokenAudience),
		jwt.WithExpirationRequired(),
	)
	var claims jwt.MapClaims
	tok, err := parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := m.keys.Verifier(kid)
		if !ok {
			return nil, fmt.Errorf("unknown or retired signing key id %q", kid)
		}
		return ed25519.PublicKey(pub), nil
	})
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyBootstrapToken: %w", err)
	}
	if typ, _ := tok.Header["typ"].(string); typ != bootstrapTokenType {
		return nil, fmt.Errorf("capabilitygrant: VerifyBootstrapToken: unexpected typ %q, want %q", typ, bootstrapTokenType)
	}
	out := &BootstrapClaims{
		TenantID:    stringClaim(claims, "tenant"),
		OwnerUserID: stringClaim(claims, "owner"),
		PrincipalID: stringClaim(claims, "sub"),
		Kind:        stringClaim(claims, "kind"),
		Name:        stringClaim(claims, "name"),
	}
	if out.TenantID == "" || out.OwnerUserID == "" || out.PrincipalID == "" {
		return nil, errors.New("capabilitygrant: VerifyBootstrapToken: token missing tenant/owner/principal")
	}
	// Every credential this daemon mints carries a jti. Refusing one without it
	// keeps the credential individually identifiable in the audit trail.
	if stringClaim(claims, "jti") == "" {
		return nil, errors.New("capabilitygrant: VerifyBootstrapToken: token missing jti")
	}
	// The register scope must be present and is not part of the ceiling: a
	// credential that does not say it is for registering is not spent here.
	ceiling, registrable := splitBootstrapScope(stringClaim(claims, "scope"))
	if !registrable {
		return nil, fmt.Errorf("capabilitygrant: VerifyBootstrapToken: token scope does not include %q", bootstrapScopeRegister)
	}
	out.CapabilityCeiling = ceiling
	return out, nil
}

// splitBootstrapScope parses a space-delimited `scope` claim into the credential's
// capability ceiling, and reports whether the register scope is present.
func splitBootstrapScope(scope string) (ceiling []string, registrable bool) {
	for _, entry := range strings.Fields(scope) {
		if entry == bootstrapScopeRegister {
			registrable = true
			continue
		}
		ceiling = append(ceiling, entry)
	}
	return ceiling, registrable
}

func stringClaim(m jwt.MapClaims, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
