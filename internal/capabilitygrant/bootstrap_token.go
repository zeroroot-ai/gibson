package capabilitygrant

import (
	"crypto/ed25519"
	"errors"
	"fmt"
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

	// bootstrapTokenAudience is the fixed `aud` for bootstrap tokens, so a
	// per-RPC CG-JWT can never be replayed at the register endpoint.
	bootstrapTokenAudience = "gibson:capabilitygrant:bootstrap"

	// defaultBootstrapTTL is the lifetime of a minted bootstrap token. Long
	// enough to enroll on one machine and register on another, short enough to
	// bound replay of a leaked one-time credential.
	defaultBootstrapTTL = time.Hour

	// maxBootstrapTTL caps a caller-requested TTL.
	maxBootstrapTTL = 24 * time.Hour
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
}

// MintBootstrapToken signs a bootstrap token for the given principal. ttl <= 0
// uses defaultBootstrapTTL; ttl is capped at maxBootstrapTTL.
func (m *Minter) MintBootstrapToken(c BootstrapClaims, ttl time.Duration) (string, error) {
	if c.TenantID == "" || c.OwnerUserID == "" || c.PrincipalID == "" {
		return "", errors.New("capabilitygrant: MintBootstrapToken: tenant, owner, and principal are required")
	}
	if ttl <= 0 || ttl > maxBootstrapTTL {
		ttl = defaultBootstrapTTL
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":       m.issuer,
		"aud":       bootstrapTokenAudience,
		"sub":       c.PrincipalID,
		"tenant":    c.TenantID,
		"owner":     c.OwnerUserID,
		"kind":      c.Kind,
		"name":      c.Name,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"jti":       uuid.NewString(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = m.keyID
	tok.Header["typ"] = bootstrapTokenType
	signed, err := tok.SignedString(m.priv)
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: MintBootstrapToken: sign: %w", err)
	}
	return signed, nil
}

// VerifyBootstrapToken validates a bootstrap token against the daemon's CG public
// key and returns its claims. It enforces the EdDSA algorithm, the bootstrap typ
// and audience, and expiry — so neither a per-RPC CG-JWT nor a forged token is
// accepted at the register endpoint.
func (m *Minter) VerifyBootstrapToken(tokenStr string) (*BootstrapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience(bootstrapTokenAudience),
		jwt.WithExpirationRequired(),
	)
	var claims jwt.MapClaims
	tok, err := parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return ed25519.PublicKey(m.pub), nil
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
	return out, nil
}

func stringClaim(m jwt.MapClaims, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
