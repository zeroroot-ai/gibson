package capabilitygrant

import "context"

// VerifyHostJWT authenticates a RE-registration (gibson#648, ADR-0045): a
// component that already holds a registered Ed25519 host key signs a host+jwt
// (typ "host+jwt", iss = host id) instead of a one-time bootstrap token. It
// delegates to the package JWTVerifier (which looks the host up by iss, requires
// it active, verifies the signature against the stored host key, and checks
// typ/alg/aud/expiry) so the register handler can re-issue a Capability Grant for
// the existing identity — the returned HostClaims carries the host's tenant,
// owner, and FGA principal.
//
// expectedAud is the daemon's register-endpoint URL (the value the discovery
// document advertises and the SDK signs the host+jwt against).
func (s *CapabilityGrantService) VerifyHostJWT(ctx context.Context, token, expectedAud string) (*HostClaims, error) {
	return NewJWTVerifier(s.store).VerifyHostJWT(ctx, token, expectedAud)
}
