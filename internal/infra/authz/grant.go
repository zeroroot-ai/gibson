package authz

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Grant is the post-validation projection of a daemon-minted
// capability-grant JWT. It carries the claims internal services need
// downstream: who minted it, who it covers, what mission task it
// applies to, and when it stops being valid.
type Grant struct {
	// Issuer is the iss claim — the daemon's CG authority URL.
	Issuer string

	// Subject is the sub claim — the agent / tool / plugin
	// principal that presents the grant.
	Subject string

	// Audience is the aud claim — the daemon identifier the grant
	// is targeted at.
	Audience []string

	// IssuedAt is the iat claim, in UTC.
	IssuedAt time.Time

	// NotBefore is the nbf claim, in UTC. The grant is not valid
	// before this instant.
	NotBefore time.Time

	// ExpiresAt is the exp claim, in UTC. The grant is not valid
	// at or after this instant.
	ExpiresAt time.Time

	// ID is the jti claim — a per-grant unique identifier used by
	// the daemon to revoke individual grants.
	ID string
}

// Sentinel errors for VerifyCapabilityGrant. Callers distinguish
// expired from not-yet-valid for telemetry and from signature failures
// for security alerting.
var (
	// ErrGrantExpired fires when exp <= now.
	ErrGrantExpired = errors.New("authz: capability grant expired")

	// ErrGrantNotYetValid fires when nbf > now.
	ErrGrantNotYetValid = errors.New("authz: capability grant not yet valid")

	// ErrGrantSignature fires for a signature mismatch or unknown
	// kid.
	ErrGrantSignature = errors.New("authz: capability grant signature invalid")

	// ErrGrantMalformed fires for any other parse / structural
	// failure.
	ErrGrantMalformed = errors.New("authz: capability grant malformed")
)

// VerifyCapabilityGrant parses and validates a capability-grant JWT
// against the supplied JWKS public-key set. The set is the caller's
// responsibility to fetch and cache (see ext-authz/internal/cgjwt for
// a reference HTTP+TTL fetcher). All standard time claims are
// validated; the per-method scope claim is intentionally NOT enforced
// here so the same primitive can serve ext-authz (which evaluates
// scope against the FGA registry) and the daemon (which evaluates it
// against its own model).
//
// Time-of-check is time.Now().UTC(); tests inject a fixed time by
// constructing tokens with the appropriate nbf/exp around now.
func VerifyCapabilityGrant(token string, publicKeys jwk.Set) (Grant, error) {
	if token == "" {
		return Grant{}, fmt.Errorf("%w: empty token", ErrGrantMalformed)
	}
	if publicKeys == nil || publicKeys.Len() == 0 {
		return Grant{}, fmt.Errorf("%w: empty public-key set", ErrGrantMalformed)
	}

	// Step 1: parse + signature-verify against the key set. Disable
	// the library's validation so we can map each claim failure to a
	// specific sentinel below.
	tok, err := jwt.ParseString(
		token,
		jwt.WithKeySet(publicKeys),
		jwt.WithValidate(false),
	)
	if err != nil {
		// jwx returns wrapping errors for signature, kid-unknown,
		// and parse failures all through ParseString. We treat any
		// of these as a signature-class failure unless it is plainly
		// a malformed-input case (the substring check is the best
		// we can do; jwx does not expose typed parse-vs-sig errors
		// at this layer).
		if isStructuralParseError(err) {
			return Grant{}, fmt.Errorf("%w: %w", ErrGrantMalformed, err)
		}
		return Grant{}, fmt.Errorf("%w: %w", ErrGrantSignature, err)
	}

	now := time.Now().UTC()

	// Step 2: time-window validation. nbf and exp are evaluated
	// individually so the caller learns which one failed.
	if !tok.Expiration().IsZero() && !tok.Expiration().After(now) {
		return Grant{}, fmt.Errorf("%w: exp=%s now=%s", ErrGrantExpired, tok.Expiration().UTC(), now)
	}
	if !tok.NotBefore().IsZero() && tok.NotBefore().After(now) {
		return Grant{}, fmt.Errorf("%w: nbf=%s now=%s", ErrGrantNotYetValid, tok.NotBefore().UTC(), now)
	}

	return Grant{
		Issuer:    tok.Issuer(),
		Subject:   tok.Subject(),
		Audience:  tok.Audience(),
		IssuedAt:  tok.IssuedAt().UTC(),
		NotBefore: tok.NotBefore().UTC(),
		ExpiresAt: tok.Expiration().UTC(),
		ID:        tok.JwtID(),
	}, nil
}

// isStructuralParseError tells signature-class errors apart from
// malformed-token errors. We can't pattern-match the underlying error
// types because jwx wraps them through several layers; the best
// available signal is the message contents.
func isStructuralParseError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	switch {
	case containsAny(msg,
		"failed to parse",
		"invalid compact",
		"invalid JWT",
		"invalid JWS",
		"unexpected end of JSON",
		"failed to split",
		"empty token",
	):
		return true
	default:
		return false
	}
}

// containsAny is a small helper to keep the predicate above readable.
func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		// Case-insensitive substring match: jwx error messages are
		// stable in casing but tests should not be fragile if that
		// changes upstream.
		if indexFold(haystack, n) >= 0 {
			return true
		}
	}
	return false
}

// indexFold is a tiny case-insensitive substring search. We avoid
// strings.ToLower allocations on the hot path; this function is only
// called when an error is already returned, so allocation budget is
// not a concern, but writing it explicitly keeps the dependency
// surface obvious.
func indexFold(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(haystack) < len(needle) {
		return -1
	}
	hlow := toLowerASCII(haystack)
	nlow := toLowerASCII(needle)
	for i := 0; i+len(nlow) <= len(hlow); i++ {
		if hlow[i:i+len(nlow)] == nlow {
			return i
		}
	}
	return -1
}

// toLowerASCII lowercases a string assuming ASCII; sufficient for
// matching jwx error messages.
func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
