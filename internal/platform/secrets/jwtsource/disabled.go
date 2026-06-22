package jwtsource

import "context"

// DisabledJWTSource is the JWTSource that returns ErrJWTSourceDisabled on
// every call. It is the daemon's default JWTSource until cmd/gibson/main.go
// is patched (in PR gibson#169) to wire SPIREJWTSource instead.
//
// The point of having a DisabledJWTSource rather than a nil JWTSource is
// to make the failure mode loud and self-describing — a nil source would
// produce a generic nil-pointer dereference at refresh time, while
// DisabledJWTSource produces ErrJWTSourceDisabled (which the AuthCache
// surfaces via VaultRefreshError) pointing the operator straight at the
// missing wiring.
//
// Production callers must replace this with SPIREJWTSource once gibson#169
// merges.
type DisabledJWTSource struct{}

// Token always returns ErrJWTSourceDisabled.
func (DisabledJWTSource) Token(_ context.Context, _ string) (string, error) {
	return "", ErrJWTSourceDisabled
}
