package jwtsource

import (
	"context"
	"fmt"
)

// StaticJWTSource is a JWTSource that always returns the same configured
// token string, regardless of audience. It is intended ONLY for tests —
// the broker_init_vault_auth tests use it to inject a known JWT value
// without spinning up a SPIRE Workload API server.
//
// Production callers MUST use SPIREJWTSource (jwtsource/spire.go;
// wired in PR gibson#169).
type StaticJWTSource struct {
	// FixedToken is returned by every Token() call. If empty, Token()
	// returns an explicit error rather than silently producing an empty
	// JWT (which would mislead Vault into rejecting the login with a
	// confusing "jwt is required" error).
	FixedToken string
}

// Token returns FixedToken or an error if FixedToken is empty.
func (s *StaticJWTSource) Token(_ context.Context, _ string) (string, error) {
	if s == nil || s.FixedToken == "" {
		return "", fmt.Errorf("jwtsource (static): no fixed token configured")
	}
	return s.FixedToken, nil
}

// AudienceCapturingJWTSource is a test-only JWTSource that records the
// audience supplied on each Token call. Tests use it to assert the
// daemon's broker init passes the correct GIBSON_DAEMON_VAULT_JWT_AUDIENCE
// down to the source.
//
// Concurrency note: tests should access RecordedAudiences only after the
// goroutine that called Token has returned. The captured slice is not
// guarded.
type AudienceCapturingJWTSource struct {
	StaticJWTSource
	RecordedAudiences []string
}

// Token records the audience and returns the embedded StaticJWTSource's
// FixedToken (or its error).
func (s *AudienceCapturingJWTSource) Token(ctx context.Context, audience string) (string, error) {
	s.RecordedAudiences = append(s.RecordedAudiences, audience)
	return s.StaticJWTSource.Token(ctx, audience)
}
