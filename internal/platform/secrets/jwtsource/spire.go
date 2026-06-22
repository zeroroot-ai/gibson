package jwtsource

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// DefaultSPIRESocketPath is the canonical UDS path the SPIRE agent exposes
// on every gibson pod (mounted from the spire-agent-socket DaemonSet via a
// shared HostPath volume in the chart). It matches the path SPIRE itself
// uses for SDS/Workload API by default. The chart wires this via a Volume
// + VolumeMount on the gibson statefulset; if the operator changes the
// socket path they must also set GIBSON_DAEMON_SPIRE_SOCKET on the gibson
// container.
const DefaultSPIRESocketPath = "unix:///run/spire/sockets/api.sock"

// jwtSVIDFetcher is the minimal slice of *workloadapi.JWTSource used by
// SPIREJWTSource. It exists so tests can mock the JWT-SVID fetch path
// without spinning up a SPIRE Workload API server.
//
// The real *workloadapi.JWTSource satisfies this interface as-is — see
// NewSPIREJWTSource for how the real source is plumbed in.
type jwtSVIDFetcher interface {
	FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
}

// jwtSVIDCloser is jwtSVIDFetcher + Close. The real
// *workloadapi.JWTSource implements both; mocks may pass io.Closer-style
// no-ops. Splitting it lets the test path supply a non-Closeable mock when
// Close is irrelevant.
type jwtSVIDCloser interface {
	jwtSVIDFetcher
	Close() error
}

// SPIREJWTSource is the production JWTSource implementation. It wraps a
// long-lived *workloadapi.JWTSource (a managed JWT-SVID source with
// transparent rotation provided by the SPIFFE SDK) and adapts its
// FetchJWTSVID + Marshal calls to the narrow JWTSource interface defined
// in source.go.
//
// Lifecycle: a single SPIREJWTSource is constructed at daemon startup
// (cmd/gibson/main.go) and Close()d during the daemon's graceful shutdown
// chain. It is safe for concurrent use across goroutines — the
// AuthCache refresh closures call Token from multiple goroutines.
//
// Failure mode: NewSPIREJWTSource is fail-fast at boot. If the Workload
// API socket is unreachable (no spire-agent socket mounted, wrong path,
// daemon started before SPIRE rotated the first SVID), construction
// returns an error and the daemon exits. There is no silent fallback to
// DisabledJWTSource — that would let the daemon come up but fail every
// AuthMethodJWT broker refresh with a confusing per-tenant error.
//
// Spec: ADR-0009 + amendment (docs#33, docs#34); gibson#167 PRD;
// gibson#169.
type SPIREJWTSource struct {
	src jwtSVIDCloser
}

// NewSPIREJWTSource opens a SPIRE Workload API JWT source against
// socketPath. If socketPath is empty, it defaults to
// DefaultSPIRESocketPath. The call blocks until the Workload API has
// pushed the first JWT bundle update (workloadapi.NewJWTSource semantics)
// or the context is cancelled.
//
// The returned source must be Close()d when no longer in use, by the
// daemon's graceful-shutdown chain.
//
// Spec: ADR-0009 amendment (docs#34); gibson#169.
func NewSPIREJWTSource(ctx context.Context, socketPath string) (*SPIREJWTSource, error) {
	if socketPath == "" {
		socketPath = DefaultSPIRESocketPath
	}
	src, err := workloadapi.NewJWTSource(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(socketPath),
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"jwtsource (spire): open SPIRE Workload API JWT source at %s: %w "+
				"(GIBSON_DAEMON_SPIRE_SOCKET overrides the default; the chart "+
				"must mount the spire-agent socket on the gibson pod — "+
				"spec: ADR-0009 amendment, deploy#354)",
			socketPath, err)
	}
	return &SPIREJWTSource{src: src}, nil
}

// Token mints a fresh JWT-SVID for the given audience via the SPIRE
// Workload API. It implements jwtsource.JWTSource. The returned string is
// the marshaled JWT suitable for stamping onto sdkvault.Config.Auth.JWT.
//
// Concurrency: safe for concurrent use; the underlying
// *workloadapi.JWTSource is goroutine-safe.
//
// Error path: any failure from the Workload API (socket unreachable,
// SPIRE agent dropped the connection, audience refused) is wrapped with
// the audience name so operators can grep for "audience=foo" in daemon
// logs. The minted token is never included in any error message, log
// field, or other observable surface (per the JWTSource contract).
func (s *SPIREJWTSource) Token(ctx context.Context, audience string) (string, error) {
	if s == nil || s.src == nil {
		return "", errors.New("jwtsource (spire): source is not initialized")
	}
	if audience == "" {
		// Belt-and-suspenders: the daemon's broker init helper guards
		// this too (stampVaultJWTOnConfig), but a future caller that
		// skips that helper would otherwise mint an audience-less JWT
		// that Vault rejects with a generic 400.
		return "", errors.New("jwtsource (spire): audience must be non-empty (GIBSON_DAEMON_VAULT_JWT_AUDIENCE)")
	}
	svid, err := s.src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", fmt.Errorf("jwtsource (spire): FetchJWTSVID audience=%q: %w", audience, err)
	}
	tok := svid.Marshal()
	if tok == "" {
		// Defense-in-depth: a SPIRE Workload API that returned a
		// success-but-empty token would otherwise propagate as a
		// silent empty Auth.JWT that Vault rejects with a confusing
		// "jwt is required" error.
		return "", fmt.Errorf("jwtsource (spire): FetchJWTSVID audience=%q returned empty token", audience)
	}
	return tok, nil
}

// Close releases the underlying SPIRE Workload API connection. The
// daemon's graceful-shutdown chain owns this lifecycle; callers MUST NOT
// share a SPIREJWTSource across daemon lifecycles.
func (s *SPIREJWTSource) Close() error {
	if s == nil || s.src == nil {
		return nil
	}
	return s.src.Close()
}
