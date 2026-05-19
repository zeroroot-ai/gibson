// Package jwtsource provides the daemon-side seam for minting JWT bearer
// tokens that authenticate the daemon to downstream secret stores (today:
// HashiCorp Vault's auth/jwt mount).
//
// Architectural context — ADR-0009 (docs#33 + #34):
//
// The daemon authenticates to Vault via the auth/jwt mount, NOT via
// auth/kubernetes (TokenReview-based auth was forbidden by the
// jwt-spiffe-everywhere ADR; the SDK constant AuthMethodKubernetes was
// removed in sdk#81 and the daemon's mirror handler in gibson#170).
//
// Per-tenant Vault roles are written by the tenant-operator
// (tenant-operator#148) as gibson-plugin-<tenant_id> with bound_audiences =
// [<GIBSON_VAULT_JWT_BOUND_AUDIENCE>]. The role name carries the tenant
// scoping; the daemon supplies that role name when authenticating.
//
// The SPIRE Workload API mints the JWT-SVID per audience. SPIRE JWT-SVIDs
// do not naturally carry per-workload custom claims like gibson_tenant,
// so tenant isolation is enforced at the daemon's FGA layer rather than
// at the Vault role's bound_claims block. One daemon SPIFFE identity
// can request tokens against many tenant roles; the daemon is the
// trusted intermediary.
//
// The JWTSource interface is the single seam through which the daemon
// obtains those SPIRE-minted JWT-SVIDs. The concrete implementation
// (SPIREJWTSource) lives in spire.go and is wired in cmd/gibson/main.go
// (PR2 — gibson#169). In tests, callers use StaticJWTSource.
//
// Spec: gibson#167 PRD; ADR-0009 amendment (docs#34).
package jwtsource

import (
	"context"
	"errors"
)

// JWTSource mints a JWT bearer token for a configured audience. The token
// returned is a fully-marshaled JWT string suitable for stamping onto
// sdkvault.Config.Auth.JWT before calling sdkvault.New or
// sdkvault.RefreshToken.
//
// The interface is intentionally narrow: callers supply only an audience,
// and the source decides everything else (which SPIRE socket, which
// SPIFFE identity, what claims). This keeps the daemon's secret-broker
// init code free of SPIFFE/SPIRE specifics, and makes the seam trivial
// to mock in tests.
//
// Implementations must be safe for concurrent use across goroutines —
// the daemon's AuthCache may invoke Token from multiple refresh closures
// concurrently.
type JWTSource interface {
	// Token returns a freshly-minted JWT for the given audience. The
	// audience MUST match the bound_audiences set on the destination
	// service's auth role (today: a Vault auth/jwt role written by
	// tenant-operator#148). The implementation is responsible for any
	// caching, renewal, or error retry; callers treat each call as
	// independent.
	//
	// The returned token MUST NOT appear in any error message, log
	// field, or other observable surface — callers only ever hash it.
	Token(ctx context.Context, audience string) (string, error)
}

// ErrJWTSourceDisabled is returned by DisabledJWTSource.Token. It signals
// that the daemon was started without a real JWTSource — a real source
// is required to authenticate to Vault via the auth/jwt mount. Callers
// (specifically: the Vault AuthCache refresh closure) treat this error
// as a refresh failure and surface it via VaultRefreshError so the
// per-tenant config can be diagnosed.
//
// This is the default state when cmd/gibson/main.go has not yet wired a
// SPIREJWTSource (gibson#169) — i.e. between PR #168 merging and PR #169
// merging, all tenants whose broker config selects AuthMethodJWT will
// receive a clear error pointing at the missing source.
var ErrJWTSourceDisabled = errors.New("jwtsource: no JWT source configured; the daemon cannot authenticate to Vault via auth/jwt until a SPIRE JWT-SVID source is wired (gibson#169)")
