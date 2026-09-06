// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Issuer returns the iss claim the Minter stamps on every grant.
func (m *Minter) Issuer() string { return m.issuer }

// Audience returns the aud claim the Minter stamps on every grant.
func (m *Minter) Audience() string { return m.audience }

// PublicKeyByID returns the Ed25519 public key that signs under kid, when kid
// is the current or the previous key of the set. Any other kid, including one
// that names a registered component key, returns ok=false. NewMinter always
// loads a key set, so a constructed Minter always has one.
func (m *Minter) PublicKeyByID(kid string) (ed25519.PublicKey, bool) {
	for _, k := range m.keys.publicKeys() {
		if k.kid == kid {
			return k.pub, true
		}
	}
	return nil, false
}

// LocalVerifier verifies daemon-minted task grants in the daemon process,
// against the Minter's own key set. It is the in-process counterpart of the
// ext-authz cgjwt.Verifier: same SDK claim validation, no key fetch. The daemon
// uses it where a handler must read the claims of the grant a request carries,
// such as RenewCapabilityGrant and the harness callback scope check
// (gibson#1605).
type LocalVerifier struct {
	minter func() *Minter
}

// ErrNoSigningKey is returned when a verification is attempted before the
// daemon has loaded its signing key. It is an error rather than a pass-through:
// a grant nobody can verify is refused, never trusted.
var ErrNoSigningKey = errors.New("capabilitygrant: the daemon has no signing key yet, so a grant cannot be verified")

// NewLocalVerifier builds a LocalVerifier over the Minter that get returns.
//
// It takes a getter, not a Minter, because the daemon builds its Minter during
// Start, after the subsystems that need a verifier are assembled. Reading it
// per call is the only way to reach it.
//
// It returns no error. There is one way to misuse it — a nil source — and the
// answer is the same as "the key does not exist yet": every Verify refuses with
// ErrNoSigningKey. An error return would add a branch every caller must handle
// and none could ever reach.
func NewLocalVerifier(get func() *Minter) *LocalVerifier {
	if get == nil {
		get = func() *Minter { return nil }
	}
	return &LocalVerifier{minter: get}
}

// Verify parses and signature-checks token and returns its claims. Only the
// Minter's own keys are accepted, so a component-signed token is refused with
// ErrUnknownKey.
func (v *LocalVerifier) Verify(ctx context.Context, token string) (sdkcg.Claims, error) {
	m := v.minter()
	if m == nil {
		return sdkcg.Claims{}, ErrNoSigningKey
	}
	claims, err := sdkcg.Verify(ctx, minterKeys{m}, token, sdkcg.VerifyOptions{
		ExpectedIssuer:   m.Issuer(),
		ExpectedAudience: m.Audience(),
	})
	if err != nil {
		return sdkcg.Claims{}, fmt.Errorf("capabilitygrant: verify task grant: %w", err)
	}
	return claims, nil
}

// minterKeys adapts the Minter's key set to the SDK's JWKSFetcher.
type minterKeys struct{ m *Minter }

func (k minterKeys) Fetch(_ context.Context, kid string) (any, error) {
	pub, ok := k.m.PublicKeyByID(kid)
	if !ok {
		return nil, fmt.Errorf("kid %q is not a daemon signing key", kid)
	}
	return pub, nil
}
