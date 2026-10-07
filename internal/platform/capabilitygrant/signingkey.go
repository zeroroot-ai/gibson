// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

// Dedicated CG-JWT signing keys, and the rotation window that makes them
// rotatable (GHSA-3957-8wcf-929q).
//
// Before this file the Ed25519 signing key was HKDF-derived from the master
// KEK. Two things followed from that, and both were defects:
//
//   - The signing key had no lifecycle of its own. Rotating it meant rotating
//     the master KEK, which re-encrypts every credential the platform holds —
//     so in practice it was never rotated.
//   - Whoever held the master KEK could mint capability grants. One secret
//     covered both "read the stored credentials" and "forge a token", when
//     those are different powers with different blast radii.
//
// The signing key is now its own secret with its own path, delivered the same
// way every other daemon secret is (OpenBao -> External Secrets -> a projected
// Secret volume; ADR-0023 put the daemon on file mounts rather than the K8s
// API). The KEK is not consulted for it.
//
// A rotation is not a cutover, it is a window (ADR-0171, row
// platform-signing-keys). The set carries a `current` key that signs, an
// optional `next` key that only verifies, and an optional `previous` key that
// only verifies. The openbao-auto-init sidecar of the chart runs the rotation:
//
//  1. It writes `next`. Each daemon replica publishes the new kid before any
//     replica signs with it.
//  2. It moves `current` to `previous` and `next` to `current`, in this
//     order of writes: `previous` = old, then `current` = new, then `next`
//     cleared. Each slot is its own OpenBao key and an ESO refresh can read
//     between two writes, and with this order each state in between holds
//     both kids. The new key signs, and tokens already in flight (a CG-JWT
//     lives up to 30 minutes, a bootstrap token up to 24 hours) keep
//     verifying against `previous`.
//  3. It clears `previous` after the longest token life. The daemon then
//     refuses a token of that kid. ext-authz caches a daemon key by kid for
//     EXT_AUTHZ_CGJWT_TTL (1 hour by default), so ext-authz refuses it at
//     most that long after step 3.
//
// The daemon reads the mount again when it changes (Minter.WatchSigningKeys),
// so a rotation needs no restart. The published key documents carry each kid
// of the set, so a verifier that fetches by kid resolves any of them.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrSigningKeyNotProvisioned reports that the dedicated signing-key mount is
// absent. It is distinguishable from a malformed mount on purpose: an absent
// mount is the pre-migration state and the caller may fall back to the legacy
// KEK derivation, whereas a mount that is present but unreadable is an
// operator error that must not be papered over with a different key.
var ErrSigningKeyNotProvisioned = errors.New("capabilitygrant: no dedicated CG signing key provisioned")

// Mount file names. `current` is required. `next` and `previous` are optional
// and present only during a rotation. An optional slot whose two files are both
// absent or both empty is no key: the chart projects each slot always, and an
// empty slot is the steady state.
const (
	currentKeyIDFile  = "current.kid"
	currentSeedFile   = "current.key"
	previousKeyIDFile = "previous.kid"
	previousSeedFile  = "previous.key"
	nextKeyIDFile     = "next.kid"
	nextSeedFile      = "next.key"
)

// SigningKey is one Ed25519 CG signing keypair together with the kid that
// names it in the published key documents.
type SigningKey struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// KeyID returns the kid this key is published and stamped under.
func (k SigningKey) KeyID() string { return k.keyID }

// Public returns the verifying half.
func (k SigningKey) Public() ed25519.PublicKey { return k.pub }

// NewSigningKey builds a signing key from a kid and a 32-byte Ed25519 seed.
func NewSigningKey(keyID string, seed []byte) (SigningKey, error) {
	if keyID == "" {
		return SigningKey{}, errors.New("capabilitygrant: signing key id required")
	}
	if len(seed) != ed25519.SeedSize {
		return SigningKey{}, fmt.Errorf("capabilitygrant: signing key %q: seed must be %d bytes, got %d",
			keyID, ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return SigningKey{
		keyID: keyID,
		priv:  priv,
		pub:   priv.Public().(ed25519.PublicKey),
	}, nil
}

// SigningKeySet is the signing key the daemon mints with, plus the key it will
// still verify but no longer sign with.
//
// Only Current signs. Next and Previous only verify. Next exists so that each
// replica publishes a new kid before any replica signs with it. Previous exists
// so that a rotation has an overlap window instead of invalidating every live
// token the instant the kid changes. A kid that is in no slot is retired:
// Verifier returns nothing for it and the token it signed is refused.
type SigningKeySet struct {
	Current  SigningKey
	Previous *SigningKey
	Next     *SigningKey

	// derivedFromMasterKEK marks a set that was derived from the master KEK
	// rather than read from the dedicated mount. It exists so the daemon can
	// say so at startup — see Minter.DerivedFromMasterKEK.
	derivedFromMasterKEK bool
}

// DerivedFromMasterKEK reports whether this set came from the legacy master-KEK
// derivation rather than from a dedicated signing key.
func (s *SigningKeySet) DerivedFromMasterKEK() bool { return s != nil && s.derivedFromMasterKEK }

// Verifier returns the public key published under kid, and whether kid names a
// key this daemon still honours.
//
// An empty kid resolves to Current. A token predating kid headers can only have
// been signed by the key in force at the time, and treating it as Current is
// exactly what the single-key implementation did; it is not a new acceptance.
func (s *SigningKeySet) Verifier(kid string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	if kid == "" || kid == s.Current.keyID {
		return s.Current.pub, true
	}
	for _, k := range s.verifyOnly() {
		if kid == k.keyID {
			return k.pub, true
		}
	}
	return nil, false
}

// verifyOnly returns the keys that verify and do not sign: next, then previous.
func (s *SigningKeySet) verifyOnly() []SigningKey {
	var out []SigningKey
	if s.Next != nil {
		out = append(out, *s.Next)
	}
	if s.Previous != nil {
		out = append(out, *s.Previous)
	}
	return out
}

// KeyIDs returns the kids this daemon honours, current first.
func (s *SigningKeySet) KeyIDs() []string {
	if s == nil {
		return nil
	}
	out := []string{s.Current.keyID}
	for _, k := range s.verifyOnly() {
		out = append(out, k.keyID)
	}
	return out
}

// publicKeys returns the verifying halves in publication order, current first.
func (s *SigningKeySet) publicKeys() []publishedKey {
	if s == nil {
		return nil
	}
	out := []publishedKey{{kid: s.Current.keyID, pub: s.Current.pub}}
	for _, k := range s.verifyOnly() {
		out = append(out, publishedKey{kid: k.keyID, pub: k.pub})
	}
	return out
}

// publishedKey pairs a kid with the public key published under it.
type publishedKey struct {
	kid string
	pub ed25519.PublicKey
}

// LoadSigningKeySetFromDir reads the dedicated signing-key mount at dir.
//
// The mount is a projected Secret volume:
//
//	<dir>/current.kid    the kid minted tokens are stamped with   (required)
//	<dir>/current.key    its 32-byte Ed25519 seed                 (required)
//	<dir>/next.kid       the incoming kid, verify only            (optional)
//	<dir>/next.key       its 32-byte Ed25519 seed                 (optional)
//	<dir>/previous.kid   the outgoing kid, verify only            (optional)
//	<dir>/previous.key   its 32-byte Ed25519 seed                 (optional)
//
// The rotation steps are at the top of this file. Nothing re-encrypts and the
// master KEK is untouched.
//
// The sidecar writes each slot as its own OpenBao key, so a refresh can show
// one step half done: `next` and `current`, or `current` and `previous`, can
// hold the same key for one refresh. A slot that holds the same kid and the
// same seed as an earlier slot is that same key and is dropped. A slot that
// reuses a kid with a different seed is an error.
//
// An empty dir, or a dir with no current key in it, returns
// ErrSigningKeyNotProvisioned. Anything else wrong with the mount is an error:
// a half-written or corrupt key must stop the load rather than silently
// selecting different key material.
func LoadSigningKeySetFromDir(dir string) (*SigningKeySet, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, ErrSigningKeyNotProvisioned
	}
	kid, err := readMountedString(filepath.Join(dir, currentKeyIDFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrSigningKeyNotProvisioned
	}
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: read %s: %w", currentKeyIDFile, err)
	}
	seed, err := readMountedSeed(filepath.Join(dir, currentSeedFile))
	if errors.Is(err, os.ErrNotExist) {
		// The kid is there and the key is not. That is a broken mount, not an
		// unprovisioned one: falling back to the KEK here would silently sign
		// under a kid whose published key is about to be something else.
		return nil, fmt.Errorf("capabilitygrant: signing key id %q present but %s is missing", kid, currentSeedFile)
	}
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: read %s: %w", currentSeedFile, err)
	}
	current, err := NewSigningKey(kid, seed)
	if err != nil {
		return nil, err
	}
	set := &SigningKeySet{Current: current}
	seen := []SigningKey{current}

	next, err := loadOptionalSlot(dir, nextKeyIDFile, nextSeedFile, seen)
	if err != nil {
		return nil, err
	}
	if next != nil {
		set.Next = next
		seen = append(seen, *next)
	}
	previous, err := loadOptionalSlot(dir, previousKeyIDFile, previousSeedFile, seen)
	if err != nil {
		return nil, err
	}
	set.Previous = previous
	return set, nil
}

// loadOptionalSlot reads one verify-only slot of the mount. It returns nil when
// the slot is empty, or when it holds a key that an earlier slot already holds.
func loadOptionalSlot(dir, kidFile, seedFile string, seen []SigningKey) (*SigningKey, error) {
	kid, kidPresent, err := readOptionalFile(filepath.Join(dir, kidFile))
	if err != nil {
		return nil, err
	}
	_, seedPresent, err := readOptionalFile(filepath.Join(dir, seedFile))
	if err != nil {
		return nil, err
	}
	switch {
	case !kidPresent && !seedPresent:
		return nil, nil // An empty slot: no rotation step uses it now.
	case !kidPresent:
		return nil, fmt.Errorf("capabilitygrant: %s holds a key and %s is empty or missing", seedFile, kidFile)
	case !seedPresent:
		return nil, fmt.Errorf("capabilitygrant: signing key id %q present but %s is empty or missing", kid, seedFile)
	}
	seed, err := readMountedSeed(filepath.Join(dir, seedFile))
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: read %s: %w", seedFile, err)
	}
	key, err := NewSigningKey(kid, seed)
	if err != nil {
		return nil, err
	}
	for _, other := range seen {
		if other.keyID != key.keyID {
			continue
		}
		if other.pub.Equal(key.pub) {
			return nil, nil // The same key in two slots: one rotation step is half done.
		}
		return nil, fmt.Errorf("capabilitygrant: key id %q of %s names a different key than an earlier slot; "+
			"a kid must name one key", kid, kidFile)
	}
	return &key, nil
}

// readOptionalFile reads a file of an optional slot. A missing file and a file
// that holds only white space are both absent. Any other read error is an error.
func readOptionalFile(path string) (text string, present bool, err error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied mount path
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("capabilitygrant: read %s: %w", filepath.Base(path), err)
	}
	text = strings.TrimSpace(string(raw))
	return text, text != "", nil
}

// readMountedString reads a single-line value from a projected Secret file.
func readMountedString(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied mount path
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: read %s: %w", path, err)
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("%s is empty", filepath.Base(path))
	}
	return v, nil
}

// readMountedSeed reads a 32-byte Ed25519 seed from a projected Secret file.
//
// The seed is accepted raw, base64 (standard or raw-URL), or hex, because the
// encoding depends on how the operator got it out of OpenBao and none of those
// forms is wrong. Whatever the encoding, it has to decode to exactly 32 bytes.
func readMountedSeed(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied mount path
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: read %s: %w", path, err)
	}
	if len(raw) == ed25519.SeedSize {
		return raw, nil
	}
	text := strings.TrimSpace(string(raw))
	if len(text) == ed25519.SeedSize {
		return []byte(text), nil
	}
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if seed, err := decode(text); err == nil && len(seed) == ed25519.SeedSize {
			return seed, nil
		}
	}
	return nil, fmt.Errorf("%s does not decode to a %d-byte ed25519 seed (raw, base64 and hex all tried)",
		filepath.Base(path), ed25519.SeedSize)
}
