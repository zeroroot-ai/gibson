package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
	"google.golang.org/protobuf/proto"
)

// SignerKey is one Ed25519 keypair the Signer can sign and/or verify
// with. The Public half is required; Private may be nil for keys the
// Signer has been given solely for rotation-window verification.
type SignerKey struct {
	Kid     string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// ed25519Signer is the concrete Signer backed by crypto/ed25519.
// It holds a map of all known keys (active + any still-valid predecessors
// during rotation) and signs with the single key identified by activeKid.
type ed25519Signer struct {
	mu        sync.RWMutex
	keys      map[string]SignerKey // kid → key
	activeKid string
}

// Sentinel errors surfaced by Verify so callers can distinguish between
// a missing-key-for-kid problem (rotation miss) and a body-mismatch
// problem (tamper or corruption).
var (
	// ErrMissingSignature is returned when a manifest has no signature bytes.
	ErrMissingSignature = errors.New("manifest: signature missing")

	// ErrUnknownSigningKey is returned when manifest.signing_key_id names
	// a kid this Signer does not hold. Common during a rotation window
	// when a predecessor Signer hasn't yet been cycled out everywhere.
	ErrUnknownSigningKey = errors.New("manifest: unknown signing_key_id")

	// ErrBadSignature is returned when the signature verification fails.
	// Always treat this as a tamper signal — never retry.
	ErrBadSignature = errors.New("manifest: signature verification failed")
)

// NewSigner constructs an ed25519Signer from the supplied keys. activeKid
// identifies which key is used for new signatures; it must name a key
// whose Private half is set. All other keys may have Private=nil (verify-only).
func NewSigner(activeKid string, keys []SignerKey) (Signer, error) {
	if activeKid == "" {
		return nil, fmt.Errorf("manifest: activeKid is required")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("manifest: at least one signing key is required")
	}
	s := &ed25519Signer{
		keys:      make(map[string]SignerKey, len(keys)),
		activeKid: activeKid,
	}
	for _, k := range keys {
		if k.Kid == "" {
			return nil, fmt.Errorf("manifest: signing key is missing kid")
		}
		if len(k.Public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("manifest: signing key %q has invalid public key size", k.Kid)
		}
		if k.Private != nil && len(k.Private) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("manifest: signing key %q has invalid private key size", k.Kid)
		}
		s.keys[k.Kid] = k
	}
	active, ok := s.keys[activeKid]
	if !ok {
		return nil, fmt.Errorf("manifest: active kid %q not present in key set", activeKid)
	}
	if active.Private == nil {
		return nil, fmt.Errorf("manifest: active kid %q has no private key", activeKid)
	}
	return s, nil
}

// GenerateSignerKey produces a new Ed25519 keypair suitable for seeding
// NewSigner. Primarily used by tests; production key material is loaded
// from the daemon's secret store.
func GenerateSignerKey(kid string) (SignerKey, error) {
	if kid == "" {
		return SignerKey{}, fmt.Errorf("manifest: GenerateSignerKey kid required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SignerKey{}, fmt.Errorf("manifest: generate ed25519 keypair: %w", err)
	}
	return SignerKey{Kid: kid, Public: pub, Private: priv}, nil
}

// Sign clears m.Signature + m.SigningKeyId, deterministically marshals
// the body, signs with the active key, and sets the fields. Any later
// mutation of m invalidates the signature.
func (s *ed25519Signer) Sign(m *manifestpb.CapabilityManifest) error {
	if m == nil {
		return fmt.Errorf("manifest: Sign: nil manifest")
	}
	s.mu.RLock()
	active, ok := s.keys[s.activeKid]
	kid := s.activeKid
	s.mu.RUnlock()
	if !ok || active.Private == nil {
		return fmt.Errorf("manifest: Sign: active key not available")
	}

	// Clear signature fields so the signing payload covers only the body.
	m.Signature = nil
	m.SigningKeyId = ""

	payload, err := canonicalMarshal(m)
	if err != nil {
		return fmt.Errorf("manifest: Sign: canonical marshal: %w", err)
	}
	sig := ed25519.Sign(active.Private, payload)
	m.Signature = sig
	m.SigningKeyId = kid
	return nil
}

// Verify confirms m.Signature matches the body under the public key
// named by m.SigningKeyId. Returns a sentinel error the caller can
// distinguish on.
func (s *ed25519Signer) Verify(m *manifestpb.CapabilityManifest) error {
	if m == nil {
		return fmt.Errorf("manifest: Verify: nil manifest")
	}
	if len(m.Signature) == 0 {
		return ErrMissingSignature
	}
	if m.SigningKeyId == "" {
		return ErrUnknownSigningKey
	}

	s.mu.RLock()
	key, ok := s.keys[m.SigningKeyId]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownSigningKey, m.SigningKeyId)
	}

	// Clone to avoid mutating caller's message during verification. We
	// strip the signature fields, marshal canonically, then compare.
	// proto.Clone preserves unknown fields and oneof semantics.
	cloned := proto.Clone(m).(*manifestpb.CapabilityManifest)
	sig := cloned.Signature
	cloned.Signature = nil
	cloned.SigningKeyId = ""

	payload, err := canonicalMarshal(cloned)
	if err != nil {
		return fmt.Errorf("manifest: Verify: canonical marshal: %w", err)
	}
	if !ed25519.Verify(key.Public, payload, sig) {
		return ErrBadSignature
	}
	return nil
}

// PublishedKeys returns the public halves of every key known to the
// Signer. The active key is always first so consumers that prefer the
// active key for initial verification can take element [0] without
// additional bookkeeping.
func (s *ed25519Signer) PublishedKeys() []SigningKeyJWK {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SigningKeyJWK, 0, len(s.keys))
	if active, ok := s.keys[s.activeKid]; ok {
		out = append(out, keyToJWK(active))
	}
	for kid, k := range s.keys {
		if kid == s.activeKid {
			continue
		}
		out = append(out, keyToJWK(k))
	}
	return out
}

// canonicalMarshal returns a deterministic proto encoding suitable for
// signing and signature verification. proto.Marshal is not deterministic
// by default (map field ordering); the Deterministic option forces it.
func canonicalMarshal(m *manifestpb.CapabilityManifest) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func keyToJWK(k SignerKey) SigningKeyJWK {
	return SigningKeyJWK{
		Kid: k.Kid,
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		X:   base64.RawURLEncoding.EncodeToString(k.Public),
	}
}
