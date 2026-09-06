// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

// Spec: unified-identity-and-authorization Phase 3, Tasks 3.6 and 3.7.
//
// CG-JWT minting: at mission task dispatch, the orchestrator calls
// Minter.Mint(ctx, ...) to obtain a per-task JWT scoped to a specific
// agent / mission / task / RPC set with a ≤30 minute lifetime. The
// JWT is signed with the daemon's dedicated Ed25519 CG signing key —
// its own secret, on its own path, with its own rotation window. See
// signingkey.go for the key set and what a rotation looks like.
//
// ── Layered defense for non-plugin secret isolation ──────────────────
//
// Spec: non-plugin-secret-isolation Requirement 4 / 6, in concert with
// secrets-broker (Spec 1) Requirement 8.
//
// Layer 3 (this file): the Mint() function refuses to issue a CG-JWT
// when the recipient's workload class is not "plugin" AND the
// requested AllowedRPCs include any secret-resolution RPC (the
// HarnessCallbackService.GetCredential and ComponentService.GetCredential
// methods). The deny set is hardcoded rather than introspecting proto
// annotations: the guard stays simple, auditable, and decoupled from
// the proto registry. Defense fails CLOSED — an empty or unknown
// RecipientClass is treated as not-allowed-to-call-secret-resolution,
// so any caller that omits the field will be rejected by design.
//
// Layer 4 (core/ext-authz/internal/check/cg.go): the ext-authz CG
// verifier independently refuses to authorize any RPC against an
// absent FGA tuple. Even if a forged CG-JWT were signed with the
// daemon's signing key but with a mismatched recipient class, ext-
// authz would still reject the call because the tenant-operator
// (per Spec 1 R8 and Spec 3 R3) never writes a (agent_principal|
// tool_principal, can_resolve, secret:*) tuple.
//
// The two layers are independent: a forged CG-JWT signed with the
// daemon's KMS key but carrying a non-plugin class would be refused
// at Layer 4 (no FGA tuple); a legitimate Mint request from a
// confused caller never reaches the wire because Layer 3 refuses
// at issuance. Cross-reference: Spec 1 R8 and Spec 3 R6.
//
// Public-key publication: the public counterpart is served per-kid at
// /capabilitygrant/v1/keys/{kid} on the daemon's pre-auth listener, so
// that ext-authz can verify CG-JWTs in its short-circuit path. There is
// no JWKS-wide document: ADR-0045 collapses key resolution to a single
// fetch-by-kid, and ext-authz never enumerates the key set.
//
// Signing key provenance (GHSA-3957-8wcf-929q): the signing key is a
// dedicated secret read from its own mount, independent of the master
// KEK — Config.SigningKeyDir, loaded by LoadSigningKeySetFromDir.
// Holding the KEK no longer lets you mint capability grants, and
// rotating the signing key no longer means re-encrypting everything
// the KEK covers.
//
// Until an operator provisions that mount, NewMinter falls back to the
// legacy HKDF-from-KEK derivation so an upgrade does not take capability
// grants down on first boot. The fallback is announced, not silent:
// Minter.DerivedFromMasterKEK reports it and the daemon logs it at
// startup. A daemon running on the fallback still has the original
// defect — it is a migration bridge, not a supported configuration,
// and it goes away once the chart projects the signing-key Secret.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
	capabilitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
)

// MaxLifetime is the upper bound enforced by Mint on the requested
// TTL. Per Requirement 5.2, CG-JWTs MUST NOT live longer than 30
// minutes — if the orchestrator requests longer it gets capped here.
const MaxLifetime = 30 * time.Minute

// Issuer is the iss claim value. ext-authz validates this against
// EXT_AUTHZ_CGJWT_ISSUER. Should match the daemon's externally-
// addressable URL (typically the Envoy edge URL).
//
// The Audience is the daemon identifier; ext-authz validates against
// EXT_AUTHZ_CGJWT_AUDIENCE.
type Config struct {
	Issuer   string
	Audience string

	// SigningKeyDir is the projected Secret volume holding the daemon's
	// dedicated CG signing key and, during a rotation, the previous one.
	// See LoadSigningKeySetFromDir for the layout. Preferred over the
	// KeyProvider fallback below; when it is set and the mount is
	// unreadable, construction fails rather than quietly signing with
	// different key material.
	SigningKeyDir string

	// KeyProvider holds the master KEK. It is the migration fallback for
	// the signing key and is consulted only when SigningKeyDir names no
	// provisioned key. Required while that fallback exists.
	KeyProvider crypto.KeyProvider

	// KeyID is the kid used by the KeyProvider fallback only. When
	// SigningKeyDir is provisioned the kid comes from the mount, because
	// the kid has to travel with the key material it names — otherwise a
	// rotation could publish one key under another key's kid.
	KeyID string

	// Shape is the daemon's untrusted-execution deployment shape
	// (GIBSON_UNTRUSTED_EXEC). The zero value ShapeSetecOnly fail-closes:
	// an unwired Minter rejects every non-hosted isolation mode at issuance
	// (ADR-0010 / gibson#998).
	Shape dispatchpolicy.DeploymentShape
}

// Minter mints capability-grant JWTs.
//
// Construction loads the signing key set once and caches it for the
// process lifetime; picking up a rotated mount requires a restart. That
// is what the previous key in the set is for — the outgoing key keeps
// verifying while replicas roll, so a rotation does not have to be
// simultaneous across them.
type Minter struct {
	issuer   string
	audience string
	keys     *SigningKeySet
	shape    dispatchpolicy.DeploymentShape
}

// NewMinter constructs a Minter from cfg. It synchronously loads the
// signing key so failures surface at startup rather than at first mint.
func NewMinter(ctx context.Context, cfg Config) (*Minter, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("capabilitygrant: Issuer required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("capabilitygrant: Audience required")
	}
	keys, err := loadSigningKeys(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Minter{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		keys:     keys,
		shape:    cfg.Shape,
	}, nil
}

// loadSigningKeys resolves the signing key set: the dedicated mount when it is
// provisioned, otherwise the legacy master-KEK derivation.
//
// A mount that exists but does not load is an error, never a fallback. The
// fallback exists for the daemon that has not been given a signing key yet, not
// for the daemon whose signing key is broken — quietly signing with the KEK key
// under those circumstances would publish one key and sign with another.
func loadSigningKeys(ctx context.Context, cfg Config) (*SigningKeySet, error) {
	set, err := LoadSigningKeySetFromDir(cfg.SigningKeyDir)
	switch {
	case err == nil:
		return set, nil
	case !errors.Is(err, ErrSigningKeyNotProvisioned):
		return nil, fmt.Errorf("capabilitygrant: load signing key from %q: %w", cfg.SigningKeyDir, err)
	}

	// Migration bridge — see the provenance note at the top of this file.
	if cfg.KeyProvider == nil {
		return nil, errors.New("capabilitygrant: no SigningKeyDir provisioned and no KeyProvider to fall back to")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("capabilitygrant: KeyID required for the master-KEK signing fallback")
	}
	master, err := cfg.KeyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: fetch master key: %w", err)
	}
	if len(master) < 32 {
		return nil, fmt.Errorf("capabilitygrant: master key must be ≥32 bytes (got %d)", len(master))
	}
	priv, pub, err := deriveEd25519FromMaster(master)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: derive signing key: %w", err)
	}
	return &SigningKeySet{
		Current:              SigningKey{keyID: cfg.KeyID, priv: priv, pub: pub},
		derivedFromMasterKEK: true,
	}, nil
}

// MintRequest carries the per-task scope.
type MintRequest struct {
	// Subject is the agent's Zitadel service-account ID. Required.
	Subject string

	// Tenant is the validated tenant scope. Required.
	Tenant string

	// MissionID names the mission being executed. Required.
	MissionID string

	// TaskID names the specific task. Required and unique per
	// mission step.
	TaskID string

	// AllowedRPCs is the set of fully-qualified gRPC method names
	// the agent may invoke without further FGA evaluation. Required
	// and non-empty.
	AllowedRPCs []string

	// TTL is the requested CG-JWT lifetime. Capped at MaxLifetime.
	// Defaults to MaxLifetime when zero.
	TTL time.Duration

	// RecipientClass is the recipient workload's class as recorded on
	// its Zitadel service-account. Acceptable values are "agent",
	// "tool", and "plugin"; any other value (including the empty
	// string) is treated as deny-all by the secret-resolution guard
	// in Mint(). The class is consulted to refuse issuance of CG-JWTs
	// that would let a non-plugin caller invoke a credential-resolving
	// RPC. See spec non-plugin-secret-isolation Requirement 4 and the
	// layered-defense block at the top of this file.
	RecipientClass string

	// Isolation is where this grant's untrusted-execution boundary lives
	// (ADR-0010). The zero value (ISOLATION_MODE_UNSPECIFIED) is treated as
	// HOSTED_SANDBOX, so grants minted without setting it pass under every
	// shape. Under ShapeSetecOnly, Mint rejects any non-hosted mode at
	// issuance (gibson#998).
	Isolation capabilitypb.IsolationMode
}

// secretResolutionRPCs is the hardcoded set of gRPC methods through
// which a caller could obtain a tenant credential value. Mint refuses
// to issue a CG-JWT that grants any of these to a non-plugin
// recipient. The set is hardcoded rather than derived from proto
// annotations to keep the guard auditable and decoupled from the
// proto registry.
var secretResolutionRPCs = map[string]struct{}{
	"/gibson.harness.v1.HarnessCallbackService/GetCredential": {},
	"/gibson.component.v1.ComponentService/GetCredential":     {},
}

// classCanCallSecretResolution maps recipient workload class to
// whether that class is permitted to be granted any of the secret-
// resolution RPCs above. Defense fails CLOSED: any class not present
// in this map (including the empty string) is treated as forbidden.
var classCanCallSecretResolution = map[string]bool{
	"plugin": true,
	"agent":  false,
	"tool":   false,
}

// CGMintDeniedByRecipientClassError is returned by Mint when the
// requested AllowedRPCs include a secret-resolution method but the
// MintRequest.RecipientClass is not permitted to invoke them. The
// error names the offending class, the rejected RPC, and the classes
// that would have been allowed (currently just "plugin").
//
// Spec: non-plugin-secret-isolation Requirement 4.2 (structured error
// with code CG_MINT_DENIED_BY_RECIPIENT_CLASS).
type CGMintDeniedByRecipientClassError struct {
	RecipientClass string
	RejectedRPC    string
	AllowedClasses []string
}

func (e *CGMintDeniedByRecipientClassError) Error() string {
	cls := e.RecipientClass
	if cls == "" {
		cls = "<empty>"
	}
	return fmt.Sprintf(
		"capabilitygrant: CG_MINT_DENIED_BY_RECIPIENT_CLASS: recipient class %q cannot be granted secret-resolution RPC %q (allowed classes: %v)",
		cls, e.RejectedRPC, e.AllowedClasses,
	)
}

// CGMintDeniedByIsolationError is returned by Mint when the requested
// MintRequest.Isolation is not permitted under the daemon's deployment shape
// (ADR-0010 / gibson#998) — e.g. a customer-isolation mode requested under the
// hosted setec-only shape. Fails CLOSED.
type CGMintDeniedByIsolationError struct {
	Isolation capabilitypb.IsolationMode
	Shape     dispatchpolicy.DeploymentShape
}

func (e *CGMintDeniedByIsolationError) Error() string {
	shape := "setec-only"
	if e.Shape == dispatchpolicy.ShapeCustomerIsolation {
		shape = "customer-isolation"
	}
	return fmt.Sprintf(
		"capabilitygrant: CG_MINT_DENIED_BY_ISOLATION: isolation mode %q is not permitted under deployment shape %q (hosted setec-only permits only ISOLATION_MODE_HOSTED_SANDBOX)",
		e.Isolation.String(), shape,
	)
}

// Mint produces a signed CG-JWT for the given request. Returns the
// compact-serialized JWT string suitable for placing in the X-
// Capability-Grant header on agent callbacks.
func (m *Minter) Mint(req MintRequest) (string, error) {
	if req.Subject == "" || req.Tenant == "" || req.MissionID == "" || req.TaskID == "" {
		return "", errors.New("capabilitygrant: Subject/Tenant/MissionID/TaskID all required")
	}
	if len(req.AllowedRPCs) == 0 {
		return "", errors.New("capabilitygrant: AllowedRPCs required and non-empty")
	}

	// Layer 3 (non-plugin-secret-isolation R4): refuse to issue a
	// CG-JWT granting any secret-resolution RPC to a recipient whose
	// workload class is not permitted to call them. Defense fails
	// CLOSED — an empty or unknown RecipientClass is rejected for
	// any secret-resolution RPC by virtue of classCanCallSecretResolution
	// returning the zero-value (false) for missing keys.
	if allowed := classCanCallSecretResolution[req.RecipientClass]; !allowed {
		for _, rpc := range req.AllowedRPCs {
			if _, isSecretRPC := secretResolutionRPCs[rpc]; isSecretRPC {
				return "", &CGMintDeniedByRecipientClassError{
					RecipientClass: req.RecipientClass,
					RejectedRPC:    rpc,
					AllowedClasses: []string{"plugin"},
				}
			}
		}
	}

	// Layer (ADR-0010 / gibson#998): refuse to issue a CG-JWT whose isolation
	// boundary is not permitted under the deployment shape. Fails CLOSED — under
	// the hosted setec-only shape only HOSTED_SANDBOX (and UNSPECIFIED, treated
	// as HOSTED_SANDBOX) is allowed; every customer-operated mode is rejected.
	if !dispatchpolicy.IsolationAllowed(req.Isolation, m.shape) {
		return "", &CGMintDeniedByIsolationError{Isolation: req.Isolation, Shape: m.shape}
	}

	ttl := req.TTL
	if ttl <= 0 || ttl > MaxLifetime {
		ttl = MaxLifetime
	}
	now := time.Now().UTC()
	jti := uuid.NewString()

	claims := jwt.MapClaims{
		"iss":          m.issuer,
		"aud":          m.audience,
		"sub":          req.Subject,
		"tenant":       req.Tenant,
		"mission_id":   req.MissionID,
		"task_id":      req.TaskID,
		"allowed_rpcs": req.AllowedRPCs,
		"iat":          now.Unix(),
		"exp":          now.Add(ttl).Unix(),
		"jti":          jti,
	}
	// Carry the isolation boundary as a claim so the read-side projection
	// (CapabilityGrantInfo.isolation) and ext-authz can surface it. Omitted when
	// UNSPECIFIED to keep legacy grants byte-identical (consumers default a
	// missing claim to HOSTED_SANDBOX).
	if req.Isolation != capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED {
		claims["isolation"] = int32(req.Isolation)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = m.keyID()
	tok.Header["typ"] = "JWT"
	signed, err := tok.SignedString(m.keys.Current.priv)
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: sign: %w", err)
	}
	return signed, nil
}

// PublicKey returns the Ed25519 public key the Minter currently signs with.
func (m *Minter) PublicKey() ed25519.PublicKey { return m.keys.Current.pub }

// KeyID returns the JWS kid the Minter stamps on each token — the current key.
func (m *Minter) KeyID() string { return m.keyID() }

// keyID is the kid of the key in force.
func (m *Minter) keyID() string { return m.keys.Current.keyID }

// KeyIDs returns every kid this daemon still honours, current first. During a
// rotation window that is two: the key that signs and the key that only
// verifies.
func (m *Minter) KeyIDs() []string { return m.keys.KeyIDs() }

// KnowsKeyID reports whether kid names a daemon signing key that is still
// honoured. A retired kid — one dropped from the mount at the end of a rotation
// window — is not.
func (m *Minter) KnowsKeyID(kid string) bool {
	_, ok := m.keys.Verifier(kid)
	return ok
}

// DerivedFromMasterKEK reports whether this Minter is running on the legacy
// master-KEK derivation because no dedicated signing key is provisioned. The
// daemon surfaces this at startup; see the provenance note at the top of this
// file.
func (m *Minter) DerivedFromMasterKEK() bool { return m.keys.DerivedFromMasterKEK() }

// PublicKeyJWKS returns the JWKS document for the daemon's CG signing keys. The
// per-kid key endpoint serves this when the requested kid is a daemon key
// (verifying daemon-minted dispatch tokens). gibson#648.
//
// During a rotation window the document carries BOTH kids — the key that signs
// and the key that only verifies. That overlap is what makes a rotation a
// window rather than a mass invalidation: a verifier holding a cached copy, or
// one that fetched before the rotation, still resolves the outgoing kid for
// tokens minted under it.
func (m *Minter) PublicKeyJWKS() ([]byte, error) { return buildJWKS(m.keys.publicKeys()...) }

// deriveEd25519FromMaster derives a deterministic Ed25519 keypair
// from the supplied master key bytes via HKDF-SHA256 with a domain-
// separation tag. Same master + same code = same key, so process
// restarts produce a stable JWKS. The HKDF info string is the
// versioned domain tag — a future v2 derivation can use a new tag
// without changing GetEncryptionKey output.
func deriveEd25519FromMaster(master []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	salt := []byte("gibson/v1/cg-jwt-signing-salt")
	info := []byte("gibson/v1/ed25519-signing-key")

	hk := hkdf.New(sha256.New, master, salt, info)
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hk, seed); err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// buildJWKS renders the JWK Set body for the supplied Ed25519 public keys, in
// the order given. A rotation window passes two: the signing key first, the
// outgoing verify-only key second.
func buildJWKS(keys ...publishedKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("capabilitygrant: buildJWKS: no keys to publish")
	}
	type jwkSet struct {
		Keys []jwk `json:"keys"`
	}
	set := jwkSet{Keys: make([]jwk, 0, len(keys))}
	for _, k := range keys {
		set.Keys = append(set.Keys, newJWK(k.pub, k.kid))
	}
	body, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: buildJWKS: marshal: %w", err)
	}
	return body, nil
}

// jwk is one published Ed25519 verification key.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func newJWK(pub ed25519.PublicKey, kid string) jwk {
	return jwk{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
	}
}

// buildKeyDescriptor renders the per-kid key descriptor (ADR-0045, gibson#648):
// a JWKS superset that also carries the authoritative FGA principal, tenant, and
// status for a registered component key. ext-authz parses `keys` to verify the
// signature, then runs its per-method FGA check on the daemon-asserted
// `principal`/`tenant` — it trusts no caller-asserted identity. The `keys` field
// keeps the standard JWKS shape so the same parser handles both this and the
// daemon's own key document.
func buildKeyDescriptor(pub ed25519.PublicKey, kid, principal, tenant, status string) ([]byte, error) {
	type descriptor struct {
		Keys      []jwk  `json:"keys"`
		Principal string `json:"principal,omitempty"`
		Tenant    string `json:"tenant,omitempty"`
		Status    string `json:"status,omitempty"`
	}
	return json.Marshal(descriptor{
		Keys:      []jwk{newJWK(pub, kid)},
		Principal: principal,
		Tenant:    tenant,
		Status:    status,
	})
}

// Compile-time assert: rand is referenced so the import is valid even
// if a future refactor stops using it directly. Cheap.
var _ = rand.Reader
