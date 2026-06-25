package capabilitygrant

// Spec: unified-identity-and-authorization Phase 3, Tasks 3.6 and 3.7.
//
// CG-JWT minting: at mission task dispatch, the orchestrator calls
// Minter.Mint(ctx, ...) to obtain a per-task JWT scoped to a specific
// agent / mission / task / RPC set with a ≤30 minute lifetime. The
// JWT is signed with an Ed25519 keypair derived from the master KEK
// the daemon's KeyProvider holds, with HKDF domain-separation so the
// signing key is not the encryption key.
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
// JWKS publication: JWKS exposes the public counterpart at
// /.well-known/jwks.json so that ext-authz can verify CG-JWTs in its
// short-circuit path. The endpoint is served via the daemon's HTTP
// listener (or as a sidecar) and goes through Envoy externally.
//
// Trade-off acknowledged for v1: deriving the Ed25519 signing key
// from the encryption KEK reuses key material across two crypto
// primitives, which is not ideal hygiene. Mitigated by HKDF domain
// separation. A future iteration can move to a dedicated KMS-managed
// signing key (Vault Transit Sign API, AWS KMS Sign, GCP KMS
// AsymmetricSign, Azure Key Vault Sign) without breaking the public
// JWKS contract — only the source of the private key changes.

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
	"net/http"
	"sync"
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

	// KeyProvider holds the master KEK used to derive the Ed25519
	// signing keypair. Required.
	KeyProvider crypto.KeyProvider

	// KeyID is the JWS kid header attached to every minted JWT. The
	// JWKS endpoint publishes one entry under this kid. Required.
	// Rotation: change KeyID and the master key together; ext-authz
	// caches JWKS for 1 hour by default so a brief overlap is
	// expected.
	KeyID string

	// Shape is the daemon's untrusted-execution deployment shape
	// (GIBSON_UNTRUSTED_EXEC). The zero value ShapeSetecOnly fail-closes:
	// an unwired Minter rejects every non-hosted isolation mode at issuance
	// (ADR-0010 / gibson#998).
	Shape dispatchpolicy.DeploymentShape
}

// Minter mints capability-grant JWTs.
//
// Construction loads the Ed25519 keypair from the configured
// KeyProvider and caches it for the process lifetime. Rotation
// requires a process restart (a future iteration may add hot rotation
// via a watch on the underlying secret).
type Minter struct {
	issuer   string
	audience string
	keyID    string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	shape    dispatchpolicy.DeploymentShape
}

// NewMinter constructs a Minter from cfg. It synchronously fetches
// the master KEK and derives the Ed25519 keypair so failures surface
// at startup rather than at first mint.
func NewMinter(ctx context.Context, cfg Config) (*Minter, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("capabilitygrant: Issuer required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("capabilitygrant: Audience required")
	}
	if cfg.KeyProvider == nil {
		return nil, errors.New("capabilitygrant: KeyProvider required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("capabilitygrant: KeyID required")
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
	return &Minter{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		keyID:    cfg.KeyID,
		priv:     priv,
		pub:      pub,
		shape:    cfg.Shape,
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
	tok.Header["kid"] = m.keyID
	tok.Header["typ"] = "JWT"
	signed, err := tok.SignedString(m.priv)
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: sign: %w", err)
	}
	return signed, nil
}

// PublicKey returns the Ed25519 public key for this Minter. JWKSHandler
// (jwks.go) consumes this to render the published JWKS document.
func (m *Minter) PublicKey() ed25519.PublicKey { return m.pub }

// KeyID returns the JWS kid the Minter stamps on each token.
func (m *Minter) KeyID() string { return m.keyID }

// PublicKeyJWKS returns a single-key JWKS document for the daemon's CG signing
// key, keyed by KeyID(). The per-kid key endpoint serves this when the requested
// kid is the daemon key (verifying daemon-minted dispatch tokens). gibson#648.
func (m *Minter) PublicKeyJWKS() ([]byte, error) { return buildJWKS(m.pub, m.keyID) }

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

// JWKSHandler returns an http.HandlerFunc serving the daemon's JWKS
// at /.well-known/jwks.json. ext-authz fetches and caches this for
// the verification path.
//
// The handler emits a single OKP/Ed25519 key under Minter.KeyID().
// Cache-Control allows ext-authz (or any other consumer) to cache
// for up to 1 hour per Requirement 5.7 — the daemon's restart
// rotation cadence and ext-authz's stale-key handling are designed
// around this window.
type JWKSHandler struct {
	mu sync.RWMutex

	body []byte
}

// NewJWKSHandler builds a JWKSHandler for the supplied Minter.
func NewJWKSHandler(m *Minter) (*JWKSHandler, error) {
	if m == nil {
		return nil, errors.New("capabilitygrant: nil minter")
	}
	body, err := buildJWKS(m.PublicKey(), m.KeyID())
	if err != nil {
		return nil, err
	}
	return &JWKSHandler{body: body}, nil
}

// ServeHTTP implements http.Handler.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	body := h.body
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// buildJWKS renders the JWK Set body for a single Ed25519 public key.
func buildJWKS(pub ed25519.PublicKey, kid string) ([]byte, error) {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	}
	type jwkSet struct {
		Keys []jwk `json:"keys"`
	}
	return json.Marshal(jwkSet{Keys: []jwk{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
	}}})
}

// buildKeyDescriptor renders the per-kid key descriptor (ADR-0045, gibson#648):
// a JWKS superset that also carries the authoritative FGA principal, tenant, and
// status for a registered component key. ext-authz parses `keys` to verify the
// signature, then runs its per-method FGA check on the daemon-asserted
// `principal`/`tenant` — it trusts no caller-asserted identity. The `keys` field
// keeps the standard JWKS shape so the same parser handles both this and the
// daemon's own key document.
func buildKeyDescriptor(pub ed25519.PublicKey, kid, principal, tenant, status string) ([]byte, error) {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	}
	type descriptor struct {
		Keys      []jwk  `json:"keys"`
		Principal string `json:"principal,omitempty"`
		Tenant    string `json:"tenant,omitempty"`
		Status    string `json:"status,omitempty"`
	}
	return json.Marshal(descriptor{
		Keys: []jwk{{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Kid: kid,
			Use: "sig",
			Alg: "EdDSA",
		}},
		Principal: principal,
		Tenant:    tenant,
		Status:    status,
	})
}

// Compile-time assert: rand is referenced so the import is valid even
// if a future refactor stops using it directly. Cheap.
var _ = rand.Reader
