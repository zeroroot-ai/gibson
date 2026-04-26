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

	"github.com/zero-day-ai/gibson/internal/crypto"
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

// Compile-time assert: rand is referenced so the import is valid even
// if a future refactor stops using it directly. Cheap.
var _ = rand.Reader
