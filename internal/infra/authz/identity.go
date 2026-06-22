package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Identity-header names emitted by ext-authz to the upstream daemon.
// The bundle is HMAC-signed by ext-authz; the signature is carried in
// HeaderSignature and validated by the daemon via ValidateIdentityHeaders.
//
// The hyphenated form is the wire-canonical lowercase form used by
// http.Header.Get (Go canonicalizes "X-Gibson-Identity-Subject" →
// "X-Gibson-Identity-Subject" already; callers should pass the exact
// constants here rather than reinventing them).
const (
	HeaderSubject        = "X-Gibson-Identity-Subject"
	HeaderIssuer         = "X-Gibson-Identity-Issuer"
	HeaderCredentialType = "X-Gibson-Identity-Credential-Type"
	HeaderTenant         = "X-Gibson-Identity-Tenant"
	HeaderIssuedAt       = "X-Gibson-Identity-Issued-At"
	HeaderSignature      = "X-Gibson-Identity-Signature"
)

// signedHeaders lists the headers covered by the HMAC, in canonical
// order. Order MUST be deterministic for signer + verifier to agree;
// signedHeaders is sorted at package init time so this is enforced by
// construction.
var signedHeaders = func() []string {
	h := []string{
		HeaderSubject,
		HeaderIssuer,
		HeaderCredentialType,
		HeaderTenant,
		HeaderIssuedAt,
	}
	sort.Strings(h)
	return h
}()

// Identity is the post-validation projection of the
// X-Gibson-Identity-* header bundle. All fields are required; an
// Identity returned by ValidateIdentityHeaders is guaranteed
// non-zero.
type Identity struct {
	Subject        string
	Issuer         string
	CredentialType string
	Tenant         string
	IssuedAt       time.Time
}

// identityFreshnessSkewDefault is the default tolerance window applied
// by ValidateIdentityHeaders. Mirrors the SDK's identityFreshnessSkew
// constant so daemon and customer-SDK freshness semantics agree.
const identityFreshnessSkewDefault = 60 * time.Second

// ValidateOption configures ValidateIdentityHeaders behaviour.
type ValidateOption func(*validateConfig)

type validateConfig struct {
	skew  time.Duration
	clock func() time.Time
}

// WithFreshnessSkew overrides the default 60-second freshness window.
// A bundle whose |now − IssuedAt| exceeds d is rejected with
// ErrSkewExceeded. Pass 0 to disable freshness checking entirely.
func WithFreshnessSkew(d time.Duration) ValidateOption {
	return func(c *validateConfig) { c.skew = d }
}

// withClock injects a clock function for deterministic testing. Not
// exported: only test code in this package uses it.
func withClock(fn func() time.Time) ValidateOption {
	return func(c *validateConfig) { c.clock = fn }
}

// ValidateIdentityHeaders verifies that the X-Gibson-Identity-* bundle
// carries a valid HMAC-SHA256 signature computed with hmacSecret over
// the canonical message (signedHeaders joined with newlines in
// alphabetical order, each line "Name: value"). All required headers
// must be present; the signature must match exactly via
// constant-time compare; the issued-at must parse as Unix seconds; and
// the bundle must be within the freshness window (default 60 s).
//
// Structural failures (missing headers, bad hex, HMAC mismatch) wrap
// ErrInvalidArgument. A stale / future-dated bundle wraps
// ErrSkewExceeded so callers can emit a replay-specific signal.
func ValidateIdentityHeaders(headers http.Header, hmacSecret []byte, opts ...ValidateOption) (Identity, error) {
	cfg := validateConfig{
		skew:  identityFreshnessSkewDefault,
		clock: func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(&cfg)
	}
	if headers == nil {
		return Identity{}, fmt.Errorf("%w: nil headers", ErrInvalidArgument)
	}
	if len(hmacSecret) == 0 {
		return Identity{}, fmt.Errorf("%w: hmacSecret must not be empty", ErrInvalidArgument)
	}

	subject := headers.Get(HeaderSubject)
	issuer := headers.Get(HeaderIssuer)
	credType := headers.Get(HeaderCredentialType)
	tenant := headers.Get(HeaderTenant)
	issuedAtStr := headers.Get(HeaderIssuedAt)
	sigHex := headers.Get(HeaderSignature)

	var missing []string
	if subject == "" {
		missing = append(missing, HeaderSubject)
	}
	if issuer == "" {
		missing = append(missing, HeaderIssuer)
	}
	if credType == "" {
		missing = append(missing, HeaderCredentialType)
	}
	if tenant == "" {
		missing = append(missing, HeaderTenant)
	}
	if issuedAtStr == "" {
		missing = append(missing, HeaderIssuedAt)
	}
	if sigHex == "" {
		missing = append(missing, HeaderSignature)
	}
	if len(missing) > 0 {
		return Identity{}, fmt.Errorf("%w: missing identity headers: %v", ErrInvalidArgument, missing)
	}

	issuedAtUnix, err := strconv.ParseInt(issuedAtStr, 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %s is not Unix seconds: %w", ErrInvalidArgument, HeaderIssuedAt, err)
	}

	// Recompute the HMAC and constant-time compare.
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %s is not hex: %w", ErrInvalidArgument, HeaderSignature, err)
	}
	got := computeIdentityHMAC(headers, hmacSecret)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return Identity{}, fmt.Errorf("%w: identity HMAC mismatch", ErrInvalidArgument)
	}

	issuedAt := time.Unix(issuedAtUnix, 0).UTC()
	if cfg.skew > 0 {
		now := cfg.clock()
		delta := now.Sub(issuedAt)
		if delta < 0 {
			delta = -delta
		}
		if delta > cfg.skew {
			rawDelta := now.Sub(issuedAt)
			return Identity{}, fmt.Errorf("%w: %s delta=%v max=%v",
				ErrSkewExceeded, HeaderIssuedAt, rawDelta.Round(time.Second), cfg.skew)
		}
	}

	return Identity{
		Subject:        subject,
		Issuer:         issuer,
		CredentialType: credType,
		Tenant:         tenant,
		IssuedAt:       issuedAt,
	}, nil
}

// SignIdentityHeaders computes the HMAC over the bundle and writes the
// hex-encoded signature into HeaderSignature. The caller is the signer
// (ext-authz today; tests + tooling tomorrow); the daemon is the
// verifier and calls ValidateIdentityHeaders.
func SignIdentityHeaders(headers http.Header, hmacSecret []byte) error {
	if headers == nil {
		return fmt.Errorf("%w: nil headers", ErrInvalidArgument)
	}
	if len(hmacSecret) == 0 {
		return fmt.Errorf("%w: hmacSecret must not be empty", ErrInvalidArgument)
	}
	for _, h := range signedHeaders {
		if headers.Get(h) == "" {
			return fmt.Errorf("%w: SignIdentityHeaders: %s is empty", ErrInvalidArgument, h)
		}
	}
	mac := computeIdentityHMAC(headers, hmacSecret)
	headers.Set(HeaderSignature, hex.EncodeToString(mac))
	return nil
}

// computeIdentityHMAC builds the canonical message (one line per
// signed header, "Name: value", joined with "\n") and computes
// HMAC-SHA256 over it. signedHeaders is package-sorted so signer and
// verifier always produce the same byte sequence.
func computeIdentityHMAC(headers http.Header, secret []byte) []byte {
	var b strings.Builder
	for i, h := range signedHeaders {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(h)
		b.WriteString(": ")
		b.WriteString(headers.Get(h))
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(b.String()))
	return m.Sum(nil)
}
