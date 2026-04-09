// Package authz — envelope_hmac.go provides the daemon-side HMAC signing helper
// for work envelope AuthzContexts.
//
// The daemon signs an AuthzContext when dispatching work to a component queue.
// The SDK verifies the signature at dequeue time. The same algorithm (HMAC-SHA256
// over "run_id|issued_at|ttl_seconds") is used on both sides; this file is the
// authoritative signing half.
//
// Security constraints:
//   - The secret is per-daemon-instance, regenerated on restart, never logged.
//   - After a daemon restart, in-flight work with old signatures will fail the
//     HMAC check on the SDK side and be rejected. The mission is re-scheduled.
package authz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"
)

const (
	// hmacPayloadSep separates fields in the HMAC payload string.
	hmacPayloadSep = "|"

	// DefaultWorkTTLSeconds is the default TTL for work envelope AuthzContexts.
	// 10 minutes is long enough for normal tool execution but short enough to
	// limit the window of stale authz in queues.
	DefaultWorkTTLSeconds = 600

	// AuthzContextWorkKey is the key used in the work item Context map to carry
	// the JSON-encoded EnvelopeAuthzContext. Shared between harness dispatch
	// (daemon side) and serve loop verification (SDK side).
	AuthzContextWorkKey = "authz_context"
)

// EnvelopeSigner generates and verifies HMAC-SHA256 signatures for work envelope
// AuthzContexts. One instance is created per daemon process and holds the
// per-daemon secret in memory.
//
// EnvelopeSigner is safe for concurrent use.
type EnvelopeSigner struct {
	secret []byte
}

// NewEnvelopeSigner creates a new EnvelopeSigner with a randomly generated
// per-daemon-instance secret (32 bytes). The secret is never persisted or logged.
// Callers should store the returned signer for the lifetime of the daemon.
func NewEnvelopeSigner() (*EnvelopeSigner, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate envelope HMAC secret: %w", err)
	}
	return &EnvelopeSigner{secret: secret}, nil
}

// NewEnvelopeSignerWithSecret creates an EnvelopeSigner with an explicit secret.
// Use this in tests or when the secret must be stable across restarts.
// The secret must be at least 16 bytes.
func NewEnvelopeSignerWithSecret(secret []byte) (*EnvelopeSigner, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("envelope HMAC secret must be at least 16 bytes, got %d", len(secret))
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &EnvelopeSigner{secret: cp}, nil
}

// EnvelopeAuthzContext holds the signed authorization context fields.
// The Signature is HMAC-SHA256 over "run_id|issued_at|ttl_seconds".
type EnvelopeAuthzContext struct {
	RunID      string
	IssuedAt   int64
	TTLSeconds int32
	Signature  []byte
}

// Sign creates a signed EnvelopeAuthzContext for the given run ID.
// ttlSeconds should be DefaultWorkTTLSeconds or a config-overridden value.
func (s *EnvelopeSigner) Sign(runID string, ttlSeconds int32) *EnvelopeAuthzContext {
	now := time.Now().Unix()
	sig := computeHMACDaemon(s.secret, runID, now, ttlSeconds)
	return &EnvelopeAuthzContext{
		RunID:      runID,
		IssuedAt:   now,
		TTLSeconds: ttlSeconds,
		Signature:  sig,
	}
}

// computeHMACDaemon computes HMAC-SHA256 over "run_id|issued_at|ttl_seconds" using key.
// This function MUST produce the same output as the SDK's computeHMAC function in
// core/sdk/harness/envelope_hmac.go — both sides must use the same algorithm.
func computeHMACDaemon(key []byte, runID string, issuedAt int64, ttlSeconds int32) []byte {
	payload := fmt.Sprintf("%s%s%d%s%d", runID, hmacPayloadSep, issuedAt, hmacPayloadSep, ttlSeconds)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}
