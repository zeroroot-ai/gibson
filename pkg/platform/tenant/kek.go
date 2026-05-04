package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/zero-day-ai/sdk/auth"
)

// HKDF parameters for per-tenant KEK derivation. These values are
// load-bearing — changing any of them is a coordinated re-encryption
// procedure across every existing tenant. The KEKInfo string is the
// domain-separation tag that ensures HKDF outputs cannot collide with any
// other use of HKDF in the system.
const (
	// KEKInfo is the HKDF info string. Identical to the value used by the
	// daemon's legacy datapool/kek.go and the operator's legacy
	// dataplane/kek.go before this package consolidated them. Do NOT change
	// without re-deriving every tenant's password.
	KEKInfo = "gibson/v1/tenant-kek"

	// KEKLength is the per-tenant KEK length in bytes (AES-256).
	KEKLength = 32

	// MinMasterKEKLength is the minimum acceptable master KEK length. A
	// shorter master is rejected to prevent weak derivation.
	MinMasterKEKLength = 32
)

// DeriveTenantKEK derives a per-tenant 32-byte KEK from masterKEK using
// HKDF-SHA256 with salt=tenantID, info=KEKInfo. Deterministic — same inputs
// always produce the same output, which is what allows the operator to
// derive a Postgres password and the daemon to read that password back
// from Vault without ever exchanging it directly.
//
// Production code paths use Vault transit (transit/derive/master-kek)
// instead, so the master KEK never leaves Vault. This function exists for
// dev mode (--dev-mode flag) where the master KEK is read from a Secret
// and the operator performs HKDF locally.
//
// The caller MUST zeroize the returned slice when done.
func DeriveTenantKEK(masterKEK []byte, tenantID auth.TenantID) ([]byte, error) {
	if len(masterKEK) < MinMasterKEKLength {
		return nil, fmt.Errorf("tenant: master KEK too short: have %d bytes, need at least %d",
			len(masterKEK), MinMasterKEKLength)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("tenant: cannot derive KEK for zero TenantID")
	}

	r := hkdf.New(sha256.New, masterKEK, []byte(tenantID.String()), []byte(KEKInfo))
	kek := make([]byte, KEKLength)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("tenant: HKDF expand failed: %w", err)
	}
	return kek, nil
}

// PostgresPasswordFromKEK returns the Postgres role password derived from
// a per-tenant KEK. The password is the first 32 hex characters of the
// hex-encoded KEK (i.e., the first 16 bytes of the KEK encoded as 32 hex
// chars). This matches the legacy operator+daemon derivation byte-for-byte
// so existing dev-mode tenants continue to work after consolidation.
//
// The KEK is NOT zeroized by this function — the caller still owns the
// returned slice and is responsible for zeroizing it.
func PostgresPasswordFromKEK(kek []byte) (string, error) {
	if len(kek) < KEKLength {
		return "", fmt.Errorf("tenant: KEK too short for Postgres password: have %d bytes, need %d",
			len(kek), KEKLength)
	}
	return hex.EncodeToString(kek)[:KEKLength], nil
}

// Zeroize overwrites b with zeros. Useful for clearing derived KEK bytes
// after use. Inlinable; the compiler will not optimize this away because
// the slice is observable.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
