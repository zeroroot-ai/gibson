package datapool

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// kekInfo is the HKDF info string that domain-separates tenant KEKs
	// from any other HKDF usage in the daemon. Never change this value
	// without a documented re-encryption procedure for all existing wrapped
	// DEKs.
	kekInfo = "gibson/v1/tenant-kek"

	// kekLen is the output key length in bytes. 32 bytes = AES-256.
	kekLen = 32

	// minMasterKEKLen is the minimum acceptable master KEK length. A master
	// KEK shorter than 32 bytes is rejected to prevent weak derivation.
	minMasterKEKLen = 32
)

// DeriveTenantKEK derives a 32-byte per-tenant key encryption key from the
// master KEK using HKDF-SHA256. The derivation is deterministic: the same
// masterKEK and tenant always produce the same output.
//
// This is the public API used by cross-package callers (e.g., the Setec
// adapter in the daemon package for R8.2 envelope-wrapping).
// The unexported deriveTenantKEK calls through to this function.
//
// Parameters:
//   - masterKEK: the daemon's master KEK loaded from KMS. Must be at least
//     32 bytes; shorter inputs are rejected with an error.
//   - tenant: the auth.TenantID of the tenant. Its String() representation
//     is used as the HKDF salt. The auth package guarantees it is non-empty
//     and validated.
//
// The derived KEK must be zeroed by the caller when it is no longer needed.
func DeriveTenantKEK(masterKEK []byte, tenant auth.TenantID) ([]byte, error) {
	return deriveTenantKEK(masterKEK, tenant)
}

// deriveTenantKEK is the package-internal implementation. Callers outside
// this package should use DeriveTenantKEK.
func deriveTenantKEK(masterKEK []byte, tenant auth.TenantID) ([]byte, error) {
	if len(masterKEK) < minMasterKEKLen {
		return nil, fmt.Errorf("datapool: master KEK is too short (%d bytes, minimum %d)", len(masterKEK), minMasterKEKLen)
	}
	if tenant.IsZero() {
		return nil, fmt.Errorf("datapool: cannot derive KEK for zero TenantID")
	}

	salt := []byte(tenant.String())
	info := []byte(kekInfo)

	r := hkdf.New(sha256.New, masterKEK, salt, info)

	kek := make([]byte, kekLen)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("datapool: HKDF derivation failed: %w", err)
	}
	return kek, nil
}
