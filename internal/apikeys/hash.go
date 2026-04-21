package apikeys

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashKey returns the lowercase hex-encoded SHA-256 of the raw key.
// Never log the input to this function.
func hashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
