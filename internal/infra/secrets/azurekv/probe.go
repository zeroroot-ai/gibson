package azurekv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// probeCanaryName generates a random canary secret name for use in Probe.
// The name is designed to pass sanitizeName without modification (only
// alphanumeric characters and hyphens, starts with a letter).
func probeCanaryName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "probe-fallback"
	}
	return fmt.Sprintf("probe-%s", hex.EncodeToString(b))
}
