package vault

import (
	"crypto/rand"
	"encoding/hex"
)

// probeCanaryName generates a random canary secret name for use in Probe.
// The name is prefixed with "__probe." so it is visually distinct from real
// secrets and can be filtered out in audits if needed. The random suffix
// prevents collisions across concurrent probe calls.
func probeCanaryName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use a timestamp-derived name (acceptable for probe).
		return "__probe.fallback"
	}
	return "__probe." + hex.EncodeToString(b)
}
