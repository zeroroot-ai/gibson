package awssm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// probeCanaryName generates a random canary secret name for use in Probe.
// The name is prefixed with "__probe." so it is visually distinct from real
// secrets and can be filtered out in audits. The random suffix prevents
// collisions across concurrent probe calls.
func probeCanaryName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "__probe.fallback"
	}
	return fmt.Sprintf("__probe.%s", hex.EncodeToString(b))
}
