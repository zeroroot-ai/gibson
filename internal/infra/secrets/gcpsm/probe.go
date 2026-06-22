package gcpsm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// probeCanaryName generates a random canary secret name for use in Probe.
// The name is prefixed with "probe-" so it is visually distinct from real
// secrets. The random hex suffix prevents collisions across concurrent calls.
// The name is designed to pass sanitizeName without modification.
func probeCanaryName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "probe-fallback"
	}
	return fmt.Sprintf("probe-%s", hex.EncodeToString(b))
}
