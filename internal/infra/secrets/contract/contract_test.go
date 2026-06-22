package contract_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/contract"
)

// TestInMemoryBrokerContract runs the full SecretsBroker contract suite
// against the in-memory reference implementation. All test cases must pass
// without skips (the in-memory broker declares all capabilities as true).
func TestInMemoryBrokerContract(t *testing.T) {
	contract.RunContract(t, contract.NewInMemoryBroker())
}
