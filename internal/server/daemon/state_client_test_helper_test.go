package daemon

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

// setupTestStateClient returns a miniredis-backed StateClient for tests.
func setupTestStateClient(t *testing.T) *state.StateClient {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	client, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}
