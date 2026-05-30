package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func provWithModel(name, model string) *mockLLMProvider {
	return &mockLLMProvider{
		name:   name,
		models: []llm.ModelInfo{{Name: model, ContextWindow: 200000, Features: []string{agent.FeatureToolUse}, MaxOutput: 4096}},
		health: types.Healthy("ok"),
	}
}

func TestResolveByConstraints_PrefersTenantDefault(t *testing.T) {
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(provWithModel("alpha", "alpha-1")))
	require.NoError(t, registry.RegisterProvider(provWithModel("zebra", "zebra-1")))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slot := agent.NewSlotDefinition("primary", "primary", true)

	// Without a default, the deterministic fallback picks the sorted-first ("alpha").
	noDefault := NewDaemonSlotManager(registry, logger)
	p, _, err := noDefault.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "alpha", p.Name())

	// With the tenant default = "zebra", resolution prefers it over the sorted scan.
	withDefault := NewDaemonSlotManager(registry, logger).WithDefaultProvider("zebra")
	p2, _, err := withDefault.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "zebra", p2.Name())
}
