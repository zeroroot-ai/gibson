// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

func TestResolveByConstraints_PrefersTenantDefault(t *testing.T) {
	providers := []SlotProvider{provWithModel("alpha", "alpha-1"), provWithModel("zebra", "zebra-1")}
	slot := agent.NewSlotDefinition("primary", "primary", true)

	// Without a default, the deterministic fallback picks the sorted first ("alpha").
	noDefault := NewDaemonSlotManager(providers, slotTestLogger())
	p, err := noDefault.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "alpha", p.Provider)

	// With the tenant default "zebra", resolution prefers it over the sorted scan.
	withDefault := NewDaemonSlotManager(providers, slotTestLogger()).WithDefaultProvider("zebra")
	p2, err := withDefault.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "zebra", p2.Provider)
}
