// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPriority_Validate(t *testing.T) {
	for _, p := range []Priority{"", PriorityP1, PriorityP2, PriorityP3, PriorityP4} {
		require.NoError(t, p.Validate(), string(p))
	}
	for _, p := range []Priority{"P0", "P5", "p1", "high", " P1"} {
		require.ErrorIs(t, p.Validate(), ErrInvalidPriority, string(p))
	}
	assert.False(t, Priority("").IsValid(), "no priority is not a priority")
}
