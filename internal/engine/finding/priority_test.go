// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

func TestPriority_Validate(t *testing.T) {
	for _, p := range []Priority{"", PriorityP1, PriorityP2, PriorityP3, PriorityP4} {
		assert.NoError(t, p.Validate(), string(p))
	}
	for _, p := range []Priority{"P0", "P5", "p1", "high", " P1"} {
		assert.ErrorIs(t, p.Validate(), ErrInvalidPriority, string(p))
	}
	assert.False(t, Priority("").IsValid(), "no priority is not a priority")
}

func TestRankOf(t *testing.T) {
	assert.Equal(t, 1, RankOf(PriorityP1, agent.SeverityLow))
	assert.Equal(t, 4, RankOf(PriorityP4, agent.SeverityCritical), "a set priority beats severity")
	assert.Equal(t, 1, RankOf("", agent.SeverityCritical))
	assert.Equal(t, 2, RankOf("", agent.SeverityHigh))
	assert.Equal(t, 3, RankOf("", agent.SeverityMedium))
	assert.Equal(t, 4, RankOf("", agent.SeverityInfo))
}
