// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck_Validate(t *testing.T) {
	require.NoError(t, Check{Kind: CheckPredicate, Ref: "rce"}.Validate())
	require.NoError(t, Check{Kind: CheckTool, Ref: "tool-1"}.Validate())
	require.NoError(t, Check{Kind: CheckScan}.Validate())
	require.ErrorIs(t, Check{}.Validate(), ErrNoCheck)
	require.ErrorIs(t, Check{Kind: "guess", Ref: "x"}.Validate(), ErrNoCheck)
	require.ErrorIs(t, Check{Kind: CheckTool}.Validate(), ErrNoCheck)
}

// A stronger check can verify and a weaker check cannot (ADR-0178).
func TestCheck_CanVerify(t *testing.T) {
	p, s, tool := Check{Kind: CheckPredicate, Ref: "rce"}, Check{Kind: CheckScan, Ref: "m"}, Check{Kind: CheckTool, Ref: "t"}
	assert.True(t, p.CanVerify(s))
	assert.True(t, p.CanVerify(tool))
	assert.True(t, s.CanVerify(tool))
	assert.True(t, s.CanVerify(s))
	assert.False(t, s.CanVerify(p))
	assert.False(t, tool.CanVerify(s))
	assert.False(t, p.CanVerify(Check{}), "no check is verified by none")
}
