// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

func countermeasureService() *HarnessCallbackService {
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(), testEventBus())
}

// A technique that D3FEND counters returns its countermeasures with the tactic
// and the NIST controls, in the order of the pack (gibson#1487).
func TestGetCountermeasures_ReturnsTheCountermeasuresOfATechnique(t *testing.T) {
	resp, err := countermeasureService().GetCountermeasures(context.Background(), &harnesspb.GetCountermeasuresRequest{Technique: "T1059"})
	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	ids := make([]string, 0, len(resp.GetCountermeasures()))
	for _, c := range resp.GetCountermeasures() {
		ids = append(ids, c.GetId())
		assert.NotEmpty(t, c.GetName())
		assert.NotEmpty(t, c.GetTactic())
	}
	assert.Contains(t, ids, "D3-FA")
}

// A technique that no countermeasure counters, and an empty one, give an empty
// list and no error. A value that is no technique id is refused.
func TestGetCountermeasures_EmptyAndInvalidTechniques(t *testing.T) {
	svc := countermeasureService()
	for _, technique := range []string{"", "T0000"} {
		resp, err := svc.GetCountermeasures(context.Background(), &harnesspb.GetCountermeasuresRequest{Technique: technique})
		require.NoError(t, err)
		require.Nil(t, resp.GetError(), "technique %q", technique)
		assert.Empty(t, resp.GetCountermeasures(), "technique %q", technique)
	}
	resp, err := svc.GetCountermeasures(context.Background(), &harnesspb.GetCountermeasuresRequest{Technique: "not a technique"})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetError().GetCode())
	assert.Empty(t, resp.GetCountermeasures())
}
