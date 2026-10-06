// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audittest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// TestRecorder_KeepsEachEventAndReturnsACopy: the Recorder keeps the events
// in order, and a change to the returned slice does not change the Recorder.
func TestRecorder_KeepsEachEventAndReturnsACopy(t *testing.T) {
	var r Recorder
	assert.Empty(t, r.Events())

	r.Log(audit.Event{TenantID: "acme"})
	r.Log(audit.Event{TenantID: "beta"})

	got := r.Events()
	require.Len(t, got, 2)
	assert.Equal(t, "acme", got[0].TenantID)
	assert.Equal(t, "beta", got[1].TenantID)

	got[0].TenantID = "changed"
	assert.Equal(t, "acme", r.Events()[0].TenantID)
}
