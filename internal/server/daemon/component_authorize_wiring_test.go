// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

type recordingTarget struct{ got component.RunAuthorizer }

func (r *recordingTarget) WithRunAuthorizer(a component.RunAuthorizer) *component.ComponentServiceServer {
	r.got = a
	return nil
}

type fixedSource struct {
	svc *harness.HarnessCallbackService
}

func (f fixedSource) RunAuthorizer() *harness.HarnessCallbackService { return f.svc }

// TestWireRunAuthorizer proves that the component service gets the callback
// service as its decision, and that a source with no decision wires nothing.
// A lost wire makes ComponentService.Authorize refuse every request (it fails
// closed), and no other test would notice.
func TestWireRunAuthorizer(t *testing.T) {
	svc := &harness.HarnessCallbackService{}

	t.Run("the callback service becomes the decision", func(t *testing.T) {
		target := &recordingTarget{}
		require.True(t, wireRunAuthorizer(target, fixedSource{svc: svc}))
		assert.Same(t, svc, target.got)
	})
	t.Run("no decision wires nothing", func(t *testing.T) {
		target := &recordingTarget{}
		require.False(t, wireRunAuthorizer(target, fixedSource{}))
		assert.Nil(t, target.got, "a nil service must not reach the component service as a non-nil interface")
	})
}

// The real callback manager is the source in the daemon.
var _ runAuthorizerSource = (*harness.CallbackManager)(nil)

// The real component service is the target in the daemon.
var _ runAuthorizerTarget = (*component.ComponentServiceServer)(nil)
