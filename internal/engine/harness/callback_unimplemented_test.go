// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// The phase-2 harness RPCs the sdk declared ahead of their handlers. Each is
// classified denied in callbackMethodPolicy with reasonUnimplemented, and the
// service answers it with codes.Unimplemented from the embedded
// UnimplementedHarnessCallbackServiceServer: an honest "not here yet", never a
// silent grant. The change that adds a handler replaces the test for that
// method with real success and error cases and flips the policy entry.

func assertDeclaredNotHandled(t *testing.T, method string, call func(context.Context) codes.Code) {
	t.Helper()
	decision, ok := callbackMethodPolicy[method]
	require.True(t, ok, "%s must be classified in callbackMethodPolicy", method)
	assert.False(t, decision.agentSurface, "%s has no handler and must stay off the agent surface", method)
	assert.Equal(t, reasonUnimplemented, decision.reason)

	assert.Equal(t, codes.Unimplemented, call(context.Background()), "%s must answer Unimplemented until its handler lands", method)
}

func TestSubmitProof_DeclaredNotHandled(t *testing.T) {
	var svc harnesspb.UnimplementedHarnessCallbackServiceServer
	assertDeclaredNotHandled(t, harnesspb.HarnessCallbackService_SubmitProof_FullMethodName, func(ctx context.Context) codes.Code {
		_, err := svc.SubmitProof(ctx, &harnesspb.SubmitProofRequest{})
		return status.Code(err)
	})
}

func TestRequestDestructiveAuthorization_DeclaredNotHandled(t *testing.T) {
	var svc harnesspb.UnimplementedHarnessCallbackServiceServer
	assertDeclaredNotHandled(t, harnesspb.HarnessCallbackService_RequestDestructiveAuthorization_FullMethodName, func(ctx context.Context) codes.Code {
		_, err := svc.RequestDestructiveAuthorization(ctx, &harnesspb.RequestDestructiveAuthorizationRequest{})
		return status.Code(err)
	})
}

func TestProposeOntologyExtension_DeclaredNotHandled(t *testing.T) {
	var svc harnesspb.UnimplementedHarnessCallbackServiceServer
	assertDeclaredNotHandled(t, harnesspb.HarnessCallbackService_ProposeOntologyExtension_FullMethodName, func(ctx context.Context) codes.Code {
		_, err := svc.ProposeOntologyExtension(ctx, &harnesspb.ProposeOntologyExtensionRequest{})
		return status.Code(err)
	})
}
