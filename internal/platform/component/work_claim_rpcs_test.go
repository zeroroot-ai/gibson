// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// otherAgentCtx calls as a second principal of the same tenant. It did not
// claim the work item.
func otherAgentCtx(tenant string) context.Context {
	return withSubject(ctxForTenant(tenant), "component-2")
}

// Authorize answers for the run of the work item of the caller. An agent of
// the same tenant that did not claim the item gets no answer for its run.
func TestAuthorize_RefusesAWorkItemThatAnotherAgentClaimed(t *testing.T) {
	env := newWorkIDEnv(t)
	fake := &fakeRunAuthorizer{allowed: true, reason: "fga_allow"}
	env.svc.WithRunAuthorizer(fake)
	workID := env.enqueueRun(t, victimTenant, "work-claim-az", "run-42")

	_, err := env.svc.Authorize(otherAgentCtx(victimTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, fake.calls, "the decision must not run for the run of another agent")

	// A caller with no identity is refused too.
	_, err = env.svc.Authorize(auth.ContextWithTenantString(context.Background(), victimTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A finding names a work item, and the work item names the mission that the
// finding is attributed to. An agent that did not claim the item cannot attach
// a finding to its mission.
func TestSubmitFinding_RefusesAWorkItemThatAnotherAgentClaimed(t *testing.T) {
	env := newWorkIDEnv(t)
	submitter := &countingFindingSubmitter{}
	env.svc.findingSubmitter = submitter
	workID := env.enqueueRun(t, victimTenant, "work-claim-find", "run-42")

	_, err := env.svc.SubmitFinding(otherAgentCtx(victimTenant), &componentpb.SubmitFindingRequest{
		WorkId: workID, Finding: []byte(`{"title":"x"}`),
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, submitter.submitted, "nothing may be submitted for a work item of another agent")

	// The claimant itself gets through.
	_, err = env.svc.SubmitFinding(ctxForTenant(victimTenant), &componentpb.SubmitFindingRequest{
		WorkId: workID, Finding: []byte(`{"title":"x"}`),
	})
	require.NoError(t, err)
	assert.Len(t, submitter.submitted, 1)
}

// A delegation names the work item of its caller. An agent that did not claim
// the item cannot delegate from it, and so cannot take its mission or its run.
func TestDelegateToAgent_RefusesASourceWorkItemThatAnotherAgentClaimed(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.WithGrantVerifier(fakeGrants{})
	env.svc.WithCapabilityChecker(grantedChecker())
	const tenant = "test-tenant"
	source := env.enqueueRun(t, tenant, "work-claim-del", "run-42")

	_, _, err := env.svc.bindSourceWork(grantedCtx(otherAgentCtx(tenant), "mission-7", "run-42"), tenant, source)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, sourceRunEntry(otherAgentCtx(tenant), env.svc, tenant, source), "a foreign claimant gets no run")
	assert.NotEmpty(t, sourceRunEntry(ctxForTenant(tenant), env.svc, tenant, source), "the claimant keeps its run")
}
