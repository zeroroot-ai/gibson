// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// finding_submitter_principal_test.go covers the attribution of a finding
// submitted over the component path (gibson#208): the stored record names the
// verified principal, the registered agent name and the enrolling person, and
// none of it comes from the client payload.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// submitterCtx is the context a component call arrives with once ext-authz
// and the SDK interceptor have run: the tenant and the verified identity whose
// Subject is the typed FGA principal.
func submitterCtx(tenant, principal string) context.Context {
	// The tenant lives on the Identity, so the identity goes in first and
	// ContextWithTenantString scopes it.
	return auth.ContextWithTenantString(
		auth.WithIdentity(context.Background(),
			auth.Identity{Subject: principal, Issuer: auth.IssuerCapabilityGrant, CredentialType: auth.CredentialCapabilityGrant}),
		tenant,
	)
}

// stubEnrolledAgents is an EnrolledAgentLookup with one enrolled agent.
type stubEnrolledAgents struct {
	tenant, principal, name, enrolledBy string
	err                                 error
	calls                               int
}

func (s *stubEnrolledAgents) LookupEnrolledAgent(_ context.Context, tenant, principal string) (string, string, error) {
	s.calls++
	if s.err != nil {
		return "", "", s.err
	}
	if tenant == s.tenant && principal == s.principal {
		return s.name, s.enrolledBy, nil
	}
	return "", "", nil
}

// recordingSink captures the record the World sink is handed.
func recordingSink(seen *finding.EnhancedFinding) WorldFindingSink {
	return func(_ context.Context, _ string, f finding.EnhancedFinding) { *seen = f }
}

func TestFindingSubmitter_StampsTheVerifiedSubmitter(t *testing.T) {
	var seen finding.EnhancedFinding
	registry := &stubEnrolledAgents{tenant: victimTenant, principal: "agent_principal:sa-1", name: "zerocool-demo", enrolledBy: "user-9"}
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger()).
		WithEnrolledAgentLookup(registry)

	// The payload claims another submitter. None of it is attribution.
	payload := `{"title":"exposed admin panel","severity":"info",` +
		`"agent_name":"forged-agent","submitted_by":"agent_principal:forged","enrolled_by":"user-forged"}`

	id, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"), victimTenant, "", payload, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, id)

	assert.Equal(t, id, seen.ID.String(), "the sink receives the record under the id the caller got")
	assert.Equal(t, "agent_principal:sa-1", seen.SubmittedBy, "the principal is the verified identity")
	assert.Equal(t, "zerocool-demo", seen.AgentName, "the agent name is the registered one")
	assert.Equal(t, "user-9", seen.EnrolledBy, "the enroller comes from the registry")
	assert.Equal(t, "exposed admin panel", seen.Title)
	assert.Equal(t, 1, registry.calls)
}

func TestFindingSubmitter_RefusesACallerWithoutIdentity(t *testing.T) {
	var seen finding.EnhancedFinding
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger())

	_, err := submitter.Submit(auth.ContextWithTenantString(context.Background(), victimTenant),
		victimTenant, "", `{"title":"orphan"}`, "", "")

	require.ErrorIs(t, err, ErrNoSubmitterIdentity)
	assert.Empty(t, seen.ID, "a finding with no submitter is not recorded")
}

func TestFindingSubmitter_UnenrolledPrincipalCarriesThePrincipalOnly(t *testing.T) {
	var seen finding.EnhancedFinding
	registry := &stubEnrolledAgents{tenant: victimTenant, principal: "agent_principal:someone-else", name: "other"}
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger()).
		WithEnrolledAgentLookup(registry)

	_, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-2"), victimTenant, "", `{"title":"x"}`, "", "")
	require.NoError(t, err)

	assert.Equal(t, "agent_principal:sa-2", seen.SubmittedBy)
	assert.Empty(t, seen.AgentName)
	assert.Empty(t, seen.EnrolledBy)
}

func TestFindingSubmitter_HumanSubjectIsStampedAsAUser(t *testing.T) {
	var seen finding.EnhancedFinding
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger()).
		WithEnrolledAgentLookup(&stubEnrolledAgents{})

	ctx := auth.ContextWithTenantString(
		auth.WithIdentity(context.Background(),
			auth.Identity{Subject: "12345", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser}),
		victimTenant)
	_, err := submitter.Submit(ctx, victimTenant, "", `{"title":"x"}`, "", "")
	require.NoError(t, err)

	assert.Equal(t, "user:12345", seen.SubmittedBy)
}

func TestFindingSubmitter_RegistryFailureIsAnError(t *testing.T) {
	var seen finding.EnhancedFinding
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger()).
		WithEnrolledAgentLookup(&stubEnrolledAgents{err: errors.New("db down")})

	_, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"), victimTenant, "", `{"title":"x"}`, "", "")
	require.ErrorContains(t, err, "db down")
	assert.Empty(t, seen.ID)
}

// TestSubmitFinding_RefusesACallerWithoutIdentity: the RPC itself refuses a
// request that carries a tenant but no verified caller.
func TestSubmitFinding_RefusesACallerWithoutIdentity(t *testing.T) {
	env := newWorkIDEnv(t)

	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)
	resp, err := env.svc.SubmitFinding(ctx, &componentpb.SubmitFindingRequest{Finding: []byte(`{"title":"orphan"}`)})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
