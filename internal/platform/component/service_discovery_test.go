// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_discovery_test.go covers ListTools / ListAgents (gibson#1186 slice A).
//
// Both are served from the registry the service already owns plus the FGA
// authorizer — there is no injectable lister to stub, so these tests drive a
// fake registry and a fake authorizer and assert the security-relevant
// behaviour: authz filtering, tenant scoping, and that a failed check omits
// rather than reveals.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// listRegistry serves DiscoverAll / ListTenantComponents from a fixed set.
type listRegistry struct {
	noopRegistry
	byKind map[string][]ComponentInfo
	all    []ComponentInfo
	err    error
}

func (r *listRegistry) DiscoverAll(_ context.Context, _, kind string) ([]ComponentInfo, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.byKind[kind], nil
}

func (r *listRegistry) ListTenantComponents(_ context.Context, _ string) ([]ComponentInfo, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.all, nil
}

// allowAuthorizer answers Check from an allow-set keyed by "<relation>:<object>".
type allowAuthorizer struct {
	authz.Authorizer
	allow map[string]bool
	err   error
	// seen records every (user, relation, object) triple checked.
	seen []string
}

func (a *allowAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	a.seen = append(a.seen, user+"|"+relation+"|"+object)
	if a.err != nil {
		return false, a.err
	}
	return a.allow[relation+":"+object], nil
}

// componentCtx stamps both the tenant and a COMPONENT identity, the way
// ext-authz presents an off-cluster caller.
func componentCtx(subject string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), "test-tenant")
	tenant, err := auth.NewTenantID("test-tenant")
	if err != nil {
		panic(err)
	}
	return auth.WithIdentity(ctx, auth.Identity{Subject: subject, Tenant: tenant})
}

func discoveryServer(reg ComponentRegistry, az authz.Authorizer) *ComponentServiceServer {
	svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
	if az != nil {
		svc.WithAuthorizer(az)
	}
	return svc
}

// ---------------------------------------------------------------------------
// ListAgents
// ---------------------------------------------------------------------------

func TestListAgents_ReturnsOnlyAuthorizedAgents(t *testing.T) {
	reg := &listRegistry{byKind: map[string][]ComponentInfo{
		"agent": {
			{Kind: "agent", Name: "recon", Version: "1.0.0", Description: "recon agent",
				Metadata: map[string]string{"capabilities": "recon, discovery", "target_types": "web"}},
			{Kind: "agent", Name: "forbidden", Version: "1.0.0"},
		},
	}}
	az := &allowAuthorizer{allow: map[string]bool{"can_execute:component:agent/recon": true}}

	resp, err := discoveryServer(reg, az).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	require.NoError(t, err)
	require.Len(t, resp.Agents, 1, "an agent the caller cannot execute must not be listed")
	assert.Equal(t, "recon", resp.Agents[0].Name)
	assert.Equal(t, []string{"recon", "discovery"}, resp.Agents[0].Capabilities,
		"comma-separated metadata is split and trimmed")
	assert.Equal(t, []string{"web"}, resp.Agents[0].TargetTypes)
}

func TestListAgents_ChecksTheComponentPrincipalVerbatim(t *testing.T) {
	// ext-authz already supplies a typed FGA ref; prefixing it again would
	// produce "user:agent_principal:..." and never match a tuple.
	reg := &listRegistry{byKind: map[string][]ComponentInfo{
		"agent": {{Kind: "agent", Name: "recon"}},
	}}
	az := &allowAuthorizer{allow: map[string]bool{"can_execute:component:agent/recon": true}}

	_, err := discoveryServer(reg, az).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	require.NoError(t, err)
	require.NotEmpty(t, az.seen)
	assert.Equal(t, "agent_principal:abc|can_execute|component:agent/recon", az.seen[0])
}

func TestListAgents_DeduplicatesReplicas(t *testing.T) {
	reg := &listRegistry{byKind: map[string][]ComponentInfo{
		"agent": {
			{Kind: "agent", Name: "recon", InstanceID: "i-1"},
			{Kind: "agent", Name: "recon", InstanceID: "i-2"},
			{Kind: "agent", Name: "recon", InstanceID: "i-3"},
		},
	}}
	az := &allowAuthorizer{allow: map[string]bool{"can_execute:component:agent/recon": true}}

	resp, err := discoveryServer(reg, az).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	require.NoError(t, err)
	assert.Len(t, resp.Agents, 1, "three live replicas are one agent")
}

func TestListAgents_ExcludesTheSystemBackplane(t *testing.T) {
	// component:_system is the synthetic client backplane, deliberately kept out
	// of catalog enumerations; it must not surface as a fleet agent.
	reg := &listRegistry{byKind: map[string][]ComponentInfo{
		"agent": {{Kind: "agent", Name: "_system"}, {Kind: "agent", Name: "recon"}},
	}}
	az := &allowAuthorizer{allow: map[string]bool{
		"can_execute:component:_system":     true,
		"can_execute:component:agent/recon": true,
	}}

	resp, err := discoveryServer(reg, az).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	require.NoError(t, err)
	require.Len(t, resp.Agents, 1)
	assert.Equal(t, "recon", resp.Agents[0].Name)
}

func TestListAgents_AuthzFailureOmitsRatherThanReveals(t *testing.T) {
	reg := &listRegistry{byKind: map[string][]ComponentInfo{
		"agent": {{Kind: "agent", Name: "recon"}},
	}}
	az := &allowAuthorizer{err: errors.New("fga unavailable")}

	resp, err := discoveryServer(reg, az).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	// Fail closed on the entry, not on the call: a broken authz backend must not
	// leak an agent, and must not break an agent's startup either.
	require.NoError(t, err)
	assert.Empty(t, resp.Agents)
}

func TestListAgents_RequiresTenant(t *testing.T) {
	_, err := discoveryServer(&listRegistry{}, &allowAuthorizer{}).ListAgents(
		context.Background(), &componentpb.ListAgentsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListAgents_RequiresCallerIdentity(t *testing.T) {
	// Tenant present but no identity — there is no subject to authorize against,
	// so listing everything would be an authz bypass.
	ctx := auth.ContextWithTenantString(context.Background(), "test-tenant")
	_, err := discoveryServer(&listRegistry{}, &allowAuthorizer{}).ListAgents(
		ctx, &componentpb.ListAgentsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListAgents_RegistryFailureIsInternal(t *testing.T) {
	reg := &listRegistry{err: errors.New("redis down")}
	_, err := discoveryServer(reg, &allowAuthorizer{}).ListAgents(
		componentCtx("agent_principal:abc"), &componentpb.ListAgentsRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListTools
// ---------------------------------------------------------------------------

func TestListTools_ReturnsOnlyAuthorizedTools(t *testing.T) {
	// CatalogToolLister expands the tenant's live components; a native tool
	// becomes one "native:<name>" entry.
	reg := &listRegistry{all: []ComponentInfo{
		{Kind: "tool", Name: "nmap", Version: "7.94", Description: "port scanner"},
		{Kind: "tool", Name: "secret-scanner", Version: "1.0.0", Description: "not granted"},
	}}
	az := &allowAuthorizer{allow: map[string]bool{"can_execute:component:tool/nmap": true}}

	resp, err := discoveryServer(reg, az).ListTools(
		componentCtx("agent_principal:abc"), &componentpb.ListToolsRequest{})

	require.NoError(t, err)
	require.Len(t, resp.Tools, 1, "a tool the caller cannot execute must not be listed")
	assert.Equal(t, "native:nmap", resp.Tools[0].Name, "the canonical id is what CallTool expects")
	assert.Equal(t, "port scanner", resp.Tools[0].Description)
	assert.Contains(t, resp.Tools[0].Tags, "source:native")
}

func TestListTools_AgentsAreNotTools(t *testing.T) {
	reg := &listRegistry{all: []ComponentInfo{
		{Kind: "agent", Name: "recon", Version: "1.0.0"},
	}}
	az := &allowAuthorizer{allow: map[string]bool{"can_execute:component:agent/recon": true}}

	resp, err := discoveryServer(reg, az).ListTools(
		componentCtx("agent_principal:abc"), &componentpb.ListToolsRequest{})

	require.NoError(t, err)
	assert.Empty(t, resp.Tools)
}

func TestListTools_RequiresTenantAndIdentity(t *testing.T) {
	svc := discoveryServer(&listRegistry{}, &allowAuthorizer{})

	_, err := svc.ListTools(context.Background(), &componentpb.ListToolsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	ctx := auth.ContextWithTenantString(context.Background(), "test-tenant")
	_, err = svc.ListTools(ctx, &componentpb.ListToolsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListTools_NoAuthorizerIsUnimplemented(t *testing.T) {
	// The daemon always wires an authorizer; without one there is no safe answer,
	// so refuse rather than list unfiltered.
	svc := discoveryServer(&listRegistry{}, nil)

	_, err := svc.ListTools(componentCtx("agent_principal:abc"), &componentpb.ListToolsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
