// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

func sp(s string) *string { return &s }

// discoveryFixture is what a recon tool puts in proto field 100: a host with a
// service on a port, plus a finding parented on that host.
func discoveryFixture() *graphragpb.DiscoveryResult {
	return &graphragpb.DiscoveryResult{
		Hosts:    []*graphragpb.Host{{Id: sp("h1"), Ip: "192.0.2.10"}},
		Ports:    []*graphragpb.Port{{Id: sp("p1"), HostId: "h1", Number: 8080, Protocol: "tcp"}},
		Services: []*graphragpb.Service{{Id: sp("s1"), PortId: "p1", Name: "http-alt"}},
		Domains:  []*graphragpb.Domain{{Id: sp("d1"), Name: "example.test"}},
		Findings: []*graphragpb.Finding{{
			Id: sp("f1"), Title: "Directory listing enabled", Severity: "medium",
			ParentId: sp("h1"), ParentType: sp("host"),
		}},
	}
}

// TestDiscoveryResultReachesTheGraphThroughTheProjector walks the whole ingest
// path the harness callback and sandboxed dispatch both terminate in: a
// DiscoveryResult goes into the daemon's production-wired processor, and the
// entities come out the other side as writes issued by the graph projector —
// the single writer.
//
// This is the test the acceptance criterion asks for. It fails if any link is
// severed: remove the wiring (newDiscoveryProcessor returning nil), stop the
// sink submitting, drop an entity from the translation, or take the projector
// off the registry, and the assertions below go red rather than passing on an
// empty result. Verified by mutation — see the PR description.
func TestDiscoveryResultReachesTheGraphThroughTheProjector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const tenant = "acme"
	reg := brain.NewRegistry(ctx)

	// Build the processor exactly the way the daemon does at startup, so this
	// test is exercising the production wiring rather than a parallel one.
	d := &daemonImpl{logger: testObsLogger(), brainRegistry: reg, registryTenant: tenant}
	proc := d.newDiscoveryProcessor()
	require.NotNil(t, proc, "the daemon must wire a discovery processor when the brain is live")

	res, err := proc.Process(ctx, ingest.ExecContext{
		MissionID:    "mission-42",
		MissionRunID: "run-1",
		AgentName:    "recon",
	}, discoveryFixture())
	require.NoError(t, err)
	require.Equal(t, 3, res.EventsSubmitted, "host, domain and finding must all be submitted")

	writer := newFakeGraphWriter()
	projector := NewGraphProjector(reg, writer, time.Millisecond, nil)

	// The brain folds asynchronously on its own tick, so project until the World
	// has caught up rather than assuming a single pass sees everything.
	require.Eventually(t, func() bool {
		projector.project(ctx)
		writer.mu.Lock()
		defer writer.mu.Unlock()
		return len(writer.hosts[tenant]) > 0 &&
			len(writer.findings[tenant]) > 0 &&
			len(writer.domains[tenant]) > 0
	}, 5*time.Second, 10*time.Millisecond,
		"the projector must materialize the discovered entities for the tenant")

	writer.mu.Lock()
	defer writer.mu.Unlock()

	host := writer.hosts[tenant][0]
	assert.Equal(t, "192.0.2.10", host.Address)
	assert.Equal(t, "mission-42", host.ScopeID, "scope is resolved from the mission, never from the payload")
	assert.Equal(t, "mission-42", host.MissionID)
	assert.Contains(t, host.OpenPorts, 8080)
	assert.Equal(t, "http-alt", host.Services[8080].Name,
		"the service must be reassembled onto its port on its host")

	finding := writer.findings[tenant][0]
	assert.Equal(t, "f1", finding.ID)
	assert.Equal(t, "Directory listing enabled", finding.Title)
	assert.Equal(t, "192.0.2.10", finding.Address,
		"a host-parented finding must carry the host's coordinate")

	assert.Equal(t, "example.test", writer.domains[tenant][0].Name)

	// Nothing must have landed under any other tenant's World.
	for other := range writer.hosts {
		assert.Equal(t, tenant, other, "a discovery must not cross tenants")
	}
}

// TestDiscoveryIngestFallsBackToTheRegistryTenant covers the callback and
// sandboxed dispatch paths, neither of which resolves a tenant: their ExecContext
// carries mission context only. The sink applies the daemon's registry tenant,
// matching how the Observe RPC's sink behaves on the same surface.
func TestDiscoveryIngestFallsBackToTheRegistryTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := brain.NewRegistry(ctx)
	d := &daemonImpl{logger: testObsLogger(), brainRegistry: reg, registryTenant: "fallback-tenant"}

	_, err := d.newDiscoveryProcessor().Process(ctx, ingest.ExecContext{MissionID: "m"}, discoveryFixture())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(reg.For("fallback-tenant").Hosts()) == 1
	}, 5*time.Second, 10*time.Millisecond,
		"a tenant-less ExecContext must land in the registry tenant's World, not nowhere")
}

// TestDiscoveryProcessorIsAlwaysConstructed states the constructor is total.
// It used to return nil when the brain registry was absent, which put the
// "is there a World to fold into?" decision at each of the three wiring sites —
// the shape that let the ingest path be imported in seven files and wired in
// none (gibson#1266). The registry is built unconditionally in Start before any
// of those sites runs, so there is no such state to degrade into.
func TestDiscoveryProcessorIsAlwaysConstructed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &daemonImpl{logger: testObsLogger(), brainRegistry: brain.NewRegistry(ctx), registryTenant: "t"}
	assert.NotNil(t, d.newDiscoveryProcessor())
}

// TestDiscoverySinkDropsEventsWithNoTenantToRouteThem checks the one case where
// dropping is correct: no resolved tenant AND no fallback means there is no
// World to submit to, and guessing one would be a cross-tenant write.
func TestDiscoverySinkDropsEventsWithNoTenantToRouteThem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := brain.NewRegistry(ctx)
	sink := ingestDiscovery(reg, "")
	sink("", brain.HostObserved{ScopeID: "s", Address: "192.0.2.99"})

	assert.Empty(t, reg.Tenants(), "an unroutable event must not conjure a World")
}
