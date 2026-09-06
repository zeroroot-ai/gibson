// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// recordingSink captures every (tenant, event) pair the processor submits.
type recordingSink struct {
	tenants []string
	events  []brain.Event
}

func (r *recordingSink) sink() WorldSink {
	return func(tenant string, ev brain.Event) {
		r.tenants = append(r.tenants, tenant)
		r.events = append(r.events, ev)
	}
}

func strp(s string) *string { return &s }
func i32p(i int32) *int32   { return &i }
func i64p(i int64) *int64   { return &i }

// fullDiscovery is a payload exercising every entity the World has vocabulary
// for, wired together by the same parent-id joins a real tool emits.
func fullDiscovery() *graphragpb.DiscoveryResult {
	return &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: strp("h1"), Ip: "10.0.0.1"},
			{Id: strp("h2"), Ip: "10.0.0.2"},
		},
		Ports: []*graphragpb.Port{
			{Id: strp("p1"), HostId: "h1", Number: 443, Protocol: "tcp"},
			{Id: strp("p2"), HostId: "h1", Number: 22, Protocol: "tcp"},
		},
		Services: []*graphragpb.Service{
			{Id: strp("s1"), PortId: "p1", Name: "https", Product: strp("nginx"), Version: strp("1.25.3")},
		},
		Endpoints: []*graphragpb.Endpoint{
			{Id: strp("e1"), ServiceId: "s1", Url: "/admin", StatusCode: i32p(401)},
		},
		Technologies: []*graphragpb.Technology{
			{Id: strp("t1"), Name: "React", Version: strp("18"), ParentId: strp("s1"), ParentType: strp("service")},
		},
		Certificates: []*graphragpb.Certificate{
			{
				Id: strp("c1"), ParentId: strp("p1"), ParentType: strp("port"),
				Subject: strp("CN=example.com"), Issuer: strp("CN=Let's Encrypt"),
				FingerprintSha256: strp("ab12"), NotAfter: i64p(1800000000),
			},
		},
		Domains: []*graphragpb.Domain{
			{Id: strp("d1"), Name: "example.com"},
		},
		Subdomains: []*graphragpb.Subdomain{
			{Id: strp("sd1"), DomainId: "d1", Name: "api", FullName: strp("api.example.com")},
		},
		Findings: []*graphragpb.Finding{
			{
				Id: strp("f1"), Title: "Exposed admin panel", Severity: "high",
				Description: strp("no auth"), ParentId: strp("h1"), ParentType: strp("host"),
			},
		},
	}
}

func eventsByKind(evs []brain.Event, kind string) []brain.Event {
	var out []brain.Event
	for _, e := range evs {
		if e.Kind() == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestProcessFoldsEveryTaxonomyEntityIntoTheWorld(t *testing.T) {
	rec := &recordingSink{}
	p := NewDiscoveryProcessor(rec.sink(), discardLogger())

	res, err := p.Process(context.Background(), ExecContext{
		MissionID:    "mission-1",
		MissionRunID: "run-1",
		TenantID:     auth.MustNewTenantID("acme"),
	}, fullDiscovery())
	require.NoError(t, err)

	// Two hosts, one domain, one subdomain, one finding.
	require.Equal(t, 5, res.EventsSubmitted, "every taxonomy entity must produce an event")
	require.Len(t, rec.events, 5)
	for _, tenant := range rec.tenants {
		assert.Equal(t, "acme", tenant, "every event must carry the resolved tenant")
	}

	hosts := eventsByKind(rec.events, "host.observed")
	require.Len(t, hosts, 2)

	h1 := hosts[0].(brain.HostObserved)
	assert.Equal(t, "10.0.0.1", h1.Address)
	assert.Equal(t, "mission-1", h1.ScopeID, "scope comes from the mission, never from the payload")
	assert.Equal(t, "mission-1", h1.MissionID)
	assert.ElementsMatch(t, []int{443, 22}, h1.OpenPorts)

	// Port 443's service, endpoint, technology and certificate all reassembled
	// onto the same port of the same host from four separate flat lists.
	assert.Equal(t, brain.ServiceInfo{Protocol: "tcp", Name: "https", Product: "nginx", Version: "1.25.3"},
		h1.Services[443])
	assert.Equal(t, []brain.EndpointInfo{{Path: "/admin", Status: 401}}, h1.Endpoints[443])
	assert.Equal(t, []brain.TechnologyInfo{{Name: "React", Version: "18"}}, h1.Technologies[443])
	assert.Equal(t, brain.CertificateInfo{
		Fingerprint: "ab12", Subject: "CN=example.com", Issuer: "CN=Let's Encrypt", NotAfter: "1800000000",
	}, h1.Certificates[443])

	// Port 22 carries only the bare protocol, and no endpoint/technology bled
	// across from port 443.
	assert.Equal(t, brain.ServiceInfo{Protocol: "tcp"}, h1.Services[22])
	assert.Empty(t, h1.Endpoints[22])
	assert.Empty(t, h1.Technologies[22])

	// The second host was seen with no ports at all and must still be observed.
	h2 := hosts[1].(brain.HostObserved)
	assert.Equal(t, "10.0.0.2", h2.Address)
	assert.Empty(t, h2.OpenPorts)

	dom := eventsByKind(rec.events, "domain.observed")
	require.Len(t, dom, 1)
	assert.Equal(t, brain.DomainObserved{ScopeID: "mission-1", Name: "example.com"}, dom[0])

	sub := eventsByKind(rec.events, "subdomain.observed")
	require.Len(t, sub, 1)
	assert.Equal(t, brain.SubdomainObserved{
		ScopeID: "mission-1", FQDN: "api.example.com", Domain: "example.com",
	}, sub[0])

	find := eventsByKind(rec.events, "finding.raised")
	require.Len(t, find, 1)
	assert.Equal(t, brain.FindingRaised{
		ID: "f1", Title: "Exposed admin panel", Description: "no auth", Severity: "high",
		ScopeID: "mission-1", Address: "10.0.0.1", MissionID: "mission-1",
		Status: brain.FindingStatusOpen,
	}, find[0], "a host-parented finding carries the host's coordinate, not its uuid")
}

func TestProcessFallsBackToAnEmptyTenantWhenNoneWasResolved(t *testing.T) {
	rec := &recordingSink{}
	p := NewDiscoveryProcessor(rec.sink(), discardLogger())

	_, err := p.Process(context.Background(), ExecContext{MissionID: "m"}, &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{{Id: strp("h1"), Ip: "10.0.0.1"}},
	})
	require.NoError(t, err)
	require.Len(t, rec.tenants, 1)
	assert.Empty(t, rec.tenants[0], "an unresolved tenant is passed through empty; the sink applies the fallback")
}

func TestProcessReportsAnErrorWhenWiredToNothing(t *testing.T) {
	p := NewDiscoveryProcessor(nil, discardLogger())

	res, err := p.Process(context.Background(), ExecContext{}, fullDiscovery())
	require.Error(t, err, "a processor with no sink must be loud, not a silent no-op")
	require.NotNil(t, res)
	assert.Zero(t, res.EventsSubmitted)
}

func TestProcessSkipsRatherThanInventsWhatTheWorldCannotHold(t *testing.T) {
	rec := &recordingSink{}
	p := NewDiscoveryProcessor(rec.sink(), discardLogger())

	res, err := p.Process(context.Background(), ExecContext{MissionID: "m"}, &graphragpb.DiscoveryResult{
		// A host with no address has no identity coordinate.
		Hosts: []*graphragpb.Host{{Id: strp("h0")}},
		// A port whose host is not in the payload.
		Ports: []*graphragpb.Port{{Id: strp("p9"), HostId: "", Number: 80}},
		// A service naming a port nobody sent.
		Services: []*graphragpb.Service{{Id: strp("s9"), PortId: "nope", Name: "http"}},
		// Out-of-taxonomy shapes: the ADR-0012 Observations case, not built yet.
		CustomNodes:           []*graphragpb.CustomNode{{NodeType: "Wharrgarbl"}},
		ExplicitRelationships: []*graphragpb.ExplicitRelationship{{FromType: "a", ToType: "b", RelationshipType: "X"}},
		Evidence:              []*graphragpb.Evidence{{Id: strp("ev1"), FindingId: "f-none", Type: "log"}},
	})
	require.NoError(t, err)
	assert.Zero(t, res.EventsSubmitted)
	assert.Empty(t, rec.events)
	assert.Equal(t, 6, res.Skipped, "everything unmappable is counted, never silently dropped")
}

func TestFindingIDIsStableAcrossRedeliveryWhenTheAgentSuppliesNone(t *testing.T) {
	d := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{{Title: "Weak cipher", Severity: "medium"}},
	}
	first, _ := discoveryEvents(ExecContext{MissionID: "m"}, d)
	second, _ := discoveryEvents(ExecContext{MissionID: "m"}, d)
	require.Len(t, first, 1)
	require.Len(t, second, 1)

	a := first[0].(brain.FindingRaised)
	b := second[0].(brain.FindingRaised)
	assert.Equal(t, a.ID, b.ID, "a redelivered finding must reduce to the same entity")
	assert.NotEmpty(t, a.ID)

	// A different scope is a different finding: the reducer dedupes by id alone,
	// so two missions must not collapse onto one entity.
	other, _ := discoveryEvents(ExecContext{MissionID: "other"}, d)
	assert.NotEqual(t, a.ID, other[0].(brain.FindingRaised).ID)
}

func TestProcessIgnoresAnEmptyOrNilDiscovery(t *testing.T) {
	rec := &recordingSink{}
	p := NewDiscoveryProcessor(rec.sink(), discardLogger())

	res, err := p.Process(context.Background(), ExecContext{}, nil)
	require.NoError(t, err)
	assert.Zero(t, res.EventsSubmitted)

	res, err = p.Process(context.Background(), ExecContext{}, &graphragpb.DiscoveryResult{})
	require.NoError(t, err)
	assert.Zero(t, res.EventsSubmitted)
	assert.Empty(t, rec.events)
}
