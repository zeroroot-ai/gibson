// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// fakePublished answers Get from a map and records each question.
type fakePublished struct {
	inboundmissionstore.Store
	entries map[string]inboundmissionstore.Entry
	err     error
	asked   []string
	// The task methods.
	reserveErr      error
	reservedMission string
	releaseErr      error
	events          []string
	owners          map[string]string
	ownerErr        error
	// msgs holds the message keys by tenant and key, as the per-tenant database does.
	msgs      map[string]string
	forgotten []string
	takeErr   error
	forgetErr error
}

func (f *fakePublished) TakeMessage(_ context.Context, tenant, key, missionID string) (string, error) {
	if f.takeErr != nil {
		return "", f.takeErr
	}
	if f.msgs == nil {
		f.msgs = map[string]string{}
	}
	k := tenant + "/" + key
	if taken, ok := f.msgs[k]; ok {
		return taken, nil
	}
	f.msgs[k] = missionID
	return "", nil
}

func (f *fakePublished) ForgetMessage(_ context.Context, tenant, key string) error {
	f.forgotten = append(f.forgotten, tenant+"/"+key)
	delete(f.msgs, tenant+"/"+key)
	return f.forgetErr
}

func (f *fakePublished) Reserve(_ context.Context, tenant, agent, owner, missionID string) (string, error) {
	f.events = append(f.events, "reserve:"+tenant+"/"+agent+"/"+owner+"/"+missionID)
	f.reservedMission = missionID
	return "slot-1", f.reserveErr
}

func (f *fakePublished) Release(_ context.Context, _, slot string) error {
	f.events = append(f.events, "release:"+slot)
	return f.releaseErr
}

func (f *fakePublished) Owner(_ context.Context, _, missionID string) (owner, agent string, err error) {
	if f.ownerErr != nil {
		return "", "", f.ownerErr
	}
	o, ok := f.owners[missionID]
	if !ok {
		return "", "", inboundmissionstore.ErrNotFound
	}
	return o, "recon", nil
}

func (f *fakePublished) Get(_ context.Context, tenant, agent string) (*inboundmissionstore.Entry, error) {
	f.asked = append(f.asked, tenant+"/"+agent)
	if f.err != nil {
		return nil, f.err
	}
	e, ok := f.entries[agent]
	if !ok {
		return nil, inboundmissionstore.ErrNotFound
	}
	return &e, nil
}

func publishedFor(agents ...string) *fakePublished {
	f := &fakePublished{entries: map[string]inboundmissionstore.Entry{}}
	for _, a := range agents {
		f.entries[a] = inboundmissionstore.Entry{Agent: a, DefinitionID: "def-1", TargetIDs: []string{"t1"}}
	}
	return f
}

func TestPublishedCards_TheInterfaceIsThePublicEdgeURLOfTheAgent(t *testing.T) {
	cards := publishedCards{
		published: publishedFor("recon"),
		registry:  cardRegistry{},
		baseURL:   "https://edge.example/a2a/inbound",
	}
	card, err := cards.Card(context.Background(), "acme", "recon")
	require.NoError(t, err)
	require.Len(t, card.SupportedInterfaces, 1)
	assert.Equal(t, "https://edge.example/a2a/inbound/recon", card.SupportedInterfaces[0].URL)
}

func TestPublishedCards_Failures(t *testing.T) {
	ctx := context.Background()
	base := "https://edge.example/a2a/inbound"

	_, err := publishedCards{published: publishedFor(), registry: cardRegistry{}, baseURL: base}.Card(ctx, "acme", "recon")
	require.ErrorIs(t, err, a2aserver.ErrNoCard, "an agent that is not published has no card")

	broken := publishedFor("recon")
	broken.err = errors.New("db down")
	_, err = publishedCards{published: broken, registry: cardRegistry{}, baseURL: base}.Card(ctx, "acme", "recon")
	require.ErrorContains(t, err, "read the publication of agent recon")

	_, err = publishedCards{published: publishedFor("recon"), registry: kindRegistry{}, baseURL: base}.Card(ctx, "acme", "recon")
	require.ErrorIs(t, err, a2aserver.ErrNoCard, "a published agent with no instance has no card")

	_, err = publishedCards{published: publishedFor("recon"), registry: kindRegistry{err: errors.New("redis down")}, baseURL: base}.
		Card(ctx, "acme", "recon")
	require.ErrorContains(t, err, "discover agent recon")

	notAnAgent := kindRegistry{instances: []component.ComponentInfo{{Kind: "tool", Name: "recon"}}}
	_, err = publishedCards{published: publishedFor("recon"), registry: notAnAgent, baseURL: base}.Card(ctx, "acme", "recon")
	require.ErrorContains(t, err, "build the inbound card of agent recon")
}

// checkAuthorizer answers Check from a set of allowed questions and records each one.
type checkAuthorizer struct {
	authz.Authorizer
	allow  map[string]bool
	err    error
	asked  []string
	higher int
}

func (c *checkAuthorizer) CheckHigherConsistency(ctx context.Context, user, relation, object string) (bool, error) {
	c.higher++
	return c.Check(ctx, user, relation, object)
}

func (c *checkAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	key := user + "|" + relation + "|" + object
	c.asked = append(c.asked, key)
	return c.allow[key], c.err
}

func TestInboundGrants_CanOriginateAsksFGAForTheCallerOnThePublishedDefinition(t *testing.T) {
	az := &checkAuthorizer{allow: map[string]bool{"agent_principal:9|can_originate|published_mission:acme/recon": true}}
	g := inboundGrants{authorizer: az}
	caller := a2aserver.InboundCaller{Tenant: "acme", Subject: "agent_principal:9"}

	ok, err := g.CanOriginate(context.Background(), caller, "recon")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1, az.higher, "the grant is checked with higher consistency")

	ok, err = g.CanOriginate(context.Background(), caller, "scanner")
	require.NoError(t, err)
	assert.False(t, ok, "no grant to another agent")
	ok, err = g.CanOriginate(context.Background(), a2aserver.InboundCaller{Tenant: "other", Subject: "agent_principal:9"}, "recon")
	require.NoError(t, err)
	assert.False(t, ok, "the grant of one tenant is not the grant of another")

	_, err = g.CanOriginate(context.Background(), caller, "Bad/Name")
	require.Error(t, err)
	az.err = errors.New("fga down")
	_, err = g.CanOriginate(context.Background(), caller, "recon")
	require.ErrorContains(t, err, "check can_originate")
}

func inboundListenerDaemon(t *testing.T, mutate func(d *daemonImpl)) *daemonImpl {
	t.Helper()
	return a2aListenerDaemon(t, func(d *daemonImpl) {
		d.inboundMissions = publishedFor("recon")
		d.compRegistry = cardRegistry{}
		d.authorizer = &checkAuthorizer{allow: map[string]bool{
			"agent_principal:9|can_originate|published_mission:acme/recon": true,
		}}
		d.daemonServer = api.NewDaemonServer(nil, nil, nil)
		d.pool = stubPool{}
		if mutate != nil {
			mutate(d)
		}
	})
}

func TestBuildA2AInboundServer_RefusesAnIncompleteSetup(t *testing.T) {
	const svid = "spiffe://example.org/platform/envoy"
	const publicURL = "https://edge.example/a2a/inbound"
	tests := []struct {
		name      string
		svid      string
		addr      string
		publicURL string
		mutate    func(d *daemonImpl)
		wantErr   string
	}{
		{"no address", svid, "", publicURL, nil, "GIBSON_A2A_INBOUND_ADDR is not set"},
		{"the identity is not a SPIFFE ID", "not-an-id", "127.0.0.1:0", publicURL, nil, "is not a SPIFFE ID"},
		{"no public URL", svid, "127.0.0.1:0", "", nil, "GIBSON_A2A_INBOUND_PUBLIC_URL is not set"},
		{"a public URL off the route", svid, "127.0.0.1:0", "https://edge.example/gateway/agent", nil,
			"must end with /a2a/inbound"},
		{"no published missions", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.inboundMissions = nil },
			"not available"},
		{"no component registry", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.compRegistry = nil },
			"not available"},
		{"no authorizer", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.authorizer = nil }, "not available"},
		{"no daemon server", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.daemonServer = nil },
			"the daemon server is not available"},
		{"no brain registry", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.brainRegistry = nil },
			"the brain and the data pool are not available"},
		{"no data pool", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.pool = nil },
			"the brain and the data pool are not available"},
		{"no SPIFFE config", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.config.Auth.SPIFFE = nil },
			"SPIFFE is not configured"},
		{"another trust domain", "spiffe://other.org/platform/envoy", "127.0.0.1:0", publicURL, nil, "not in the trust domain"},
		{"the X.509 source is not open", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.spiffeX509Source = nil },
			"the SPIFFE X.509 source is not open"},
		{"the address cannot be bound", svid, "127.0.0.1:-1", publicURL, nil, "listen on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvA2AInboundEdgeSVID, tt.svid)
			t.Setenv(EnvA2AInboundAddr, tt.addr)
			t.Setenv(EnvA2AInboundPublicURL, tt.publicURL)
			sub, err := inboundListenerDaemon(t, tt.mutate).buildA2AInboundServer()
			require.Error(t, err)
			assert.Nil(t, sub)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBuildA2AInboundServer_RequiresTheEdgeIdentity(t *testing.T) {
	t.Setenv(EnvA2AInboundEdgeSVID, "  ")
	sub, err := inboundListenerDaemon(t, nil).buildA2AInboundServer()
	require.ErrorContains(t, err, "GIBSON_A2A_INBOUND_EDGE_SVID is not set")
	assert.Nil(t, sub)
}

func TestBuildA2AInboundServer_ServesThePublishedCardAndNothingElse(t *testing.T) {
	t.Setenv(EnvA2AInboundEdgeSVID, "spiffe://example.org/platform/envoy")
	t.Setenv(EnvA2AInboundAddr, "127.0.0.1:0")
	t.Setenv(EnvA2AInboundPublicURL, "https://edge.example/a2a/inbound/")
	sub, err := inboundListenerDaemon(t, nil).buildA2AInboundServer()
	require.NoError(t, err)
	require.NotNil(t, sub)
	defer func() { _ = sub.listener.Close() }()
	assert.Equal(t, 64<<10, sub.srv.MaxHeaderBytes)
	assert.Equal(t, 30*time.Second, sub.srv.ReadTimeout, "a slow request cannot hold a connection")
	assert.Equal(t, 2*time.Minute, sub.srv.IdleTimeout, "an idle connection ends")

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.Header.Set("x-gibson-tenant", "acme")
		req.Header.Set("x-gibson-subject", "agent_principal:9")
		rec := httptest.NewRecorder()
		sub.srv.Handler.ServeHTTP(rec, req)
		return rec
	}
	rec := get("/a2a/inbound/recon/.well-known/agent-card.json")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "https://edge.example/a2a/inbound/recon", "the trailing slash of the URL is trimmed")
	assert.Equal(t, http.StatusNotFound, get("/a2a/inbound/scanner/.well-known/agent-card.json").Code,
		"an agent that the caller has no grant to has no card, as an agent that is not published")

	// A message to an agent that the caller has no grant to gets a rejected Task and no mission.
	body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":` +
		`{"messageId":"m","role":"ROLE_USER","parts":[{"text":"scan"}]}}}`
	req := httptest.NewRequest(http.MethodPost, "/a2a/inbound/scanner", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-gibson-tenant", "acme")
	req.Header.Set("x-gibson-subject", "agent_principal:9")
	rpc := httptest.NewRecorder()
	sub.srv.Handler.ServeHTTP(rpc, req)
	assert.Equal(t, http.StatusOK, rpc.Code)
	assert.Contains(t, rpc.Body.String(), "TASK_STATE_REJECTED")
	assert.Contains(t, rpc.Body.String(), a2aserver.ReasonAgentNotAvailable)
}

func TestBuildA2AInboundServer_RefusesAResultLimitThatIsNotAPositiveNumber(t *testing.T) {
	t.Setenv(EnvA2AInboundEdgeSVID, "spiffe://example.org/platform/envoy")
	t.Setenv(EnvA2AInboundAddr, "127.0.0.1:0")
	t.Setenv(EnvA2AInboundPublicURL, "https://edge.example/a2a/inbound")
	for _, name := range []string{EnvA2AInboundResultGlobalLimit, EnvA2AInboundResultTenantLimit, EnvA2AInboundResultCallerLimit} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "0")
			sub, err := inboundListenerDaemon(t, nil).buildA2AInboundServer()
			require.ErrorContains(t, err, name)
			assert.Nil(t, sub)
		})
	}
}
