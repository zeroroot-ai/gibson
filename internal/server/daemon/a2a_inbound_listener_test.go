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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func inboundListenerDaemon(t *testing.T, mutate func(d *daemonImpl)) *daemonImpl {
	t.Helper()
	return a2aListenerDaemon(t, func(d *daemonImpl) {
		d.inboundMissions = publishedFor("recon")
		d.compRegistry = cardRegistry{}
		d.daemonServer = api.NewDaemonServer(nil, nil, nil)
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
		{"no address", svid, "", publicURL, nil, "GIBSON_A2A_INBOUND_ADDR is not"},
		{"the identity is not a SPIFFE ID", "not-an-id", "127.0.0.1:0", publicURL, nil, "is not a SPIFFE ID"},
		{"no public URL", svid, "127.0.0.1:0", "", nil, "GIBSON_A2A_INBOUND_PUBLIC_URL is not set"},
		{"a public URL off the route", svid, "127.0.0.1:0", "https://edge.example/gateway/agent", nil,
			"must end with /a2a/inbound"},
		{"no published missions", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.inboundMissions = nil },
			"not available"},
		{"no component registry", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.compRegistry = nil },
			"not available"},
		{"no daemon server", svid, "127.0.0.1:0", publicURL, func(d *daemonImpl) { d.daemonServer = nil },
			"the daemon server is not available"},
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
			sub, err := inboundListenerDaemon(t, tt.mutate).buildA2AInboundServer(context.Background())
			require.Error(t, err)
			assert.Nil(t, sub)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBuildA2AInboundServer_IsOffWithoutAnEdgeIdentity(t *testing.T) {
	t.Setenv(EnvA2AInboundEdgeSVID, "  ")
	sub, err := inboundListenerDaemon(t, nil).buildA2AInboundServer(context.Background())
	require.NoError(t, err)
	assert.Nil(t, sub)
}

func TestBuildA2AInboundServer_ServesThePublishedCardAndNothingElse(t *testing.T) {
	t.Setenv(EnvA2AInboundEdgeSVID, "spiffe://example.org/platform/envoy")
	t.Setenv(EnvA2AInboundAddr, "127.0.0.1:0")
	t.Setenv(EnvA2AInboundPublicURL, "https://edge.example/a2a/inbound/")
	sub, err := inboundListenerDaemon(t, nil).buildA2AInboundServer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sub)
	defer func() { _ = sub.listener.Close() }()
	assert.Equal(t, 64<<10, sub.srv.MaxHeaderBytes)

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
	assert.Equal(t, http.StatusNotFound, get("/a2a/inbound/scanner/.well-known/agent-card.json").Code)

	// A message to an agent with no published definition gets a rejected Task.
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
}
