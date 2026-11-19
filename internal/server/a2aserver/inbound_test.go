// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// recordingCards answers the card of each agent in cards and records the last
// question.
type recordingCards struct {
	cards  map[string]*a2a.AgentCard
	err    error
	tenant string
	agent  string
	asked  int
}

func (c *recordingCards) Card(_ context.Context, tenant, agent string) (*a2a.AgentCard, error) {
	c.asked++
	c.tenant, c.agent = tenant, agent
	if c.err != nil {
		return nil, c.err
	}
	card, ok := c.cards[agent]
	if !ok {
		return nil, ErrNoCard
	}
	return card, nil
}

func inboundGet(h http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var inboundHeaders = map[string]string{
	modelcall.HeaderTenant: "acme", modelcall.HeaderSubject: "agent_principal:9",
}

func TestInboundCallerFromHeaders(t *testing.T) {
	h := http.Header{}
	h.Set(modelcall.HeaderTenant, " acme ")
	h.Set(modelcall.HeaderSubject, "agent_principal:9")
	c, err := InboundCallerFromHeaders(h)
	require.NoError(t, err)
	assert.Equal(t, InboundCaller{Tenant: "acme", Subject: "agent_principal:9"}, c)

	for name, drop := range map[string]string{"no tenant": modelcall.HeaderTenant, "no subject": modelcall.HeaderSubject} {
		g := h.Clone()
		g.Del(drop)
		_, err := InboundCallerFromHeaders(g)
		assert.ErrorIs(t, err, ErrNoInboundCaller, name)
	}
}

func TestInboundCard_ServesTheCardOfTheAgentInThePath(t *testing.T) {
	cards := &recordingCards{cards: map[string]*a2a.AgentCard{"recon": {Name: "recon"}}}
	h := NewInboundHandler(&fakeStarts{}, cards)
	// The caller sends forged route and mission headers. Only the path names the agent.
	headers := map[string]string{
		modelcall.HeaderTenant: "acme", modelcall.HeaderSubject: "agent_principal:9",
		agentcall.HeaderRouteAgent: "other", modelcall.HeaderRouteTenant: "evil", modelcall.HeaderMission: "m-1",
	}

	rec := inboundGet(h, "/a2a/inbound/recon"+agentcall.CardPath, headers)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var got a2a.AgentCard
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "recon", got.Name)
	assert.Equal(t, "recon", cards.agent)
	assert.Equal(t, "acme", cards.tenant)
}

func TestInboundCard_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		headers map[string]string
		cards   *recordingCards
		want    int
		asked   int
	}{
		{"no caller headers", "/a2a/inbound/recon"+agentcall.CardPath, nil, &recordingCards{}, http.StatusUnauthorized, 0},
		{"no subject", "/a2a/inbound/recon"+agentcall.CardPath, map[string]string{modelcall.HeaderTenant: "acme"},
			&recordingCards{}, http.StatusUnauthorized, 0},
		{"an agent that is not published", "/a2a/inbound/scanner"+agentcall.CardPath, inboundHeaders,
			&recordingCards{cards: map[string]*a2a.AgentCard{}}, http.StatusNotFound, 1},
		{"a path with an invalid agent name", agentcall.InboundPrefix + "Re_con" + agentcall.CardPath, inboundHeaders,
			&recordingCards{}, http.StatusNotFound, 0},
		{"a card source that fails", "/a2a/inbound/recon"+agentcall.CardPath, inboundHeaders,
			&recordingCards{err: errors.New("registry down")}, http.StatusInternalServerError, 1},
		{"a path off the inbound prefix", "/agents/recon/.well-known/agent-card.json", inboundHeaders,
			&recordingCards{}, http.StatusNotFound, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := inboundGet(NewInboundHandler(&fakeStarts{}, tt.cards), tt.path, tt.headers)
			assert.Equal(t, tt.want, rec.Code)
			assert.Equal(t, tt.asked, tt.cards.asked)
			assert.NotContains(t, rec.Body.String(), "registry down", "an internal cause never reaches the caller")
		})
	}
}

func TestInboundCardHandler_RefusesAContextWithNoCaller(t *testing.T) {
	rec := httptest.NewRecorder()
	inboundCardHandler(&recordingCards{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
