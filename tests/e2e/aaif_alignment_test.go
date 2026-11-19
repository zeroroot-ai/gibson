// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: aaif_alignment_test.go is the exit test of the AAIF alignment
// epic (gibson#1404).
//
// In plain words: a mission agent calls its model through agentgateway with Open
// Responses. The gateway asks ext-authz for each call. The daemon reads the
// gateway trace and writes one llm_call.observed event for each call, with all
// items, the token counts and the cost. One agent delegates to a second agent
// over A2A through the same gateway.
//
// The agents of the test are outside agents that the suite serves itself (see
// helpers.HeldAgent). Each one holds its mission open. The test then calls the
// gateway with the task grant of the open work item, as the agent would.
//
// The provider is the mock provider of tests/fixtures/mockprovider, behind a
// ModelProvider of the type openai. agentgateway v1.7.0 serves Open Responses to
// an OpenAI backend. The workflow deploys the mock and sets two variables:
//
//	GIBSON_E2E_MOCK_PROVIDER_URL  the https URL that the provider record holds
//	GIBSON_E2E_MOCK_RECORDED_URL  the plain http URL where the test reads /_recorded
//
// The 10 points of the epic, and the subtest that holds each one:
//
//	1  an Open Responses call is observed with all items, tokens, cost  "a call with a tool round trip ..."
//	2  the same for a streamed call                                     "a streamed call ..."
//	3  a forged tenant header and a token of another audience           "a forged tenant ..."
//	4  tenant A cannot match a route of tenant B                        "a call of tenant A cannot match ..."
//	5  a call of an ended mission is refused                            "a call of an ended mission ..."
//	6  a model that FGA forbids is refused and the provider is silent   "a model that FGA forbids ..."
//	7  an embedding call returns a vector of the mapped dimension       "an embedding call ..."
//	8  one agent delegates to a second agent over A2A                   TestAAIFAlignment_A2ADelegation
//	9  a delegation to an outside agent with no grant is refused        NOT COVERED (gibson#1403, not built)
//	10 the drop counter is zero at the end                              the workflow reads it
//
// Point 3 has no token of a second audience to hand. The test sends two stand-ins
// that the gateway must refuse: the service account token of the pod (a token
// with another issuer and another audience) and a task grant with a changed
// payload. Point 4 has no second provisioned tenant, so the test claims the route
// of tenant B with the credential of tenant A, and ext-authz must refuse it.
//
// The Anthropic path waits for an upstream release of agentgateway (gibson#1406).
// TestAAIFAlignment_AnthropicPath holds its points. The workflow does not select it.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	aaifTenant         = "primary"
	aaifProviderOpenAI = "mock-aaif-openai"
	aaifProviderClaude = "mock-aaif-anthropic"
	// aaifOpenAIModel has a price in the built-in catalog of agentgateway, so the
	// call has a cost. The mock echoes the model name of the request.
	aaifOpenAIModel = "gpt-4o-mini"
	// aaifAnthropicModel is the model name that the mock lists.
	aaifAnthropicModel = "claude-sonnet-5-5"
	aaifEmbeddingModel = "text-embedding-3-small"
	aaifAgent          = "e2e-aaif-agent"
	aaifAgentA         = "e2e-a2a-caller"
	aaifAgentB         = "e2e-a2a-callee"

	aaifMockURLEnv      = "GIBSON_E2E_MOCK_PROVIDER_URL"
	aaifMockRecordedEnv = "GIBSON_E2E_MOCK_RECORDED_URL"
	aaifSATokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// The fixed content of the mock provider. They must equal the values in
	// tests/fixtures/mockprovider/main.go. That package is a command, so the
	// test cannot import them.
	aaifMockReply         = "I will run a port scan."
	aaifMockPromptTokens  = 120
	aaifMockOutputTokens  = 45
	aaifMockEmbeddingDims = 3

	// The operator renders the route about every 30 seconds, and the gateway
	// takes a moment to load it.
	aaifRouteTimeout   = 4 * time.Minute
	aaifTraceTimeout   = 2 * time.Minute
	aaifMissionTimeout = 6 * time.Minute
	aaifToolCallID     = "call_e2e_1"
	aaifToolResult     = "PORT-22-OPEN-E2E"
)

// aaifMockRequest is one request that the mock provider recorded.
type aaifMockRequest struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// aaifMockRequests reads the requests that the mock provider recorded.
func aaifMockRequests(t *testing.T) []aaifMockRequest {
	t.Helper()
	base := os.Getenv(aaifMockRecordedEnv)
	if base == "" {
		t.Fatalf("%s is not set: the AAIF test needs the URL that serves /_recorded of the mock provider", aaifMockRecordedEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/_recorded", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "read the requests of the mock provider")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the mock provider answered: %s", body)
	var out []aaifMockRequest
	require.NoError(t, json.Unmarshal(body, &out), "decode the record: %s", body)
	return out
}

// aaifMockCount returns how many model calls the mock provider got.
func aaifMockCount(t *testing.T) int {
	t.Helper()
	n := 0
	for _, r := range aaifMockRequests(t) {
		if r.Method == http.MethodPost {
			n++
		}
	}
	return n
}

// aaifSetup holds the parts that each AAIF test needs.
type aaifSetup struct {
	ctx      context.Context
	clients  *helpers.GRPCClientSet
	comp     componentpb.ComponentServiceClient
	world    worldpb.WorldServiceClient
	provs    tenantv1.ProviderServiceClient
	access   tenantv1.ModelAccessServiceClient
	member   tenantv1.MembershipServiceClient
	targetID string
}

func newAAIFSetup(t *testing.T) *aaifSetup {
	t.Helper()
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), aaifTenant)
	s := &aaifSetup{
		ctx: ctx, clients: clients,
		comp:   componentpb.NewComponentServiceClient(clients.Conn()),
		world:  worldpb.NewWorldServiceClient(clients.Conn()),
		provs:  tenantv1.NewProviderServiceClient(clients.Conn()),
		access: tenantv1.NewModelAccessServiceClient(clients.Conn()),
		member: tenantv1.NewMembershipServiceClient(clients.Conn()),
	}
	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, aaifTenant), clients.Daemon, targetID)
	})
	s.targetID = targetID
	return s
}

// ensureProvider saves a provider of the tenant that points at the mock provider.
// The context window is stated, so the save makes no list call. The tenant
// operator renders the route later, and the first call waits for it.
func (s *aaifSetup) ensureProvider(t *testing.T, name, providerType, model string) {
	t.Helper()
	mockURL := os.Getenv(aaifMockURLEnv)
	if mockURL == "" {
		t.Fatalf("%s is not set: the AAIF test needs the https URL of the mock provider", aaifMockURLEnv)
	}
	// The mock serves a certificate of a private CA. The provider names the tenant
	// secret that holds that CA, and the gateway verifies the mock against it.
	caSecret := saveMockProviderCA(s.ctx, t, aaifTenant, secretsv1.NewSecretsServiceClient(s.clients.Conn()))
	_, err := s.provs.CreateProvider(s.ctx, &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: name, Type: providerType, SetAsDefault: true,
		DefaultModel: model, DefaultModelContextWindow: 200000,
		Credentials: mockProviderCredentials(mockURL, caSecret),
	}})
	if status.Code(err) != codes.AlreadyExists {
		require.NoError(t, err, "CreateProvider(%s)", name)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), aaifTenant), 30*time.Second)
		defer cancel()
		_, _ = s.provs.DeleteProvider(c, &tenantv1.DeleteProviderRequest{Name: name})
	})
}

func (s *aaifSetup) providerGrant(provider string) *tenantv1.AccessGrant {
	return &tenantv1.AccessGrant{
		TenantId: aaifTenant, SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT, SubjectId: aaifTenant,
		TargetKind: tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, TargetId: provider,
	}
}

// startHeldMission runs a mission of one outside agent and returns its open work item.
func (s *aaifSetup) startHeldMission(
	t *testing.T, agent *helpers.HeldAgent, name string,
) (*helpers.MissionRun, *helpers.HeldWork) {
	t.Helper()
	defID := helpers.CreateAgentMission(s.ctx, t, s.clients.Daemon, name, agent.Name, nil)
	run := helpers.StartMission(s.ctx, t, s.clients.Daemon, defID, s.targetID)
	w := agent.Next(t, aaifMissionTimeout)
	require.NotEmpty(t, w.MissionID, "the work item of mission %s names no mission", name)
	require.NotEmpty(t, w.TaskGrant, "the work item of mission %s holds no task grant: the agent cannot call a gateway", name)
	return run, w
}

// respondWhenRouted sends an Open Responses call and retries while no route
// matches, because the operator renders the route of a new provider after the save.
func respondWhenRouted(
	ctx context.Context, t *testing.T, g *helpers.GatewayAccess, req modelclient.Request,
) *modelclient.Response {
	t.Helper()
	c, err := g.Client()
	require.NoError(t, err)
	var resp *modelclient.Response
	helpers.Eventually(t, aaifRouteTimeout, "the gateway serves the route of the provider", func() (bool, string) {
		r, cerr := c.Respond(ctx, g.Caller(), g.Target(), req)
		if cerr == nil {
			resp = r
			return true, ""
		}
		var api *modelclient.APIError
		if errors.As(cerr, &api) && api.Retryable() {
			return false, cerr.Error()
		}
		t.Fatalf("the model call failed and a retry does not help: %v", cerr)
		return false, ""
	})
	return resp
}

// toolRoundTrip is the input of point 1: a user message, a prior tool call and its result.
func toolRoundTrip() modelclient.Request {
	return modelclient.Request{Input: []modelclient.Item{
		modelclient.UserMessage("Scan the host 10.0.0.5."),
		modelclient.FunctionCall(aaifToolCallID, "nmap", `{"target":"10.0.0.5"}`),
		modelclient.FunctionCallOutput(aaifToolCallID, aaifToolResult),
	}}
}

// observedCalls reads the llm_call.observed events of a mission.
func (s *aaifSetup) observedCalls(t *testing.T, missionID string) []helpers.ObservedLlmCall {
	t.Helper()
	events, err := helpers.ReadTimeline(s.ctx, s.world, missionID)
	require.NoError(t, err)
	var out []helpers.ObservedLlmCall
	for _, ev := range helpers.OfKind(events, "llm_call.observed") {
		call, perr := helpers.ParseLlmCallObserved(ev.Summary)
		require.NoError(t, perr, "read an llm_call.observed event")
		out = append(out, call)
	}
	return out
}

// waitObserved waits until the Timeline of the mission holds a call that satisfies match.
func (s *aaifSetup) waitObserved(
	t *testing.T, missionID, what string, match func(helpers.ObservedLlmCall) bool,
) helpers.ObservedLlmCall {
	t.Helper()
	var found helpers.ObservedLlmCall
	helpers.Eventually(t, aaifTraceTimeout, what, func() (bool, string) {
		calls := s.observedCalls(t, missionID)
		for _, c := range calls {
			if match(c) {
				found = c
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d llm_call.observed events, none matches", len(calls))
	})
	return found
}

func itemsContain(c helpers.ObservedLlmCall, want string) bool {
	for _, it := range c.Items {
		if strings.Contains(it, want) {
			return true
		}
	}
	return false
}

// requireCallPoints checks the fields that points 1 and 2 name.
func requireCallPoints(t *testing.T, c helpers.ObservedLlmCall, wantInOutput string) {
	t.Helper()
	require.Equal(t, aaifMockPromptTokens, c.PromptTokens, "the event must hold the input tokens of the provider")
	require.Equal(t, aaifMockOutputTokens, c.CompletionTokens, "the event must hold the output tokens of the provider")
	require.NotEmpty(t, c.Provider, "the event must name the provider")
	require.True(t, itemsContain(c, wantInOutput), "the event must hold the output item %q; items: %q", wantInOutput, c.Items)
}

// aaifOpenResponsesPoints runs points 1 and 2 on a held work item for one provider.
func aaifOpenResponsesPoints(
	t *testing.T, s *aaifSetup, g *helpers.GatewayAccess, work *helpers.HeldWork, wantMockPath string, wantCost bool,
) {
	t.Helper()
	t.Run("a call with a tool round trip is observed with all items, tokens and cost", func(t *testing.T) {
		before := aaifMockCount(t)
		resp := respondWhenRouted(s.ctx, t, g, toolRoundTrip())
		require.Equal(t, aaifMockReply, resp.OutputText(), "the reply of the mock must reach the agent")
		reqs := aaifMockRequests(t)
		require.Greater(t, len(reqs), before, "the mock provider must get the call")
		last := reqs[len(reqs)-1]
		require.Equal(t, wantMockPath, last.Path)
		require.Contains(t, last.Body, aaifToolResult, "the provider must get the tool result that the agent sent")
		for name := range last.Header {
			require.False(t, strings.HasPrefix(strings.ToLower(name), "x-gibson-"), "the provider must get no %s header", name)
		}
		require.Empty(t, last.Header.Get("x-capability-grant"), "the provider must not get the grant of the agent")

		call := s.waitObserved(t, work.MissionID, "llm_call.observed holds the call with the tool round trip",
			func(c helpers.ObservedLlmCall) bool { return itemsContain(c, aaifToolResult) })
		requireCallPoints(t, call, aaifMockReply)
		require.True(t, itemsContain(call, "function_call"), "the event must hold the prior tool call; items: %q", call.Items)
		require.True(t, itemsContain(call, "function_call_output"), "the event must hold the tool result; items: %q", call.Items)
		if wantCost {
			require.NotEmpty(t, call.Cost, "the event must hold the cost of a priced model")
			require.NotEqual(t, "0", call.Cost, "an unknown cost is empty and never 0")
		}
	})

	t.Run("a streamed call is observed with all items, tokens and cost", func(t *testing.T) {
		c, err := g.Client()
		require.NoError(t, err)
		stream, err := c.Stream(s.ctx, g.Caller(), g.Target(), toolRoundTrip())
		require.NoError(t, err, "open the stream")
		var text strings.Builder
		completed := false
		for stream.Next() {
			ev := stream.Event()
			switch ev.Type {
			case modelclient.EventTextDelta:
				text.WriteString(ev.Delta)
			case modelclient.EventCompleted:
				completed = true
			}
		}
		require.NoError(t, stream.Err(), "read the stream")
		require.NoError(t, stream.Close())
		require.True(t, completed, "the stream must end with response.completed")
		require.Equal(t, aaifMockReply, text.String())

		helpers.Eventually(t, aaifTraceTimeout, "two llm_call.observed events", func() (bool, string) {
			n := len(s.observedCalls(t, work.MissionID))
			return n >= 2, fmt.Sprint(n)
		})
		calls := s.observedCalls(t, work.MissionID)
		seen := map[string]bool{}
		for _, call := range calls {
			seen[call.CallID] = true
		}
		require.Len(t, seen, len(calls), "each call must have its own call id")
		requireCallPoints(t, calls[len(calls)-1], aaifMockReply)
	})
}

// TestAAIFAlignment_OpenAIPath holds points 1 to 7 of the epic on an openai
// provider, with the mock provider behind it.
func TestAAIFAlignment_OpenAIPath(t *testing.T) {
	s := newAAIFSetup(t)
	s.ensureProvider(t, aaifProviderOpenAI, "openai", aaifOpenAIModel)
	agent := helpers.StartHeldAgent(s.ctx, t, s.comp, s.member, aaifAgent)
	run, work := s.startHeldMission(t, agent, "aaif-alignment-exit-openai")

	g, err := helpers.ResolveGateway(s.ctx, s.comp, aaifTenant, work.ComponentWork)
	require.NoError(t, err, "ResolveModel for the work item of the mission")
	require.Equal(t, aaifProviderOpenAI, g.Provider, "the slot must resolve to the provider of the test")
	require.NotEmpty(t, g.URL, "ResolveModel must name the gateway")
	require.NotEmpty(t, g.RouteHeaders, "ResolveModel must name the route headers")

	aaifOpenResponsesPoints(t, s, g, work, "/v1/responses", true)

	body, err := json.Marshal(modelclient.Request{Model: g.Model, Input: toolRoundTrip().Input})
	require.NoError(t, err)

	t.Run("a forged tenant header and a token of another audience are refused", func(t *testing.T) {
		ctx := s.ctx
		before := aaifMockCount(t)

		st, text, err := g.RawCall(ctx, http.MethodPost, "/v1/responses", body, map[string]string{"x-gibson-route-tenant": "forged-tenant"})
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "a forged route tenant must be refused; got %d %s", st, text)

		st, text, err = g.RawCall(ctx, http.MethodPost, "/v1/responses", body, map[string]string{"x-capability-grant": ""})
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "a call with no grant must be refused; got %d %s", st, text)

		sa, rerr := os.ReadFile(aaifSATokenPath)
		require.NoError(t, rerr, "the pod needs its service account token: it is the token of another audience")
		st, text, err = g.RawCall(ctx, http.MethodPost, "/v1/responses", body,
			map[string]string{"x-capability-grant": strings.TrimSpace(string(sa))})
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "a token of another audience must be refused; got %d %s", st, text)

		parts := strings.Split(g.Grant, ".")
		require.Len(t, parts, 3, "the task grant is a compact JWT")
		parts[1] += "AA"
		st, text, err = g.RawCall(ctx, http.MethodPost, "/v1/responses", body,
			map[string]string{"x-capability-grant": strings.Join(parts, ".")})
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "a grant with a changed payload must be refused; got %d %s", st, text)

		require.Equal(t, before, aaifMockCount(t), "the provider must get no request from a refused call")

		// The trusted header is set by ext-authz, never by the caller. A caller
		// value either fails the call or never reaches the provider.
		st, text, err = g.RawCall(ctx, http.MethodPost, "/v1/responses", body, map[string]string{"x-gibson-tenant": "forged-tenant"})
		require.NoError(t, err)
		if !helpers.IsRefusal(st) {
			require.Equal(t, http.StatusOK, st, "a forged trusted header must give 200 or a refusal; got %d %s", st, text)
			reqs := aaifMockRequests(t)
			require.Greater(t, len(reqs), before)
			for name, vals := range reqs[len(reqs)-1].Header {
				require.NotContains(t, strings.Join(vals, ","), "forged-tenant", "the provider must not see the forged value in %s", name)
			}
		}
	})

	t.Run("a call of tenant A cannot match a route of tenant B", func(t *testing.T) {
		before := aaifMockCount(t)
		// The credential of tenant A claims the route of tenant B, with the
		// provider name of tenant A.
		st, text, err := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, map[string]string{"x-gibson-route-tenant": "tenant-b"})
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "tenant A must not match a route of tenant B; got %d %s", st, text)
		// A provider name that tenant A does not hold matches no route.
		st, text, err = g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, map[string]string{"x-gibson-route-provider": "no-such-provider"})
		require.NoError(t, err)
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}, st,
			"a provider of no tenant must match no route; got %d %s", st, text)
		require.Equal(t, before, aaifMockCount(t), "the provider must get no request from a refused call")
	})

	t.Run("an embedding call returns a vector of the mapped dimension", func(t *testing.T) {
		c, err := g.Client()
		require.NoError(t, err)
		before := aaifMockCount(t)
		res, err := c.Embeddings(s.ctx, g.Caller(), g.Target(), aaifEmbeddingModel, []string{"alpha", "beta"})
		require.NoError(t, err, "the embedding call must pass the gateway")
		require.Len(t, res.Vectors, 2, "one vector for each input")
		for i, v := range res.Vectors {
			require.Len(t, v, aaifMockEmbeddingDims, "vector %d must have the dimension that the mock returns", i)
		}
		require.Greater(t, aaifMockCount(t), before)
		reqs := aaifMockRequests(t)
		require.Equal(t, "/v1/embeddings", reqs[len(reqs)-1].Path)
	})

	t.Run("a model that FGA forbids is refused and the provider gets no request", func(t *testing.T) {
		grant := s.providerGrant(g.Provider)
		// The tenant holds can_use on the provider and on each model of it through
		// the default grant. A revoke of the grant on the provider forbids the model.
		_, err := s.access.RevokeAccess(s.ctx, &tenantv1.RevokeAccessRequest{
			SubjectKind: grant.GetSubjectKind(), SubjectId: grant.GetSubjectId(),
			TargetKind: grant.GetTargetKind(), TargetId: grant.GetTargetId(),
		})
		require.NoError(t, err, "RevokeAccess of the tenant grant on %s", g.Provider)
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), aaifTenant), 30*time.Second)
			defer cancel()
			_, _ = s.access.GrantAccess(c, &tenantv1.GrantAccessRequest{Grant: grant})
		})
		var before int
		helpers.Eventually(t, time.Minute, "the gateway refuses the model after the revoke", func() (bool, string) {
			before = aaifMockCount(t)
			st, text, cerr := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, nil)
			if cerr != nil {
				return false, cerr.Error()
			}
			return helpers.IsRefusal(st), fmt.Sprintf("%d %s", st, text)
		})
		st, text, err := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, nil)
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "the model must stay refused; got %d %s", st, text)
		require.Equal(t, before, aaifMockCount(t), "the provider must get no request for a model that FGA forbids")

		// The grant comes back, so the next points have a model.
		_, err = s.access.GrantAccess(s.ctx, &tenantv1.GrantAccessRequest{Grant: grant})
		require.NoError(t, err, "GrantAccess of the tenant grant")
		helpers.Eventually(t, time.Minute, "the gateway serves the model again", func() (bool, string) {
			st, text, cerr := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, nil)
			if cerr != nil {
				return false, cerr.Error()
			}
			return st == http.StatusOK, fmt.Sprintf("%d %s", st, text)
		})
	})

	work.Complete()
	require.Equal(t, "mission_completed", run.Wait(t, aaifMissionTimeout).EventType, "the mission must complete")

	t.Run("a call of an ended mission is refused", func(t *testing.T) {
		before := aaifMockCount(t)
		var last string
		helpers.Eventually(t, 2*time.Minute, "the gateway refuses the grant of an ended mission", func() (bool, string) {
			st, text, cerr := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, nil)
			if cerr != nil {
				return false, cerr.Error()
			}
			last = fmt.Sprintf("%d %s", st, text)
			return helpers.IsRefusal(st), last
		})
		// A refused call reaches no provider. The calls that the poll let through
		// before the refusal are counted before the check, so the check starts here.
		before = aaifMockCount(t)
		st, text, err := g.RawCall(s.ctx, http.MethodPost, "/v1/responses", body, nil)
		require.NoError(t, err)
		require.True(t, helpers.IsRefusal(st), "the call of an ended mission must stay refused; got %d %s", st, text)
		require.Equal(t, before, aaifMockCount(t), "the provider must get no request from an ended mission")
	})
}

// TestAAIFAlignment_AnthropicPath holds points 1 and 2 for an anthropic provider.
// The workflow does not select this test yet. agentgateway v1.7.0 serves Open
// Responses to an OpenAI backend only. The Anthropic path waits for an upstream
// release (gibson#1406). The mock provider answers POST /v1/messages in the
// Anthropic Messages format, which is where the gateway sends the call then.
func TestAAIFAlignment_AnthropicPath(t *testing.T) {
	s := newAAIFSetup(t)
	s.ensureProvider(t, aaifProviderClaude, "anthropic", aaifAnthropicModel)
	agent := helpers.StartHeldAgent(s.ctx, t, s.comp, s.member, aaifAgent+"-anthropic")
	run, work := s.startHeldMission(t, agent, "aaif-alignment-exit-anthropic")
	g, err := helpers.ResolveGateway(s.ctx, s.comp, aaifTenant, work.ComponentWork)
	require.NoError(t, err, "ResolveModel for the work item of the mission")
	require.Equal(t, aaifProviderClaude, g.Provider)
	aaifOpenResponsesPoints(t, s, g, work, "/v1/messages", true)
	work.Complete()
	require.Equal(t, "mission_completed", run.Wait(t, aaifMissionTimeout).EventType)
}

// TestAAIFAlignment_A2ADelegation holds point 8: one agent delegates to a second
// agent over A2A through the Agent gateway, and the World holds both runs.
func TestAAIFAlignment_A2ADelegation(t *testing.T) {
	s := newAAIFSetup(t)
	caller := helpers.StartHeldAgent(s.ctx, t, s.comp, s.member, aaifAgentA)
	callee := helpers.StartHeldAgent(s.ctx, t, s.comp, s.member, aaifAgentB)
	run, workA := s.startHeldMission(t, caller, "aaif-alignment-exit-a2a")

	route, err := s.comp.ResolveAgent(s.ctx, &componentpb.ResolveAgentRequest{WorkId: workA.WorkID, Name: aaifAgentB})
	require.NoError(t, err, "ResolveAgent(%s) for the work item of the caller", aaifAgentB)
	require.NotEmpty(t, route.GetGatewayUrl(), "ResolveAgent must name the Agent gateway")
	require.NotEmpty(t, route.GetRouteHeaders(), "ResolveAgent must name the route headers")

	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("Please run the callee procedure."))
	sendBody, err := json.Marshal(&a2a.SendMessageRequest{Message: msg})
	require.NoError(t, err)
	rpc := fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":%s}`, sendBody)

	type a2aReply struct {
		status int
		body   string
		err    error
	}
	replyCh := make(chan a2aReply, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), aaifMissionTimeout)
		defer cancel()
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, route.GetGatewayUrl(), bytes.NewReader([]byte(rpc)))
		if rerr != nil {
			replyCh <- a2aReply{err: rerr}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("A2A-Version", "1.0")
		req.Header.Set("x-capability-grant", workA.TaskGrant)
		for k, v := range route.GetRouteHeaders() {
			req.Header.Set(k, v)
		}
		client, cerr := helpers.HTTPClientWithCA(route.GetGatewayCaPem())
		if cerr != nil {
			replyCh <- a2aReply{err: cerr}
			return
		}
		resp, derr := client.Do(req)
		if derr != nil {
			replyCh <- a2aReply{err: derr}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		replyCh <- a2aReply{status: resp.StatusCode, body: string(b)}
	}()

	workB := callee.Next(t, aaifMissionTimeout)
	require.Equal(t, workA.MissionID, workB.MissionID, "the delegated run must be a work item of the mission of the caller")
	workB.Complete()

	select {
	case r := <-replyCh:
		require.NoError(t, r.err, "send the A2A message through the Agent gateway")
		require.Equal(t, http.StatusOK, r.status, "the Agent gateway answered: %s", r.body)
		require.NotContains(t, r.body, `"error"`, "the JSON-RPC reply must hold no error: %s", r.body)
		require.Contains(t, r.body, `"result"`, "the JSON-RPC reply must hold a result: %s", r.body)
	case <-time.After(aaifMissionTimeout):
		t.Fatal("the A2A message got no reply after the callee finished")
	}

	helpers.Eventually(t, aaifTraceTimeout, "the World holds the runs of both agents", func() (bool, string) {
		events, rerr := helpers.ReadTimeline(s.ctx, s.world, workA.MissionID)
		if rerr != nil {
			return false, rerr.Error()
		}
		sawA, sawB, childLinked := false, false, false
		for _, ev := range helpers.OfKind(events, "work.dispatched") {
			if strings.Contains(ev.Summary, "Target:"+aaifAgentA+" ") {
				sawA = true
			}
			if strings.Contains(ev.Summary, "Target:"+aaifAgentB+" ") {
				sawB = true
				childLinked = !strings.Contains(ev.Summary, "ParentID: ") && strings.Contains(ev.Summary, "ParentID:")
			}
		}
		return sawA && sawB && childLinked, fmt.Sprintf("caller=%t callee=%t linked=%t in %d events", sawA, sawB, childLinked, len(events))
	})

	workA.Complete()
	require.Equal(t, "mission_completed", run.Wait(t, aaifMissionTimeout).EventType, "the mission must complete")
}
