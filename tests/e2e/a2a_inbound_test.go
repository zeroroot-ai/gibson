// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: a2a_inbound_test.go is the exit test of the A2A inbound epic
// (gibson#1367, gibson#1413).
//
// In plain words: an outside A2A client calls a Gibson agent through the Edge. The
// call starts a mission with approved targets, and the Task holds the findings of
// that mission. The client is small. It signs each call with the Capability Grant
// JWT of an enrolled agent identity, as the SDK signer does, and it sends plain
// HTTP to the Edge.
//
// The agent of the test is an outside agent that the suite serves itself (see
// helpers.HeldAgent). The tenant admin publishes a mission definition for it with
// InboundMissionService and grants each identity of the test one right at most.
//
// The venue is the one of the secrets suite. The public api origin and the Edge
// address come from the environment that the workflow sets:
//
//	GIBSON_TEST_FIXTURES_ENABLED=true
//	GIBSON_URL              the public api origin
//	GIBSON_EDGE_ADDR        the in-cluster Envoy address, host:port
//	GIBSON_EDGE_CA_PEM_B64  the CA of the edge certificate, base64 PEM
//	DAEMON_GRPC_ADDR        the daemon mTLS listener
//
// The 10 points of the epic, and the subtest that holds each one:
//
//	 1  an enrolled client with a grant reads the Agent Card         "a granted caller reads the Agent Card"
//	 2  a client with no token gets no card                          "a client with no token gets no card"
//	 3  a message starts a mission, and the Task holds the findings  "a message starts a mission ..."
//	 4  a data part narrows the targets, and nothing else does       "a data part narrows ..." and "a target outside ..."
//	 5  a message to an agent with no published definition is refused "an agent with no published definition ..."
//	 6  a Task cancel ends the mission                               "a Task cancel ends the mission ..."
//	 7  a caller with no grant to the definition is refused          "a caller with no grant ..."
//	 8  a caller with no mission:originate ceiling is refused        "a caller with no ceiling ..."
//	 9  a revoked identity is refused                                "a revoked identity ..."
//	10  a call with a Zitadel token and no Capability Grant is refused "a call with a Zitadel token ..."
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	agentidentityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

const (
	inboundTenant = "primary"
	// inboundAgent is the agent name of the publication. It is a DNS label.
	inboundAgent = "e2e-inbound-recon"
	// inboundUnpublished is an agent that no definition is published for.
	inboundUnpublished = "e2e-inbound-unpublished"
	inboundTimeout     = 6 * time.Minute
	inboundFindingText = "INBOUND-TYPED-EVIDENCE"
)

// inboundEdge is the Envoy Edge as an outside client sees it. The client names the
// public api origin, and every connection goes to the in-cluster Envoy address
// with that host in SNI and :authority.
type inboundEdge struct {
	origin *url.URL
	addr   string
	tls    *tls.Config
}

func requireInboundEdge(t *testing.T) inboundEdge {
	t.Helper()
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is not set: the workflow sets it (exit-test-a2a-inbound.yml)", name)
		}
		return v
	}
	origin, err := url.Parse(get("GIBSON_URL"))
	require.NoError(t, err, "parse GIBSON_URL")
	require.Equal(t, "https", origin.Scheme, "GIBSON_URL must be the https api origin")
	pemBytes, err := base64.StdEncoding.DecodeString(get("GIBSON_EDGE_CA_PEM_B64"))
	require.NoError(t, err, "decode GIBSON_EDGE_CA_PEM_B64")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes), "GIBSON_EDGE_CA_PEM_B64 holds no PEM certificate")
	return inboundEdge{
		origin: origin, addr: get("GIBSON_EDGE_ADDR"),
		tls: &tls.Config{RootCAs: pool, ServerName: origin.Hostname(), MinVersion: tls.VersionTLS12},
	}
}

func (e inboundEdge) httpClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: e.tls.Clone(),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, e.addr)
			},
		},
	}
}

// inboundClient is the small A2A client of the test. It holds one enrolled
// identity and signs each call.
type inboundClient struct {
	edge      inboundEdge
	cg        *capabilitygrant.Client
	principal string
}

// token signs the Capability Grant JWT of one call. The SDK signer binds the token
// to the method of the gRPC RequestInfo of the context. The test gives it the path
// of the HTTP call, which is the value that ext-authz reads from the request.
func (c *inboundClient) token(ctx context.Context, path string) string {
	md, err := c.cg.GRPCPerRPCCredentials().GetRequestMetadata(
		credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{Method: path}))
	if err != nil {
		panic(fmt.Sprintf("sign the grant of %s: %v", path, err))
	}
	return md[capabilitygrant.MetadataHeaderCapabilityGrant]
}

// call sends one HTTP request to the Edge and returns the status and the body.
// A client with no signer sends no grant. extra holds more headers.
func (c *inboundClient) call(
	ctx context.Context, t *testing.T, method, path string, body []byte, extra map[string]string,
) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, c.edge.origin.String()+path, bytes.NewReader(body))
	require.NoError(t, err)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cg != nil {
		req.Header.Set("x-capability-grant", c.token(ctx, path))
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.edge.httpClient().Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}

// rpc sends one JSON-RPC call to the A2A endpoint of the agent.
func (c *inboundClient) rpc(
	ctx context.Context, t *testing.T, agent, method, params string, extra map[string]string,
) (int, []byte) {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params)
	return c.call(ctx, t, http.MethodPost, "/a2a/inbound/"+agent, []byte(body), extra)
}

func sendParams(text string, targets ...string) string {
	parts := fmt.Sprintf(`[{"text":%q}`, text)
	if len(targets) > 0 {
		ids, _ := json.Marshal(targets)
		parts += `,{"data":{"targets":` + string(ids) + `}}`
	}
	return `{"message":{"messageId":"m-` + fmt.Sprint(time.Now().UnixNano()) + `","role":"ROLE_USER","parts":` + parts + `]}}`
}

// rpcResult is the part of a JSON-RPC answer that the test reads.
type rpcResult struct {
	Result struct {
		Task *struct {
			ID     string `json:"id"`
			Status struct {
				State string `json:"state"`
			} `json:"status"`
			Artifacts []struct {
				Name  string `json:"name"`
				Parts []struct {
					Data json.RawMessage `json:"data"`
				} `json:"parts"`
			} `json:"artifacts"`
		} `json:"task"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// The JSON-RPC error codes that the inbound endpoint answers.
const (
	codeTaskNotFound     = -32001
	codePermissionDenied = -31403
	rejectedState        = "TASK_STATE_REJECTED"
	notAvailableText     = "the agent is not available for inbound calls"
)

// requireError checks that the answer is HTTP 200 with the JSON-RPC error code.
func requireError(t *testing.T, status int, body []byte, code int, why string) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "%s: %s", why, body)
	r := decodeRPC(t, body)
	require.NotNil(t, r.Error, "%s: %s", why, body)
	require.Equal(t, code, r.Error.Code, "%s: %s", why, body)
}

// requireRejected checks that the answer is HTTP 200 with a rejected Task that holds
// the generic text. A caller with no grant and an agent that is not published get this.
func requireRejected(t *testing.T, status int, body []byte, why string) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "%s: %s", why, body)
	r := decodeRPC(t, body)
	require.Nil(t, r.Error, "%s: %s", why, body)
	require.NotNil(t, r.Result.Task, "%s: %s", why, body)
	require.Equal(t, rejectedState, r.Result.Task.Status.State, "%s: %s", why, body)
	require.Contains(t, string(body), notAvailableText, "%s: %s", why, body)
}

// decodeTaskRPC decodes the answer of GetTask or CancelTask. The handler puts the
// Task directly in "result". Only SendMessage wraps it as {"task": ...}, so
// decodeRPC reads SendMessage answers and this reads the others. The Task goes to
// Result.Task, so the callers read both the same way.
func decodeTaskRPC(t *testing.T, body []byte) rpcResult {
	t.Helper()
	var raw struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &raw), "decode the JSON-RPC answer: %s", body)
	r := rpcResult{Error: raw.Error}
	if len(raw.Result) > 0 && string(raw.Result) != "null" {
		require.NoError(t, json.Unmarshal(raw.Result, &r.Result.Task), "decode the Task: %s", body)
	}
	return r
}

func decodeRPC(t *testing.T, body []byte) rpcResult {
	t.Helper()
	var r rpcResult
	require.NoError(t, json.Unmarshal(body, &r), "decode the JSON-RPC answer: %s", body)
	return r
}

// inboundFixture holds what every subtest needs.
type inboundFixture struct {
	ctx        context.Context
	clients    *helpers.GRPCClientSet
	comp       componentpb.ComponentServiceClient
	identities agentidentityv1.AgentIdentityServiceClient
	inbound    tenantv1.InboundMissionServiceClient
	edge       inboundEdge
	agent      *helpers.HeldAgent
	targets    [3]string
	defID      string
}

// provision creates an agent identity of the tenant, enrolls it at the Edge and
// returns a client that signs with it. Each identity is revoked when the test ends.
func (f *inboundFixture) provision(t *testing.T, name string, ceiling []string) (*inboundClient, string) {
	t.Helper()
	resp, err := f.identities.CreateAgentIdentity(f.ctx, &agentidentityv1.CreateAgentIdentityRequest{
		Name: name, Kind: agentidentityv1.PrincipalKind_PRINCIPAL_KIND_AGENT,
		Description: "identity of the A2A inbound exit test", CapabilityCeiling: ceiling,
	})
	require.NoError(t, err, "CreateAgentIdentity(%s)", name)
	principalID := resp.GetPrincipalId()
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), inboundTenant), 30*time.Second)
		defer cancel()
		_, _ = f.identities.RevokeAgentIdentity(c, &agentidentityv1.RevokeAgentIdentityRequest{PrincipalId: principalID})
	})
	cg, err := capabilitygrant.NewClient(capabilitygrant.ClientConfig{
		PlatformURL: f.edge.origin.String(), BootstrapToken: resp.GetBootstrapToken(), AgentName: name,
		HostKeyPath: filepath.Join(t.TempDir(), "host_key.json"),
	})
	require.NoError(t, err, "capabilitygrant.NewClient(%s)", name)
	cg.SetHTTPClient(f.edge.httpClient())
	require.NoError(t, cg.Discover(f.ctx), "capability-grant discovery for %s", name)
	require.NoError(t, cg.Register(f.ctx), "capability-grant registration of %s", name)
	return &inboundClient{edge: f.edge, cg: cg, principal: principalID}, principalID
}

func (f *inboundFixture) grant(t *testing.T, principalID string) {
	t.Helper()
	_, err := f.inbound.GrantInboundCaller(f.ctx, &tenantv1.GrantInboundCallerRequest{Agent: inboundAgent, IdentityId: principalID})
	require.NoError(t, err, "GrantInboundCaller(%s)", principalID)
}

// taskState polls GetTask until the Task has the state, and returns the answer.
func (f *inboundFixture) waitState(t *testing.T, c *inboundClient, id, want string) rpcResult {
	t.Helper()
	var last rpcResult
	helpers.Eventually(t, inboundTimeout, "the Task "+id+" reaches "+want, func() (bool, string) {
		status, body := c.rpc(f.ctx, t, inboundAgent, "GetTask", `{"id":"`+id+`"}`, nil)
		if status != http.StatusOK {
			return false, fmt.Sprintf("HTTP %d: %s", status, body)
		}
		last = decodeTaskRPC(t, body)
		if last.Result.Task == nil {
			return false, string(body)
		}
		return last.Result.Task.Status.State == want, last.Result.Task.Status.State
	})
	return last
}

// primaryTarget reads the primary target of a mission from the daemon.
func (f *inboundFixture) primaryTarget(t *testing.T, missionID string) string {
	t.Helper()
	resp, err := f.clients.Daemon.ListMissions(f.ctx, &daemonpb.ListMissionsRequest{})
	require.NoError(t, err, "ListMissions")
	for _, m := range resp.GetMissions() {
		if m.GetId() == missionID {
			return m.GetTargetId()
		}
	}
	t.Fatalf("the daemon lists no mission %s", missionID)
	return ""
}

// startFromMessage sends a message and returns the Task. It fails the test when no
// Task comes back.
func (f *inboundFixture) startFromMessage(t *testing.T, c *inboundClient, params string) (string, string) {
	t.Helper()
	status, body := c.rpc(f.ctx, t, inboundAgent, "SendMessage", params, nil)
	require.Equal(t, http.StatusOK, status, "SendMessage: %s", body)
	r := decodeRPC(t, body)
	require.Nil(t, r.Error, "SendMessage failed: %s", body)
	require.NotNil(t, r.Result.Task, "SendMessage gave no Task: %s", body)
	return r.Result.Task.ID, r.Result.Task.Status.State
}

func TestA2AInbound(t *testing.T) {
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), inboundTenant)

	f := &inboundFixture{
		ctx: ctx, clients: clients, edge: requireInboundEdge(t),
		comp:       componentpb.NewComponentServiceClient(clients.Conn()),
		identities: agentidentityv1.NewAgentIdentityServiceClient(clients.Conn()),
		inbound:    tenantv1.NewInboundMissionServiceClient(clients.Conn()),
	}

	// Three targets. The definition publishes all three. A message can narrow them.
	for i := range f.targets {
		name := fmt.Sprintf("inbound-e2e-target-%d.gibson.svc.cluster.local", i)
		id, terr := helpers.RegisterTestTarget(ctx, clients.Daemon, name, "http://"+name+":8080")
		require.NoError(t, terr, "register target %d", i)
		f.targets[i] = id
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), inboundTenant), 15*time.Second)
			defer cancel()
			helpers.DeleteTestTarget(c, clients.Daemon, id)
		})
	}

	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	f.agent = helpers.StartHeldAgent(ctx, t, f.comp, membership, inboundAgent)
	f.defID = helpers.CreateAgentMission(ctx, t, clients.Daemon, "a2a-inbound-exit", inboundAgent, nil)

	_, err = f.inbound.PublishInboundMission(ctx, &tenantv1.PublishInboundMissionRequest{
		Agent: inboundAgent, MissionDefinitionId: f.defID, TargetIds: f.targets[:], MaxActiveMissions: 3,
	})
	require.NoError(t, err, "PublishInboundMission")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), inboundTenant), 30*time.Second)
		defer cancel()
		_, _ = f.inbound.UnpublishInboundMission(c, &tenantv1.UnpublishInboundMissionRequest{Agent: inboundAgent})
	})

	// The identities of the test.
	ceiling := []string{"mission:originate"}
	caller, callerID := f.provision(t, "inbound-e2e-caller", ceiling)
	f.grant(t, callerID)
	noGrant, _ := f.provision(t, "inbound-e2e-nogrant", ceiling)
	noCeiling, noCeilingID := f.provision(t, "inbound-e2e-noceiling", nil)
	f.grant(t, noCeilingID)
	revoked, revokedID := f.provision(t, "inbound-e2e-revoked", ceiling)
	f.grant(t, revokedID)

	cardPath := "/a2a/inbound/" + inboundAgent + "/.well-known/agent-card.json"

	t.Run("a granted caller reads the Agent Card", func(t *testing.T) {
		var status int
		var body []byte
		// A new identity is unknown at ext-authz for a moment.
		helpers.Eventually(t, time.Minute, "the Edge serves the card to the granted caller", func() (bool, string) {
			status, body = caller.call(ctx, t, http.MethodGet, cardPath, nil, nil)
			return status == http.StatusOK, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		var card a2a.AgentCard
		require.NoError(t, json.Unmarshal(body, &card), "decode the card: %s", body)
		require.Equal(t, inboundAgent, card.Name)
		require.Len(t, card.SupportedInterfaces, 1)
		require.Equal(t, f.edge.origin.String()+"/a2a/inbound/"+inboundAgent, card.SupportedInterfaces[0].URL,
			"the card lists the public Edge URL of the agent")
	})

	t.Run("a client with no token gets no card", func(t *testing.T) {
		anonymous := &inboundClient{edge: f.edge}
		status, body := anonymous.call(ctx, t, http.MethodGet, cardPath, nil, nil)
		require.Equal(t, http.StatusUnauthorized, status, "body: %s", body)
		require.NotContains(t, string(body), inboundAgent, "no card text reaches a client with no token")
	})

	t.Run("a message starts a mission, and the Task holds the findings", func(t *testing.T) {
		// The text names a target and a range. The daemon never reads a target from text.
		id, state := f.startFromMessage(t, caller, sendParams("scan "+f.targets[2]+" and 203.0.113.0/24"))
		require.Equal(t, "TASK_STATE_SUBMITTED", state)

		work := f.agent.Next(t, inboundTimeout)
		require.Equal(t, id, work.MissionID, "the agent got work of the mission that the message started")
		require.Equal(t, f.targets[0], f.primaryTarget(t, id),
			"a target in the text changes nothing: the mission has the published targets")
		f.waitState(t, caller, id, "TASK_STATE_WORKING") // the World holds the run

		_, err := submitFinding(ctx, f.comp, work.WorkID, evidenceFinding{
			Title: "inbound finding", Description: "A finding of a mission that an A2A message started",
			Category: "e2e", Severity: "high", Confidence: 0.8,
			Evidence: []evidenceTypedRow{{Type: "log", Title: "typed", Content: inboundFindingText}},
		})
		require.NoError(t, err, "SubmitFinding")
		work.Complete()

		done := f.waitState(t, caller, id, "TASK_STATE_COMPLETED")
		require.Len(t, done.Result.Task.Artifacts, 1, "the result holds one artifact of findings")
		var res struct {
			Summary  struct{ Total int } `json:"summary"`
			Findings []struct {
				ID       string `json:"id"`
				Title    string `json:"title"`
				Severity string `json:"severity"`
				Evidence []struct {
					Tier    string `json:"tier"`
					Content string `json:"content"`
				} `json:"evidence"`
				Repro []json.RawMessage `json:"reproduction_steps"`
			} `json:"findings"`
		}
		require.NoError(t, json.Unmarshal(done.Result.Task.Artifacts[0].Parts[0].Data, &res))
		require.Equal(t, 1, res.Summary.Total, "only the findings of that one mission")
		require.Len(t, res.Findings, 1)
		require.Equal(t, "inbound finding", res.Findings[0].Title)
		require.Equal(t, "high", res.Findings[0].Severity)
		require.NotEmpty(t, res.Findings[0].ID)
		require.NotNil(t, res.Findings[0].Repro, "the finding lists its reproduction steps")
		require.Len(t, res.Findings[0].Evidence, 1)
		require.Equal(t, "EVIDENCE_TIER_TYPED", res.Findings[0].Evidence[0].Tier, "each item shows its tier")
		require.Equal(t, inboundFindingText, res.Findings[0].Evidence[0].Content, "the evidence is raw")
	})

	var doneTask string
	t.Run("a data part narrows the targets, and nothing else does", func(t *testing.T) {
		id, state := f.startFromMessage(t, caller, sendParams("scan the middle target", f.targets[1]))
		require.Equal(t, "TASK_STATE_SUBMITTED", state)
		work := f.agent.Next(t, inboundTimeout)
		require.Equal(t, id, work.MissionID)
		require.Equal(t, f.targets[1], f.primaryTarget(t, id), "the mission has exactly the target of the data part")
		work.Complete()
		f.waitState(t, caller, id, "TASK_STATE_COMPLETED")
		doneTask = id
	})

	t.Run("a target outside the definition gets rejected and no mission starts", func(t *testing.T) {
		before, err := clients.Daemon.ListMissions(ctx, &daemonpb.ListMissionsRequest{})
		require.NoError(t, err)
		id, state := f.startFromMessage(t, caller, sendParams("scan", "00000000-0000-4000-8000-000000000000"))
		require.Equal(t, "TASK_STATE_REJECTED", state)
		after, err := clients.Daemon.ListMissions(ctx, &daemonpb.ListMissionsRequest{})
		require.NoError(t, err)
		require.Equal(t, len(before.GetMissions()), len(after.GetMissions()), "no mission started for the Task %s", id)
		select {
		case w := <-f.agent.Works():
			t.Fatalf("the agent got work %s after a rejected message", w.WorkID)
		case <-time.After(5 * time.Second):
		}
	})

	t.Run("an agent with no published definition is refused", func(t *testing.T) {
		status, body := caller.rpc(ctx, t, inboundUnpublished, "SendMessage", sendParams("scan"), nil)
		requireRejected(t, status, body, "an agent that is not published")
	})

	t.Run("a Task cancel ends the mission and only the mission of the caller", func(t *testing.T) {
		id, _ := f.startFromMessage(t, caller, sendParams("scan until canceled"))
		work := f.agent.Next(t, inboundTimeout)
		require.Equal(t, id, work.MissionID)
		f.waitState(t, caller, id, "TASK_STATE_WORKING")

		// A second identity with the same grant cannot see or end the mission.
		other, otherID := f.provision(t, "inbound-e2e-other", ceiling)
		f.grant(t, otherID)
		var status int
		var body []byte
		helpers.Eventually(t, time.Minute, "the other caller reaches the Edge", func() (bool, string) {
			status, body = other.rpc(ctx, t, inboundAgent, "CancelTask", `{"id":"`+id+`"}`, nil)
			return status == http.StatusOK, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		requireError(t, status, body, codeTaskNotFound, "another caller cannot cancel the mission")
		f.waitState(t, caller, id, "TASK_STATE_WORKING")

		status, body = caller.rpc(ctx, t, inboundAgent, "CancelTask", `{"id":"`+id+`"}`, nil)
		require.Equal(t, http.StatusOK, status, "CancelTask: %s", body)
		require.Equal(t, "TASK_STATE_CANCELED", decodeTaskRPC(t, body).Result.Task.Status.State)
		f.waitState(t, caller, id, "TASK_STATE_CANCELED")
		work.Complete()
	})

	t.Run("a caller with no grant to the definition gets a rejected Task and no card", func(t *testing.T) {
		// The answer is the one of an agent that is not published: HTTP 404 for the
		// card, and a rejected Task with the same text for a message.
		helpers.Eventually(t, time.Minute, "the daemon answers the caller with no grant", func() (bool, string) {
			status, body := noGrant.call(ctx, t, http.MethodGet, cardPath, nil, nil)
			return status == http.StatusNotFound, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		status, body := noGrant.call(ctx, t, http.MethodGet, "/a2a/inbound/"+inboundUnpublished+"/.well-known/agent-card.json", nil, nil)
		require.Equal(t, http.StatusNotFound, status, "the card of an agent that is not published: %s", body)
		status, body = noGrant.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"), nil)
		requireRejected(t, status, body, "a caller with no grant starts no mission")
	})

	t.Run("after its grant is revoked a caller keeps the read and nothing else", func(t *testing.T) {
		keeper, keeperID := f.provision(t, "inbound-e2e-keeper", ceiling)
		f.grant(t, keeperID)
		var id string
		helpers.Eventually(t, time.Minute, "the keeper starts a mission", func() (bool, string) {
			status, body := keeper.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"), nil)
			r := decodeRPC(t, body)
			if status != http.StatusOK || r.Result.Task == nil {
				return false, string(body)
			}
			id = r.Result.Task.ID
			return true, ""
		})
		work := f.agent.Next(t, inboundTimeout)
		work.Complete()
		f.waitState(t, keeper, id, "TASK_STATE_COMPLETED")

		_, err := f.inbound.RevokeInboundCaller(ctx, &tenantv1.RevokeInboundCallerRequest{Agent: inboundAgent, IdentityId: keeperID})
		require.NoError(t, err, "RevokeInboundCaller")

		status, body := keeper.rpc(ctx, t, inboundAgent, "GetTask", `{"id":"`+id+`"}`, nil)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Equal(t, "TASK_STATE_COMPLETED", decodeTaskRPC(t, body).Result.Task.Status.State, "the read stays")
		status, body = keeper.rpc(ctx, t, inboundAgent, "CancelTask", `{"id":"`+id+`"}`, nil)
		requireError(t, status, body, codePermissionDenied, "the cancel needs the live grant")
		status, body = keeper.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"), nil)
		requireRejected(t, status, body, "a new start is refused")
		// The read of a task of another caller is not found.
		status, body = keeper.rpc(ctx, t, inboundAgent, "GetTask", `{"id":"`+doneTask+`"}`, nil)
		requireError(t, status, body, codeTaskNotFound, "the task of another caller is not found")
	})

	t.Run("a caller with no ceiling is refused", func(t *testing.T) {
		helpers.Eventually(t, time.Minute, "ext-authz refuses the caller with no ceiling", func() (bool, string) {
			status, body := noCeiling.call(ctx, t, http.MethodGet, cardPath, nil, nil)
			return status == http.StatusForbidden, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		status, body := noCeiling.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"), nil)
		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
	})

	t.Run("a revoked identity is refused", func(t *testing.T) {
		// The identity works before the revocation.
		helpers.Eventually(t, time.Minute, "the identity reads the card before the revocation", func() (bool, string) {
			status, body := revoked.call(ctx, t, http.MethodGet, cardPath, nil, nil)
			return status == http.StatusOK, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		_, err := f.identities.RevokeAgentIdentity(ctx, &agentidentityv1.RevokeAgentIdentityRequest{PrincipalId: revokedID})
		require.NoError(t, err, "RevokeAgentIdentity")
		// The inbound route reads the key descriptor for each call, so the refusal
		// comes at the next call. The wait covers the revoke itself.
		helpers.Eventually(t, time.Minute, "ext-authz refuses the revoked identity", func() (bool, string) {
			status, body := revoked.call(ctx, t, http.MethodGet, cardPath, nil, nil)
			return status == http.StatusUnauthorized, fmt.Sprintf("HTTP %d: %s", status, body)
		})
		status, body := revoked.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"), nil)
		require.Equal(t, http.StatusUnauthorized, status, "body: %s", body)
	})

	t.Run("a call with a Zitadel token and no Capability Grant is refused", func(t *testing.T) {
		anonymous := &inboundClient{edge: f.edge}
		// The token is not a valid Zitadel token. The Edge must refuse the call
		// whatever the token, because the inbound route accepts the grant only.
		status, body := anonymous.call(ctx, t, http.MethodGet, cardPath, nil,
			map[string]string{"Authorization": "Bearer " + strings.Repeat("a", 40)})
		require.Equal(t, http.StatusUnauthorized, status, "body: %s", body)
		status, body = anonymous.rpc(ctx, t, inboundAgent, "SendMessage", sendParams("scan"),
			map[string]string{"Authorization": "Bearer " + strings.Repeat("a", 40)})
		require.Equal(t, http.StatusUnauthorized, status, "body: %s", body)
	})
}
