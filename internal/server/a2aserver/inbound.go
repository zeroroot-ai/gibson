// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// The inbound A2A endpoint (epic gibson#1367). An outside A2A client calls a
// published agent through the Edge. Only the Edge can reach this handler.
// ext-authz checked the Capability Grant JWT of the caller, the ceiling
// mission:originate and the FGA grant to the published definition. It then set
// x-gibson-tenant and x-gibson-subject with overwrite. The handler trusts these
// two headers and nothing else of the caller. It reads the agent from the path.

// InboundCaller is the verified caller of an inbound request.
type InboundCaller struct {
	// Tenant is the tenant of the key descriptor of the caller. The caller cannot
	// set it.
	Tenant string
	// Subject is the FGA principal of the caller, for example
	// "agent_principal:<id>".
	Subject string
}

// ErrNoInboundCaller reports a request without the trusted caller headers.
var ErrNoInboundCaller = errors.New("a2a: the request has no verified caller")

// InboundCallerFromHeaders reads the caller of an inbound request. It trims each
// value. It needs the tenant and the subject.
func InboundCallerFromHeaders(h http.Header) (InboundCaller, error) {
	c := InboundCaller{
		Tenant:  strings.TrimSpace(h.Get(modelcall.HeaderTenant)),
		Subject: strings.TrimSpace(h.Get(modelcall.HeaderSubject)),
	}
	if c.Tenant == "" || c.Subject == "" {
		return InboundCaller{}, ErrNoInboundCaller
	}
	return c, nil
}

type inboundCtxKey struct{}

type inboundCall struct {
	caller InboundCaller
	agent  string
}

// inboundCallFrom returns the caller and the agent of a request context.
func inboundCallFrom(ctx context.Context) (InboundCaller, string, bool) {
	v, ok := ctx.Value(inboundCtxKey{}).(inboundCall)
	return v.caller, v.agent, ok
}

// InboundStart is one message to a published agent.
type InboundStart struct {
	Caller InboundCaller
	// Agent is the agent of the path.
	Agent string
	// Message is the A2A message of the caller. Its text is the task input. Its
	// target list comes from a data part (TargetsOf).
	Message *a2a.Message
}

// InboundRuns starts the missions that inbound A2A messages ask for. Each method
// acts only on a mission that the same caller started.
type InboundRuns interface {
	// Start starts a new mission from the definition that the tenant published
	// under the agent name, and it returns the Task of the mission. A message that
	// the policy refuses gets a Task in the state rejected, and no mission starts.
	Start(ctx context.Context, req InboundStart) (*a2a.Task, error)
}

// inboundRPC is the a2asrv.RequestHandler of the inbound listener. It serves
// SendMessage. Every other method is not supported.
type inboundRPC struct {
	UnsupportedMethods
	runs InboundRuns
}

var _ a2asrv.RequestHandler = (*inboundRPC)(nil)

func (h *inboundRPC) callOf(ctx context.Context) (InboundCaller, string, error) {
	c, agent, ok := inboundCallFrom(ctx)
	if !ok {
		return InboundCaller{}, "", a2a.ErrUnauthenticated
	}
	return c, agent, nil
}

// SendMessage starts a mission for the published agent in the path.
func (h *inboundRPC) SendMessage(ctx context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	c, agent, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Message == nil || len(req.Message.Parts) == 0 {
		return nil, fmt.Errorf("%w: the request holds no message", a2a.ErrInvalidParams)
	}
	task, err := h.runs.Start(ctx, InboundStart{Caller: c, Agent: agent, Message: req.Message})
	if err != nil {
		return nil, MapError(err)
	}
	return task, nil
}

// GetTask is not served yet.
func (h *inboundRPC) GetTask(context.Context, *a2a.GetTaskRequest) (*a2a.Task, error) {
	return nil, a2a.ErrUnsupportedOperation
}

// CancelTask is not served yet.
func (h *inboundRPC) CancelTask(context.Context, *a2a.CancelTaskRequest) (*a2a.Task, error) {
	return nil, a2a.ErrUnsupportedOperation
}

// NewInboundHandler returns the HTTP handler of the inbound listener. The JSON-RPC
// endpoint of a published agent is at "/a2a/inbound/<agent>". The Agent Card of
// it is at "/a2a/inbound/<agent>/.well-known/agent-card.json".
func NewInboundHandler(runs InboundRuns, cards Cards) http.Handler {
	mux := http.NewServeMux()
	rpc := a2asrv.NewJSONRPCHandler(&inboundRPC{runs: runs})
	mux.Handle("POST "+agentcall.InboundPrefix+"{agent}", inboundMiddleware(rpc))
	mux.Handle("GET "+agentcall.InboundPrefix+"{agent}"+agentcall.CardPath, inboundMiddleware(inboundCardHandler(cards)))
	return mux
}

// inboundMiddleware reads the caller from the headers and the agent from the
// path. It refuses a request that has no caller, or a path that names no valid
// agent. The agent is never read from a header or from the body.
func inboundMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := InboundCallerFromHeaders(req.Header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		agent, _, ok := agentcall.InboundPathAgent(req.URL.Path)
		if !ok {
			http.NotFound(w, req)
			return
		}
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), inboundCtxKey{}, inboundCall{caller: c, agent: agent})))
	})
}

// inboundCardHandler serves the Agent Card of the agent in the path. A published
// agent has a card. An agent that is not published has none, and the caller
// cannot tell it from an agent that does not exist.
func inboundCardHandler(cards Cards) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, agent, ok := inboundCallFrom(req.Context())
		if !ok {
			http.Error(w, ErrNoInboundCaller.Error(), http.StatusUnauthorized)
			return
		}
		card, err := cards.Card(req.Context(), c.Tenant, agent)
		if err != nil {
			if errors.Is(err, ErrNoCard) {
				http.NotFound(w, req)
				return
			}
			http.Error(w, "the card is not available", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(card); err != nil {
			return // the client is gone
		}
	})
}
