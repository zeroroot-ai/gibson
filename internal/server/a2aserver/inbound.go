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

// MaxInboundRequestBytes is the size limit of the body of an inbound request. A
// message holds text and a target list, so 1 MiB is far above any real message. No
// existing constant bounds an A2A message, so this is the limit of the endpoint.
const MaxInboundRequestBytes = 1 << 20

// ErrBusy reports that the daemon builds or sends as many results as it allows for
// the tenant or for the caller. The caller retries later. It maps to a server error
// of JSON-RPC with a message that says retry.
var ErrBusy = errors.New("a2a: too many results are in work for this caller, retry later")

// responseHooks are functions that run after the response of a request is written.
type responseHooks struct{ fns []func() }

type hooksKey struct{}

// AfterResponse registers fn to run after the response of the request of ctx is
// written. A result holds its permit until then, because the JSON-RPC layer encodes
// the whole Task after the handler returns. It does nothing for a context that is
// not the context of an inbound request, and it then runs fn at once.
func AfterResponse(ctx context.Context, fn func()) {
	h, ok := ctx.Value(hooksKey{}).(*responseHooks)
	if !ok {
		fn()
		return
	}
	h.fns = append(h.fns, fn)
}

// WithResponseHooks returns a context that collects the functions of AfterResponse,
// and the function that runs them. The middleware calls it for each request and runs
// done after the response is written.
func WithResponseHooks(ctx context.Context) (hooked context.Context, done func()) {
	h := &responseHooks{}
	return context.WithValue(ctx, hooksKey{}, h), func() {
		for _, fn := range h.fns {
			fn()
		}
	}
}

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
	// Task returns the Task of a mission that the caller started through the
	// endpoint of the agent. A Task belongs to the endpoint of the agent that it
	// started from, so a read through the path of another agent finds nothing. The
	// Task state
	// is the mission state. A finished mission has the findings of that mission in
	// its result. A mission of another caller is not found.
	Task(ctx context.Context, caller InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error)
	// Cancel ends a mission that the caller started, and it returns its Task. It
	// never ends the mission of another caller. A mission in a final state cannot
	// be canceled (ErrNotCancelable).
	Cancel(ctx context.Context, caller InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error)
}

// InboundGrants decides the right of a caller to use a published definition. The
// daemon is the one place that makes this decision. ext-authz proves who the caller
// is and that it has the ceiling mission:originate, and it never sees the JSON-RPC
// method, which is in the body. The handler of each method knows what it does, so
// the handler asks: a start, a cancel and the Agent Card need the live grant, and
// a read needs only the ownership of the mission. A caller cannot name a start as a
// read, because the method that runs is the method that checks.
type InboundGrants interface {
	// CanOriginate reports whether the caller holds the grant to the published
	// definition of the agent now.
	CanOriginate(ctx context.Context, caller InboundCaller, agent string) (bool, error)
}

// ErrNoGrant reports a caller with no grant to the published definition.
var ErrNoGrant = fmt.Errorf("%w: the caller has no grant to this agent", ErrRefused)

// requireGrant refuses a caller that holds no grant now.
func requireGrant(ctx context.Context, grants InboundGrants, c InboundCaller, agent string) error {
	ok, err := grants.CanOriginate(ctx, c, agent)
	if err != nil {
		return fmt.Errorf("check the grant of %s: %w", c.Subject, err)
	}
	if !ok {
		return ErrNoGrant
	}
	return nil
}

// inboundRPC is the a2asrv.RequestHandler of the inbound listener. It serves
// SendMessage, GetTask and CancelTask. Every other method is not supported.
type inboundRPC struct {
	UnsupportedMethods
	runs   InboundRuns
	grants InboundGrants
}

var _ a2asrv.RequestHandler = (*inboundRPC)(nil)

func (h *inboundRPC) callOf(ctx context.Context) (InboundCaller, string, error) {
	c, agent, ok := inboundCallFrom(ctx)
	if !ok {
		return InboundCaller{}, "", a2a.ErrUnauthenticated
	}
	return c, agent, nil
}

// ErrApprovalAnswer reports a message that names a Task. A message to a Task is
// how an A2A client answers a request for input. An inbound caller can never
// answer an approval. The Task shows input-required, and a person in the tenant
// decides in the dashboard.
var ErrApprovalAnswer = fmt.Errorf("%w: a message to a task cannot answer an approval, "+
	"a person in the tenant decides in the dashboard", ErrRefused)

// SendMessage starts a mission for the published agent in the path.
func (h *inboundRPC) SendMessage(ctx context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	c, agent, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Message == nil || len(req.Message.Parts) == 0 {
		return nil, fmt.Errorf("%w: the request holds no message", a2a.ErrInvalidParams)
	}
	if req.Message.TaskID != "" {
		return nil, MapError(ErrApprovalAnswer)
	}
	if err := requireGrant(ctx, h.grants, c, agent); err != nil {
		return nil, MapError(err)
	}
	task, err := h.runs.Start(ctx, InboundStart{Caller: c, Agent: agent, Message: req.Message})
	if err != nil {
		return nil, MapError(err)
	}
	return task, nil
}

// GetTask returns the Task of a mission that the caller started. It needs no grant:
// a caller keeps the read of its own missions after an unpublish or a revoke of its
// grant. The ownership check of the runs decides. A revoked identity does not reach
// this point, because ext-authz refuses it.
func (h *inboundRPC) GetTask(ctx context.Context, req *a2a.GetTaskRequest) (*a2a.Task, error) {
	c, agent, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.ID == "" {
		return nil, fmt.Errorf("%w: the request names no task", a2a.ErrInvalidParams)
	}
	t, err := h.runs.Task(ctx, c, agent, req.ID)
	if err != nil {
		return nil, MapError(err)
	}
	return t, nil
}

// CancelTask ends a mission that the caller started.
func (h *inboundRPC) CancelTask(ctx context.Context, req *a2a.CancelTaskRequest) (*a2a.Task, error) {
	c, agent, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireGrant(ctx, h.grants, c, agent); err != nil {
		return nil, MapError(err)
	}
	if req == nil || req.ID == "" {
		return nil, fmt.Errorf("%w: the request names no task", a2a.ErrInvalidParams)
	}
	t, err := h.runs.Cancel(ctx, c, agent, req.ID)
	if err != nil {
		return nil, MapError(err)
	}
	return t, nil
}

// NewInboundHandler returns the HTTP handler of the inbound listener. The JSON-RPC
// endpoint of a published agent is at "/a2a/inbound/<agent>". The Agent Card of
// it is at "/a2a/inbound/<agent>/.well-known/agent-card.json".
func NewInboundHandler(runs InboundRuns, cards Cards, grants InboundGrants) http.Handler {
	mux := http.NewServeMux()
	rpc := a2asrv.NewJSONRPCHandler(&inboundRPC{runs: runs, grants: grants})
	mux.Handle("POST "+agentcall.InboundPrefix+"{agent}", inboundMiddleware(rpc))
	mux.Handle("GET "+agentcall.InboundPrefix+"{agent}"+agentcall.CardPath, inboundMiddleware(inboundCardHandler(cards, grants)))
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
		req.Body = http.MaxBytesReader(w, req.Body, MaxInboundRequestBytes)
		hooked, done := WithResponseHooks(req.Context())
		defer done()
		req = req.WithContext(hooked)
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), inboundCtxKey{}, inboundCall{caller: c, agent: agent})))
	})
}

// inboundCardHandler serves the Agent Card of the agent in the path. A published
// agent has a card. An agent that is not published has none, and the caller
// cannot tell it from an agent that does not exist.
func inboundCardHandler(cards Cards, grants InboundGrants) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, agent, ok := inboundCallFrom(req.Context())
		if !ok {
			http.Error(w, ErrNoInboundCaller.Error(), http.StatusUnauthorized)
			return
		}
		if err := requireGrant(req.Context(), grants, c, agent); err != nil {
			if errors.Is(err, ErrNoGrant) {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "the grant is not available", http.StatusInternalServerError)
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
