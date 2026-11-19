// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package a2aserver serves the A2A endpoint of the daemon (gibson#1400). Only
// the Agent gateway calls it. The caller of a request is never read from the
// body. It is read from the headers that ext-authz set after it checked the
// task grant of the caller.
package a2aserver

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// Caller is the verified caller of an A2A request.
type Caller struct {
	Tenant  string
	Subject string
	Mission string
	// Task is the task of the caller: the id of its own work item.
	Task string
}

// Route is the target of an A2A request.
type Route struct {
	// Agent is the agent that receives the message.
	Agent string
	// Bank is the bank that runs the agent. Empty means an ephemeral agent.
	Bank string
}

// ErrNoCaller reports a request without the trusted caller headers.
var ErrNoCaller = errors.New("a2a: the request has no verified caller")

// ErrNoMission reports a request without a mission. A call from outside any
// mission is a later epic, and the daemon refuses it.
var ErrNoMission = errors.New("a2a: the request names no mission")

// ErrNoRoute reports a request that names no agent.
var ErrNoRoute = errors.New("a2a: the request names no agent")

type ctxKey struct{}

type callCtx struct {
	caller Caller
	route  Route
}

// FromHeaders reads the caller and the route of a request. It needs the
// tenant, the subject and the agent. It needs the mission and the task when
// requireMission is set. It trims each value, and a value with a control
// character is refused.
func FromHeaders(h http.Header, requireMission bool) (Caller, Route, error) {
	get := func(name string) string { return strings.TrimSpace(h.Get(name)) }
	c := Caller{
		Tenant:  get(modelcall.HeaderTenant),
		Subject: get(modelcall.HeaderSubject),
		Mission: get(modelcall.HeaderMission),
		Task:    get(modelcall.HeaderTask),
	}
	r := Route{Agent: get(agentcall.HeaderRouteAgent), Bank: get(agentcall.HeaderRouteBank)}
	if c.Tenant == "" || c.Subject == "" {
		return Caller{}, Route{}, ErrNoCaller
	}
	if r.Agent == "" {
		return Caller{}, Route{}, ErrNoRoute
	}
	if requireMission && (c.Mission == "" || c.Task == "") {
		return Caller{}, Route{}, ErrNoMission
	}
	return c, r, nil
}

// WithCall returns a context that holds the caller and the route.
func WithCall(ctx context.Context, c Caller, r Route) context.Context {
	return context.WithValue(ctx, ctxKey{}, callCtx{caller: c, route: r})
}

// CallFrom returns the caller and the route of a context.
func CallFrom(ctx context.Context) (Caller, Route, bool) {
	v, ok := ctx.Value(ctxKey{}).(callCtx)
	return v.caller, v.route, ok
}
