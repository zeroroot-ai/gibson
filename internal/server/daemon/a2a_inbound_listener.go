// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/agentcard"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
)

// The environment of the inbound A2A listener (epic gibson#1367). It has its own
// port, apart from the listener of the Agent gateway. The Edge calls it, and the
// call does not cross the Agent gateway.
const (
	// EnvA2AInboundAddr is the listen address of the inbound listener.
	EnvA2AInboundAddr = "GIBSON_A2A_INBOUND_ADDR"
	// EnvA2AInboundEdgeSVID is the SPIFFE ID of the Edge. It is the only peer
	// that the listener accepts.
	EnvA2AInboundEdgeSVID = "GIBSON_A2A_INBOUND_EDGE_SVID"
	// EnvA2AInboundResultTenantLimit is the most results that the daemon builds or
	// sends at one time for one tenant. The default is 4.
	EnvA2AInboundResultTenantLimit = "GIBSON_A2A_INBOUND_RESULT_TENANT_LIMIT"
	// EnvA2AInboundResultCallerLimit is the same for one caller. The default is 2.
	EnvA2AInboundResultCallerLimit = "GIBSON_A2A_INBOUND_RESULT_CALLER_LIMIT"
	// EnvA2AInboundPublicURL is the public URL of the Edge route
	// /a2a/inbound. The card of a published agent lists <URL>/<agent> as its
	// interface.
	EnvA2AInboundPublicURL = "GIBSON_A2A_INBOUND_PUBLIC_URL"
)

// inboundRoutePrefix is the last path segments of the public URL of the inbound
// route, without the slashes at the ends.
var inboundRoutePrefix = strings.Trim(agentcall.InboundPrefix, "/")

// publishedCards builds the Agent Card of a published agent. An agent that the
// tenant did not publish has no card, so the answer for it is the same as for an
// agent that does not exist.
type publishedCards struct {
	published inboundmissionstore.Store
	registry  component.ComponentRegistry
	// baseURL is the public URL of the inbound route, without a trailing slash.
	baseURL string
}

var _ a2aserver.Cards = publishedCards{}

// Card returns the card of the published agent. The interface URL of the card is
// the public Edge URL of the agent.
func (c publishedCards) Card(ctx context.Context, tenant, agent string) (*a2a.AgentCard, error) {
	if _, err := c.published.Get(ctx, tenant, agent); err != nil {
		if errors.Is(err, inboundmissionstore.ErrNotFound) {
			return nil, a2aserver.ErrNoCard
		}
		return nil, fmt.Errorf("read the publication of agent %s: %w", agent, err)
	}
	info, err := agentCardInfo(ctx, c.registry, tenant, agent)
	if err != nil {
		return nil, err
	}
	card, err := agentcard.BuildInbound(info, c.baseURL+"/"+agent)
	if err != nil {
		return nil, fmt.Errorf("build the inbound card of agent %s: %w", agent, err)
	}
	return card, nil
}

// inboundGrants decides the right of a caller to use a published definition with
// FGA: can_originate of the caller on the published definition of the agent. It is
// the one check of that right. ext-authz proves the identity and the ceiling.
type inboundGrants struct{ authorizer authz.ConsistentChecker }

var _ a2aserver.InboundGrants = inboundGrants{}

// CanOriginate asks FGA. The tenant is the tenant of the verified caller.
func (g inboundGrants) CanOriginate(ctx context.Context, c a2aserver.InboundCaller, agent string) (bool, error) {
	object, err := authz.PublishedMissionObject(c.Tenant, agent)
	if err != nil {
		return false, fmt.Errorf("form the published mission object of %s: %w", agent, err)
	}
	// Higher consistency: an unpublish or a revoke of the grant must apply at once.
	ok, err := g.authorizer.CheckHigherConsistency(ctx, c.Subject, "can_originate", object)
	if err != nil {
		return false, fmt.Errorf("check can_originate on %s: %w", object, err)
	}
	return ok, nil
}

// buildA2AInboundServer builds the inbound A2A listener (epic gibson#1367). The
// TLS layer accepts the one SPIFFE ID of the Edge and no other peer. The listener
// is required. A missing setting stops the daemon at start.
func (d *daemonImpl) buildA2AInboundServer() (*httpSubsystem, error) {
	const label = "A2A inbound listener"
	svid := strings.TrimSpace(os.Getenv(EnvA2AInboundEdgeSVID))
	if svid == "" {
		return nil, fmt.Errorf("%s: %s is not set. Set it to the SPIFFE ID of the Edge", label, EnvA2AInboundEdgeSVID)
	}
	addr := strings.TrimSpace(os.Getenv(EnvA2AInboundAddr))
	if addr == "" {
		return nil, fmt.Errorf("%s: %s is not set. Set it to the listen address, for example \":8444\"",
			label, EnvA2AInboundAddr)
	}
	edge, err := spiffeid.FromString(svid)
	if err != nil {
		return nil, fmt.Errorf("%s: %s is not a SPIFFE ID: %w", label, EnvA2AInboundEdgeSVID, err)
	}
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv(EnvA2AInboundPublicURL)), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("%s: %s is not set", label, EnvA2AInboundPublicURL)
	}
	if !strings.HasSuffix(baseURL, "/"+inboundRoutePrefix) {
		return nil, fmt.Errorf("%s: %s must end with /%s", label, EnvA2AInboundPublicURL, inboundRoutePrefix)
	}
	consistent, ok := d.authorizer.(authz.ConsistentChecker)
	if d.inboundMissions == nil || d.compRegistry == nil || !ok {
		return nil, fmt.Errorf("%s: the published missions and the component registry are not available", label)
	}
	tlsCfg, err := d.peerTLSConfig(label, edge)
	if err != nil {
		return nil, err
	}
	if d.daemonServer == nil {
		return nil, fmt.Errorf("%s: the daemon server is not available", label)
	}
	if d.brainRegistry == nil || d.pool == nil {
		return nil, fmt.Errorf("%s: the brain and the data pool are not available", label)
	}
	tenantLimit, err := envLimit(EnvA2AInboundResultTenantLimit, 4)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	callerLimit, err := envLimit(EnvA2AInboundResultCallerLimit, 2)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	runs := &inboundRuns{
		gate:      newResultGate(tenantLimit, callerLimit),
		published: d.inboundMissions, source: &inboundMissionSource{pool: d.pool, targets: d.targetStore},
		starter: d.daemonServer, registry: d.brainRegistry,
		findings: pgMissionFindings{store: pgstore.New(func() datapool.Pool { return d.pool })},
		stop: func(ctx context.Context, missionID string) error {
			return d.StopMissionWithManager(ctx, missionID, false)
		},
	}
	handler := a2aserver.NewInboundHandler(runs,
		publishedCards{published: d.inboundMissions, registry: d.compRegistry, baseURL: baseURL},
		inboundGrants{authorizer: consistent})
	lis, err := listenTLS(label, addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return d.newHTTPSubsystem(handler, lis), nil
}

// envLimit reads a positive whole number from the environment. An unset variable
// gives the default. A value that is not a whole number of at least 1 is an error,
// and it stops the daemon at start.
func envLimit(name string, def int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a whole number of at least 1, got %q", name, raw)
	}
	return n, nil
}
