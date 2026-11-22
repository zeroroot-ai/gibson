// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/loopgrantstore"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// registerLoopGrant registers gibson.tenant.v1.LoopGrantService on srv
// (gibson#1612). The service keeps the loop grants in the database of the
// tenant. The daemon cannot start without the per-tenant data pool.
func (d *daemonImpl) registerLoopGrant(ctx context.Context, srv *grpc.Server, auditLog *audit.AuditLogger) error {
	if d.pool == nil {
		return errors.New("daemon: LoopGrantService needs the per-tenant data pool")
	}
	if auditLog == nil {
		return errors.New("daemon: LoopGrantService needs the audit logger")
	}
	svc, err := api.NewLoopGrantService(loopgrantstore.NewPostgresStore(d.pool), auditLog,
		componentcatalog.LookupAgent, harness.GrantableMemberHarnessCalls())
	if err != nil {
		return fmt.Errorf("daemon: LoopGrantService: %w", err)
	}
	tenantv1.RegisterLoopGrantServiceServer(srv, svc)
	d.logger.Info(ctx, "LoopGrantService registered (gibson#1612)")
	return nil
}

// loopGrantStore returns the store over the data-plane pool, or an error while
// the pool is not up. It is read per call because the pool is built during
// Start, after the options of the callback service are assembled.
func (d *daemonImpl) loopGrantStore() (loopgrantstore.Store, error) {
	if d.pool == nil {
		return nil, errUnavailable("the data-plane pool is not up, so this daemon serves no loop grants")
	}
	return loopgrantstore.NewPostgresStore(d.pool), nil
}

// lazyLoopGrants reads the loop grant of an agent for the harness callbacks.
type lazyLoopGrants struct{ daemon *daemonImpl }

var _ harness.LoopGrantSource = (*lazyLoopGrants)(nil)

// LoopGrantFor returns the grant of the agent in the tenant. A tenant with no
// grant gives harness.ErrNoLoopGrant. The tenant is the tenant of the verified
// grant of the member, and the store reads the database of that tenant only.
func (l *lazyLoopGrants) LoopGrantFor(ctx context.Context, tenant, agentName string) (*harness.LoopGrant, error) {
	store, err := l.daemon.loopGrantStore()
	if err != nil {
		return nil, err
	}
	g, err := store.Get(ctx, tenant, agentName)
	if errors.Is(err, loopgrantstore.ErrNotFound) {
		return nil, harness.ErrNoLoopGrant
	}
	if err != nil {
		return nil, fmt.Errorf("loop grant store: %w", err)
	}
	return &harness.LoopGrant{
		ID: g.ID, AgentName: g.AgentName, ToolClasses: g.ToolClasses, HarnessCalls: g.HarnessCalls, Grantor: g.Grantor,
	}, nil
}

// memberGrantRPCs derives the allowed_rpcs of the base grant of a member: the
// base surface plus the calls of the loop grant of its agent.
func (d *daemonImpl) memberGrantRPCs(ctx context.Context, tenant, agentName string) ([]string, error) {
	rpcs := harness.MemberBaseGrantRPCs()
	g, err := (&lazyLoopGrants{daemon: d}).LoopGrantFor(ctx, tenant, agentName)
	switch {
	case errors.Is(err, harness.ErrNoLoopGrant):
		return rpcs, nil
	case err != nil:
		return nil, err
	}
	return append(rpcs, harness.MemberLoopGrantRPCs(g)...), nil
}

// memberGrantRPCSource is the renewal source of the base grant of a member.
type memberGrantRPCSource struct{ daemon *daemonImpl }

var _ api.MemberGrantRPCSource = memberGrantRPCSource{}

const agentSubjectPrefix = "component:agent:"

func (m memberGrantRPCSource) MemberGrantRPCs(ctx context.Context, claims sdkcg.Claims) ([]string, error) {
	agent := claims.Subject
	if len(agent) <= len(agentSubjectPrefix) || agent[:len(agentSubjectPrefix)] != agentSubjectPrefix {
		return nil, fmt.Errorf("the subject %q is not an agent", claims.Subject)
	}
	return m.daemon.memberGrantRPCs(ctx, claims.Tenant.String(), agent[len(agentSubjectPrefix):])
}
