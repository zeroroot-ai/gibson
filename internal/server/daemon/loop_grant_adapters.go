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
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/loopgrantstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// registerLoopGrant registers gibson.tenant.v1.LoopGrantService on srv
// (gibson#1612). The service keeps the loop grants in the database of the
// tenant. The daemon cannot start without the per-tenant data pool.
func (d *daemonImpl) registerLoopGrant(ctx context.Context, srv *grpc.Server, auditLog *audit.AuditLogger, pageKeys *pagetoken.Keys) error {
	if d.pool == nil {
		return errors.New("daemon: LoopGrantService needs the per-tenant data pool")
	}
	if auditLog == nil {
		return errors.New("daemon: LoopGrantService needs the audit logger")
	}
	svc, err := api.NewLoopGrantService(loopgrantstore.NewPostgresStore(d.pool), &bankLoopMembers{daemon: d}, auditLog,
		componentcatalog.LookupAgent, harness.GrantableMemberHarnessCalls(), pageKeys)
	if err != nil {
		return fmt.Errorf("daemon: LoopGrantService: %w", err)
	}
	tenantv1.RegisterLoopGrantServiceServer(srv, svc)
	d.logger.Info(ctx, "LoopGrantService registered (gibson#1612)")
	return nil
}

// bankLoopMembers reads the agent of a bank member over the bank store. The store
// reads the database of the tenant, so a member of another tenant is not found.
type bankLoopMembers struct {
	daemon *daemonImpl
	// banks overrides where the bank store comes from. Tests set it.
	banks func() (bank.Store, error)
}

var _ api.LoopGrantMembers = (*bankLoopMembers)(nil)

func (b *bankLoopMembers) AgentOfMember(ctx context.Context, tenant, memberID string) (string, error) {
	var store bank.Store
	switch {
	case b.banks != nil:
		var err error
		if store, err = b.banks(); err != nil {
			return "", err
		}
	case b.daemon.pool == nil:
		return "", errUnavailable("the data-plane pool is not up, so this daemon serves no banks")
	default:
		store = bank.NewPostgresStore(b.daemon.pool)
	}
	m, err := store.GetMember(ctx, tenant, memberID)
	if errors.Is(err, bank.ErrNotFound) {
		return "", api.ErrLoopMemberNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read the bank member: %w", err)
	}
	bk, err := store.Get(ctx, tenant, m.BankID)
	if errors.Is(err, bank.ErrNotFound) {
		return "", api.ErrLoopMemberNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read the bank of the member: %w", err)
	}
	return bk.AgentName, nil
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
type lazyLoopGrants struct {
	daemon *daemonImpl
	// stores overrides where the store comes from. Tests set it. The daemon
	// leaves it nil and reads the pool.
	stores func() (loopgrantstore.Store, error)
}

var _ harness.LoopGrantSource = (*lazyLoopGrants)(nil)

// LoopGrantFor returns the grant of the agent in the tenant. A tenant with no
// grant gives harness.ErrNoLoopGrant. The tenant is the tenant of the verified
// grant of the member, and the store reads the database of that tenant only.
func (l *lazyLoopGrants) LoopGrantFor(ctx context.Context, tenant, memberID string) (*harness.LoopGrant, error) {
	var store loopgrantstore.Store
	var err error
	if l.stores != nil {
		store, err = l.stores()
	} else {
		store, err = l.daemon.loopGrantStore()
	}
	if err != nil {
		return nil, err
	}
	g, err := store.Get(ctx, tenant, memberID)
	if errors.Is(err, loopgrantstore.ErrNotFound) {
		return nil, harness.ErrNoLoopGrant
	}
	if err != nil {
		return nil, fmt.Errorf("loop grant store: %w", err)
	}
	return &harness.LoopGrant{
		ID: g.ID, MemberID: g.MemberID, AgentName: g.AgentName, ToolClasses: g.ToolClasses,
		HarnessCalls: g.HarnessCalls, Grantor: g.Grantor,
	}, nil
}

// memberGrantRPCs derives the allowed_rpcs of the base grant of a member: the
// base surface plus the calls of the loop grant of its agent. A daemon with no
// data plane has no loop grant, so it gives the base surface.
func (d *daemonImpl) memberGrantRPCs(ctx context.Context, tenant, memberID, agentName string) ([]string, error) {
	if d.pool == nil {
		return harness.MemberBaseGrantRPCs(), nil
	}
	return deriveMemberRPCs(ctx, &lazyLoopGrants{daemon: d}, tenant, memberID, agentName)
}

// deriveMemberRPCs is the base surface plus the calls of the loop grant that
// the source holds for the agent in the tenant.
func deriveMemberRPCs(ctx context.Context, src harness.LoopGrantSource, tenant, memberID, agentName string) ([]string, error) {
	rpcs := harness.MemberBaseGrantRPCs()
	g, err := src.LoopGrantFor(ctx, tenant, memberID)
	switch {
	case errors.Is(err, harness.ErrNoLoopGrant):
		return rpcs, nil
	case err != nil:
		return nil, fmt.Errorf("read the loop grant of member %q: %w", memberID, err)
	}
	// A grant of another agent is no grant of this member.
	if g.AgentName != agentName {
		return rpcs, nil
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
	return m.daemon.memberGrantRPCs(ctx, claims.Tenant.String(), claims.TaskID, agent[len(agentSubjectPrefix):])
}
