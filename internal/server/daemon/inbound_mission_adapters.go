// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerInboundMission registers gibson.tenant.v1.InboundMissionService on srv
// (epic gibson#1367, gibson#1408). The record of each published definition lives
// in the database of the tenant, and the owner tuple and the caller grants live
// in FGA. The daemon cannot start without the per-tenant data pool or the
// authorizer.
func (d *daemonImpl) registerInboundMission(ctx context.Context, srv *grpc.Server, pageKeys *pagetoken.Keys) error {
	if d.pool == nil {
		return errors.New("daemon: InboundMissionService needs the per-tenant data pool")
	}
	if d.authorizer == nil {
		return errors.New("daemon: InboundMissionService needs the authorizer")
	}
	if d.targetStore == nil {
		return errors.New("daemon: InboundMissionService needs the target store")
	}
	if d.capabilityGrantSvc == nil {
		return errors.New("daemon: InboundMissionService needs the capability grant service")
	}
	d.inboundMissions = inboundmissionstore.NewPostgresStore(d.pool)
	source := &inboundMissionSource{pool: d.pool, targets: d.targetStore}
	svc, err := api.NewInboundMissionService(d.inboundMissions, source, d.authorizer, d.capabilityGrantSvc, pageKeys)
	if err != nil {
		return fmt.Errorf("daemon: InboundMissionService: %w", err)
	}
	tenantv1.RegisterInboundMissionServiceServer(srv, svc)
	d.logger.Info(ctx, "InboundMissionService registered (epic gibson#1367)")
	return nil
}

// inboundMissionSource reads the mission definitions and the targets of the
// tenant of the context.
type inboundMissionSource struct {
	pool    datapool.Pool
	targets targetGetter
}

var _ api.InboundMissionSource = (*inboundMissionSource)(nil)

// DefinitionAgents returns the agent names of the agent nodes of a definition.
func (s *inboundMissionSource) DefinitionAgents(ctx context.Context, definitionID string) ([]string, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := s.pool.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("acquire conn for tenant %s: %w", tenant, err)
	}
	defer conn.Release()
	def, err := findMissionDefinition(ctx, mission.NewConnBoundMissionStore(conn.Redis), definitionID)
	if errors.Is(err, errMissionDefinitionNotFound) {
		return nil, fmt.Errorf("%w: %s", api.ErrInboundDefinitionNotFound, definitionID)
	}
	if err != nil {
		return nil, err
	}
	var agents []string
	for _, node := range def.GetNodes() {
		if name := node.GetAgentConfig().GetAgentName(); name != "" {
			agents = append(agents, name)
		}
	}
	return agents, nil
}

// CheckTargets reads each target with the check that mission start uses, so a
// target of another tenant is not found.
func (s *inboundMissionSource) CheckTargets(ctx context.Context, targetIDs []string) error {
	caller := resolveTargetCallerTenant(ctx)
	for _, id := range targetIDs {
		if _, err := resolveTargetUUID(ctx, s.targets, id, caller); err != nil {
			return fmt.Errorf("%w: %s", api.ErrInboundTargetNotFound, id)
		}
	}
	return nil
}
