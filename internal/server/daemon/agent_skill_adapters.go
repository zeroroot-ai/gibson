// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerAgentSkill registers gibson.tenant.v1.AgentSkillService on srv (epic
// gibson#1364). The service pulls a published Agent Skill by digest with the
// registry keychain of the daemon process, the one that the signature check
// uses. It keeps the validated content in the database of the tenant. The
// daemon cannot start without the per-tenant data pool or the authorizer, so a
// missing one is an error and never a service that is silently Unimplemented.
func (d *daemonImpl) registerAgentSkill(ctx context.Context, srv *grpc.Server) error {
	if d.pool == nil {
		return errors.New("daemon: AgentSkillService needs the per-tenant data pool")
	}
	if d.authorizer == nil {
		return errors.New("daemon: AgentSkillService needs the authorizer")
	}
	keychain := supplychain.NewKeychain(registryAuthDir())
	pull := func(ctx context.Context, reference, folderName string) (*agentskill.Pulled, error) {
		return agentskill.Pull(ctx, reference, folderName, keychain)
	}
	svc, err := api.NewAgentSkillService(agentskillstore.NewPostgresStore(d.pool), pull, d.authorizer)
	if err != nil {
		return fmt.Errorf("daemon: AgentSkillService: %w", err)
	}
	tenantv1.RegisterAgentSkillServiceServer(srv, svc)
	d.logger.Info(ctx, "AgentSkillService registered (epic gibson#1364)")
	return nil
}
