// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerOutsideAgent registers gibson.tenant.v1.OutsideAgentService on srv
// (epic gibson#1366, gibson#1403). The service keeps the record of each outside
// agent in the database of the tenant and the grant to a mission in FGA. The
// daemon makes no call to an outside agent. The tenant operator renders the
// route, and the Agent gateway makes the call. The daemon cannot start without
// the per-tenant data pool or the authorizer.
func (d *daemonImpl) registerOutsideAgent(ctx context.Context, srv *grpc.Server) error {
	if d.pool == nil {
		return errors.New("daemon: OutsideAgentService needs the per-tenant data pool")
	}
	if d.authorizer == nil {
		return errors.New("daemon: OutsideAgentService needs the authorizer")
	}
	if d.secretsService == nil {
		return errors.New("daemon: OutsideAgentService needs the tenant secret store")
	}
	d.outsideAgents = outsideagentstore.NewPostgresStore(d.pool)
	svc, err := api.NewOutsideAgentService(d.outsideAgents, d.authorizer, net.DefaultResolver, d.secretsService)
	if err != nil {
		return fmt.Errorf("daemon: OutsideAgentService: %w", err)
	}
	tenantv1.RegisterOutsideAgentServiceServer(srv, svc)
	d.logger.Info(ctx, "OutsideAgentService registered (epic gibson#1366)")
	return nil
}

// outsideAgentStore returns the outside agent store that registerOutsideAgent
// built. It is nil until then. The harness callback service reads it for each
// call, because its options are assembled before the services are registered.
func (d *daemonImpl) outsideAgentStore() outsideagentstore.Store {
	return d.outsideAgents
}
