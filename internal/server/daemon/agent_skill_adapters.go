// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerAgentSkill registers gibson.tenant.v1.AgentSkillService on srv (epic
// gibson#1364). The service pulls a published Agent Skill by digest, with the
// credential of a tenant secret or none. It keeps the validated content in the database of the tenant. The
// daemon cannot start without the per-tenant data pool or the authorizer, so a
// missing one is an error and never a service that is silently Unimplemented.
func (d *daemonImpl) registerAgentSkill(ctx context.Context, srv *grpc.Server, pageKeys *pagetoken.Keys) error {
	if d.pool == nil {
		return errors.New("daemon: AgentSkillService needs the per-tenant data pool")
	}
	if d.authorizer == nil {
		return errors.New("daemon: AgentSkillService needs the authorizer")
	}
	// A tenant reference is pulled with the guarded puller and the credential of
	// a tenant secret. It never gets the credential of the daemon process.
	puller := agentskill.NewPuller()
	pull := func(ctx context.Context, reference, folderName string, kc authn.Keychain) (*agentskill.Pulled, error) {
		return puller.Pull(ctx, reference, folderName, kc)
	}
	secretReader := daemonSecretReader{d: d}
	d.agentSkills = agentskillstore.NewPostgresStore(d.pool)

	// The operator source. A reference that does not pull is not offered, and the
	// daemon still starts, as for a component image that does not verify.
	var refs []config.SharedAgentSkillConfig
	if d.config != nil {
		refs = d.config.SharedAgentSkills
	}
	shared, loadErr := loadSharedAgentSkills(ctx, refs,
		operatorSkillPuller(registryAuthDir(), supplychain.NewKeychain), d.logger.Slog())
	if loadErr != nil {
		d.logger.Warn(ctx, "shared Agent Skills not offered (non-fatal)", "error", loadErr)
	}
	d.sharedAgentSkills = shared
	svc, err := api.NewAgentSkillService(d.agentSkills, pull, d.authorizer, secretReader, shared, pageKeys)
	if err != nil {
		return fmt.Errorf("daemon: AgentSkillService: %w", err)
	}
	tenantv1.RegisterAgentSkillServiceServer(srv, svc)
	d.logger.Info(ctx, "AgentSkillService registered (epic gibson#1364)")
	return nil
}

// agentSkillStore returns the Agent Skill store that registerAgentSkill built. It
// is nil until then. The harness callback service reads it for each call,
// because its options are assembled before the services are registered.
func (d *daemonImpl) agentSkillStore() agentskillstore.Store {
	return d.agentSkills
}

// skillFileStore returns the Agent Skill store for the files of a skill-script
// call, or nil while the store is not built. It answers a nil interface, not an
// interface that holds a nil store, so the caller can test it for nil.
func (d *daemonImpl) skillFileStore() harness.SkillFileStore {
	if store := d.agentSkillStore(); store != nil {
		return store
	}
	return nil
}

// daemonSecretReader reads a tenant secret through the secrets broker. The
// broker is built after the options of the services are assembled, so it is read
// for each call.
type daemonSecretReader struct{ d *daemonImpl }

// Resolve implements api.AgentSkillSecrets.
func (r daemonSecretReader) Resolve(ctx context.Context, name string) ([]byte, error) {
	if r.d.secretsService == nil {
		return nil, errors.New("the secrets broker is not ready")
	}
	value, err := r.d.secretsService.Resolve(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("resolve the secret: %w", err)
	}
	return value, nil
}
