// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
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

// definitionHash is the SHA-256 of the canonical JSON of the whole definition, so a
// change of a node, the budget or the scope changes it. A publication pins it, and
// the mission start compares it with the definition that it loaded.
func definitionHash(def *missionpb.MissionDefinition) (string, error) {
	canonical, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return "", fmt.Errorf("encode the definition: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Definition returns the pin of a definition: its ID, the hash of its content and
// the agents of its agent nodes. The hash is the SHA-256 of the canonical JSON of
// the whole definition, so a change of a node, the budget or the scope changes it.
func (s *inboundMissionSource) Definition(ctx context.Context, definitionID string) (api.InboundDefinition, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return api.InboundDefinition{}, err
	}
	conn, err := s.pool.For(ctx, tenant)
	if err != nil {
		return api.InboundDefinition{}, fmt.Errorf("acquire conn for tenant %s: %w", tenant, err)
	}
	defer conn.Release()
	def, err := findMissionDefinition(ctx, mission.NewConnBoundMissionStore(conn.Redis), definitionID)
	if errors.Is(err, errMissionDefinitionNotFound) {
		return api.InboundDefinition{}, fmt.Errorf("%w: %s", api.ErrInboundDefinitionNotFound, definitionID)
	}
	if err != nil {
		return api.InboundDefinition{}, err
	}
	hash, err := definitionHash(def)
	if err != nil {
		return api.InboundDefinition{}, err
	}
	out := api.InboundDefinition{ID: def.GetId(), Hash: hash}
	for _, node := range def.GetNodes() {
		if name := node.GetAgentConfig().GetAgentName(); name != "" {
			out.Agents = append(out.Agents, name)
		}
	}
	return out, nil
}

// TargetHashes reads each target with the check that mission start uses, so a
// target of another tenant is not found, and it returns the hash of each one. The
// hash covers what a mission assesses: the name, the type, the connection, the
// model, the configuration, the capabilities and the URL. It does not cover the
// status, the tags, the description or the times, which change with no change of
// scope.
func (s *inboundMissionSource) TargetHashes(ctx context.Context, targetIDs []string) (map[string]string, error) {
	caller := resolveTargetCallerTenant(ctx)
	out := make(map[string]string, len(targetIDs))
	for _, id := range targetIDs {
		t, err := resolveTargetUUID(ctx, s.targets, id, caller)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", api.ErrInboundTargetNotFound, id)
		}
		h, err := targetHash(t)
		if err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, nil
}

// targetHash is the SHA-256 of the scope fields of a target. json.Marshal sorts
// the keys of a map, so the encoding is stable.
func targetHash(t *types.Target) (string, error) {
	scope := struct {
		Name         string
		Type         string
		Provider     types.Provider
		Connection   map[string]any
		Model        string
		Config       map[string]any
		Capabilities []string
		URL          string
		Headers      map[string]string
	}{t.Name, t.Type, t.Provider, t.Connection, t.Model, t.Config, t.Capabilities, t.URL, t.Headers}
	raw, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("encode target %s: %w", t.ID, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
