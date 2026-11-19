// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// missionTenantTuples is the mission.TenantRecorder of the daemon. It writes the
// tuple (tenant:<tenant>, belongs_to, mission:<id>) through the authorizer.
//
// Write is idempotent per tuple and Delete ignores an absent tuple, so a repeat
// of Record or Forget is safe.
type missionTenantTuples struct {
	az authz.Authorizer
}

// Record implements mission.TenantRecorder.
func (r missionTenantTuples) Record(ctx context.Context, tenant string, id types.ID) error {
	if err := r.az.Write(ctx, []authz.Tuple{authz.MissionBelongsToTuple(tenant, id.String())}); err != nil {
		return fmt.Errorf("write the belongs_to tuple: %w", err)
	}
	return nil
}

// Forget implements mission.TenantRecorder.
func (r missionTenantTuples) Forget(ctx context.Context, tenant string, id types.ID) error {
	if err := r.az.Delete(ctx, []authz.Tuple{authz.MissionBelongsToTuple(tenant, id.String())}); err != nil {
		return fmt.Errorf("delete the belongs_to tuple: %w", err)
	}
	return nil
}

// missionTenantRecorder returns the recorder of the daemon, or nil when the
// daemon has no authorizer. A store built with a nil recorder refuses to create
// a mission (mission.ErrNoTenantRecorder), so a daemon with no authorizer starts
// no mission. The daemon starts with an authorizer in every deployment.
func (d *daemonImpl) missionTenantRecorder() mission.TenantRecorder {
	if d.authorizer != nil {
		return missionTenantTuples{az: d.authorizer}
	}
	return nil
}

// newMissionStore returns the store that creates missions of a tenant. Each
// code path that creates a mission builds its store here, so each mission gets
// its belongs_to tuple before it exists.
func (d *daemonImpl) newMissionStore(rdb *redis.Client, tenant string) *mission.ConnBoundMissionStore {
	return newMissionStoreWith(rdb, d.missionTenantRecorder(), tenant)
}

// newMissionStoreWith builds a store that records the tenant of each mission it
// creates. A nil recorder builds a store that fails when it creates a mission.
func newMissionStoreWith(rdb *redis.Client, rec mission.TenantRecorder, tenant string) *mission.ConnBoundMissionStore {
	s := mission.NewConnBoundMissionStore(rdb)
	if rec == nil {
		return s
	}
	return s.WithTenantRecorder(rec, tenant)
}
