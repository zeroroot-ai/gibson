// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// storedBlockedTools reads the deny list of a mission (MissionConstraints
// .blocked_tools) from the stored definition of the mission in the data plane
// of the tenant. It never reads the memory of this replica, so each replica
// gives the same answer. It fails when the record cannot be read, and a caller
// that needs the list then refuses its call.
func (d *daemonImpl) storedBlockedTools(ctx context.Context, tenant, missionID string) ([]string, error) {
	rec, err := d.storedMission(ctx, tenant, missionID)
	if err != nil {
		return nil, err
	}
	return blockedToolsOf(rec)
}

// errPermanentMissionRead marks a failure to read a mission that a retry never
// fixes: a mission id that is not valid, a pool that is not configured, and a stored
// definition that does not parse. A failure with no mark may be transient.
var errPermanentMissionRead = errors.New("the mission record can never be read")

// storedMission reads the record of a mission from the data plane of the tenant.
func (d *daemonImpl) storedMission(ctx context.Context, tenant, missionID string) (*mission.Mission, error) {
	if d.pool == nil {
		return nil, fmt.Errorf("%w: the data plane pool is not configured", errPermanentMissionRead)
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: %w", tenant, err)
	}
	id, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("%w: mission id %q: %w", errPermanentMissionRead, missionID, err)
	}
	conn, err := d.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("acquire the data plane of the tenant: %w", err)
	}
	defer conn.Release()

	rec, err := mission.NewConnBoundMissionStore(conn.Redis).Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("read mission %s: %w", missionID, err)
	}
	return rec, nil
}

// blockedToolsOf reads the deny list from the stored definition of a mission.
func blockedToolsOf(rec *mission.Mission) ([]string, error) {
	if rec.MissionDefinitionJSON == "" {
		return nil, nil // a mission with no stored definition has no constraints
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(rec.MissionDefinitionJSON))
	if err != nil {
		return nil, fmt.Errorf("parse the definition of mission %s: %w", rec.ID, err)
	}
	return def.GetConstraints().GetBlockedTools(), nil
}
