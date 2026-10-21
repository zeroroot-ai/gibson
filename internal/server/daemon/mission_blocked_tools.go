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
	if d.pool == nil {
		return nil, errors.New("the data plane pool is not configured")
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: %w", tenant, err)
	}
	id, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("mission id %q: %w", missionID, err)
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
	if rec.MissionDefinitionJSON == "" {
		return nil, nil // a mission with no stored definition has no constraints
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(rec.MissionDefinitionJSON))
	if err != nil {
		return nil, fmt.Errorf("parse the definition of mission %s: %w", missionID, err)
	}
	return def.GetConstraints().GetBlockedTools(), nil
}
