// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
)

// fixHold returns the hold time of the health signal for the fix mission that
// delivered a merge request (gibson#1463). The hold time is a constraint of that
// mission (MissionConstraints.health_hold), so it comes from the stored
// definition of the mission in the data plane of the tenant. It returns zero for
// a mission that states none, and the fix loop then uses the default hold time.
// A record that cannot be read is an error, and the fix loop reads the health
// signal again at the next step.
func (d *daemonImpl) fixHold(ctx context.Context, tenant, missionID string) (time.Duration, error) {
	if missionID == "" {
		return 0, nil
	}
	rec, err := d.storedMission(ctx, tenant, missionID)
	if mission.IsNotFoundError(err) {
		return 0, fmt.Errorf("fix hold: %w: %w", fixloop.ErrHoldNotFound, err)
	}
	if err != nil {
		return 0, fmt.Errorf("fix hold: %w", err)
	}
	return fixHoldOf(rec)
}

// fixHoldOf reads the hold time from the stored definition of a mission. A
// record with no stored definition has no constraints, so it states no hold time.
func fixHoldOf(rec *mission.Mission) (time.Duration, error) {
	if rec.MissionDefinitionJSON == "" {
		return 0, nil
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(rec.MissionDefinitionJSON))
	if err != nil {
		return 0, fmt.Errorf("parse the definition of mission %s: %w", rec.ID, err)
	}
	return fixloop.HoldOf(def.GetConstraints()), nil
}
