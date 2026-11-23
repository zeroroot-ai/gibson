// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
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
// A record that is gone, a mission id that is not valid, a pool that is not
// configured and a definition that does not parse can never be read. They give
// fixloop.ErrHoldNotFound, so the fix loop uses the upper bound of the hold and
// shows the hold_unreadable wait. Any other read error may be transient, and the fix
// loop reads again at the next step.
func (d *daemonImpl) fixHold(ctx context.Context, tenant, missionID string) (time.Duration, error) {
	if missionID == "" {
		return 0, nil
	}
	rec, err := d.storedMission(ctx, tenant, missionID)
	return holdOfRead(rec, err)
}

// holdOfRead maps the result of the read of the fix mission to a hold time. A record
// that is gone, and a failure that can never work, give fixloop.ErrHoldNotFound. Any
// other error may be transient and is returned as it is.
func holdOfRead(rec *mission.Mission, err error) (time.Duration, error) {
	if mission.IsNotFoundError(err) || errors.Is(err, errPermanentMissionRead) {
		return 0, fmt.Errorf("fix hold: %w: %w", fixloop.ErrHoldNotFound, err)
	}
	if err != nil {
		return 0, fmt.Errorf("fix hold: %w", err)
	}
	hold, err := fixHoldOf(rec)
	if errors.Is(err, errPermanentMissionRead) {
		return 0, fmt.Errorf("fix hold: %w: %w", fixloop.ErrHoldNotFound, err)
	}
	return hold, err
}

// fixHoldOf reads the hold time from the stored definition of a mission. A
// record with no stored definition has no constraints, so it states no hold time.
func fixHoldOf(rec *mission.Mission) (time.Duration, error) {
	if rec.MissionDefinitionJSON == "" {
		return 0, nil
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(rec.MissionDefinitionJSON))
	if err != nil {
		return 0, fmt.Errorf("%w: parse the definition of mission %s: %w", errPermanentMissionRead, rec.ID, err)
	}
	return fixloop.HoldOf(def.GetConstraints()), nil
}
