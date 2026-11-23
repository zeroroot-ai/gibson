// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// newMissionRecord is the one place that stamps a new mission record. TenantID
// MUST be set: the ListMissions handler filters by m.TenantID == caller tenant, so
// a mission saved without it is invisible on the dashboard even though it lives in
// the tenant's store. CreatedBy and the times are set here too. Every path that
// creates a mission by a caller (the person path and the catalog launch) builds
// its record with this function.
func newMissionRecord(
	tenant auth.TenantID, name, description string, target, definition types.ID, createdBy principal.Principal,
) *mission.Mission {
	return &mission.Mission{
		ID:                  types.NewID(),
		TenantID:            tenant.String(),
		Name:                name,
		Description:         description,
		Status:              mission.MissionStatusSubmitted,
		TargetID:            target,
		MissionDefinitionID: definition,
		CreatedBy:           createdBy,
		CreatedAt:           mission.NewUnixTimeNow(),
		UpdatedAt:           mission.NewUnixTimeNow(),
	}
}

// announceMission tells the World of the tenant about a mission that was saved, as
// pending with its creator, so ListMissions and the dashboard show it before it
// runs (hosted#205). MissionStarted moves the same entity to running.
func (d *daemonImpl) announceMission(tenant auth.TenantID, m *mission.Mission) {
	if d.brainRegistry != nil {
		d.brainRegistry.For(tenant.String()).Submit(brain.MissionCreated{
			ID:          m.ID.String(),
			Name:        m.Name,
			Description: m.Description,
			TargetID:    m.TargetID.String(),
			TenantID:    m.TenantID,
			CreatedBy:   m.CreatedBy,
			Catalog:     catalogOf(m),
		})
	}
}

// catalogOf returns the catalog mission that a mission record was launched from,
// or "". The marker is in the metadata of the record, and only the launch paths of
// the catalog write it.
func catalogOf(m *mission.Mission) string {
	name, _ := m.Metadata[mission.MetadataCatalogMission].(string)
	return name
}
