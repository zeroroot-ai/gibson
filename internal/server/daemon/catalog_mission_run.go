// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// metadataCatalogMission names the checked-in mission that a mission was started
// from. It is the origin of a catalog launch.
const metadataCatalogMission = "catalog_mission"

// RunCatalogMission creates a mission from a checked-in catalog mission and
// queues it (gibson#1469). It takes the path of an agent that originates the same
// mission through the harness callback: the same render, the same mission record
// (the adapter that the harness uses), the same start, and the same scan anchors.
// The mission then reaches the ingest of the dependency alerts, which keys on a
// mission of the scan.
//
// The tenant is the one of the verified caller. The mission store and the target
// are the ones of that tenant, so no other tenant is reachable.
func (d *daemonImpl) RunCatalogMission(ctx context.Context, req api.RunCatalogMissionData) (string, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return "", err
	}
	def, err := missioncatalog.Render(ctx, req.Name, req.Params)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, err.Error())
	}
	body, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return "", fmt.Errorf("marshal the rendered mission %q: %w", req.Name, err)
	}
	targetID, err := types.ParseID(req.TargetID)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "target_id is not a valid id: %v", err)
	}

	adapter := newMissionHarnessAdapter(d)
	info, err := adapter.CreateMission(ctx, &harness.MissionClientCreateRequest{
		MissionDefinitionJSON: string(body),
		Name:                  req.Name,
		TargetID:              targetID,
		Metadata:              map[string]any{metadataCatalogMission: req.Name},
	})
	if err != nil {
		return "", fmt.Errorf("create the catalog mission %q: %w", req.Name, err)
	}
	missionID := info.ID.String()

	// The scan anchors are written before the mission runs, so the alerts node
	// finds its Application and Repository.
	if d.scanAnchors != nil && strings.TrimSpace(req.Name) == brain.ScanMissionName {
		d.scanAnchors(ctx, tenant.String(), missionID, req.Params)
	}
	if err := adapter.Run(ctx, missionID); err != nil {
		return "", fmt.Errorf("start the catalog mission %q: %w", req.Name, err)
	}
	return missionID, nil
}
