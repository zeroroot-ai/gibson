// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — catalog_missions.go implements DaemonService.ListCatalogMissions
// and DaemonService.RenderCatalogMission.
//
// gibson ships first-party mission definitions compiled into its own binary
// (ADR-0018). Until these two RPCs, the catalog had exactly ONE reader: the
// agent-facing harness callback, which takes catalog_mission + catalog_params.
// A person could neither list what the platform ships nor run one of those
// missions, so the only way to run a first-party mission by hand was to copy
// its CUE out of this repository and submit the copy — a second definition of
// one mission, which ADR-0027 forbids and which would silently stop tracking
// the checked-in one (gibson#631).
//
// Both are READS. A write would carry its own authorization surface, and the
// per-tenant gate plus the ADR-0063 origination rule would then be enforced in
// two places, which is where two enforcement paths drift apart. A caller
// renders a mission here, registers the result with CreateMissionDefinition,
// and runs it the way it runs any definition — which is referencing the
// authoritative definition rather than rebuilding it, because the graph came
// out of this binary.
package api

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

// ListCatalogMissions implements DaemonServiceServer.ListCatalogMissions.
//
// Nothing here is per-tenant: the catalog is identical for every tenant, and a
// mission is not gated — the components it dispatches are.
func (s *DaemonServer) ListCatalogMissions(
	_ context.Context,
	_ *daemonpb.ListCatalogMissionsRequest,
) (*daemonpb.ListCatalogMissionsResponse, error) {
	entries, err := missioncatalog.Entries()
	if err != nil {
		// Reported rather than returning a short list. A mission silently
		// missing is how a person concludes the platform does not ship it.
		return nil, status_grpc.Error(codes.Internal, err.Error())
	}

	out := make([]*daemonpb.CatalogMission, 0, len(entries))
	for _, e := range entries {
		out = append(out, &daemonpb.CatalogMission{
			Name:           e.Name,
			Description:    e.Description,
			Version:        e.Version,
			DeclaredParams: e.DeclaredParams,
		})
	}

	s.logger.Debug("listed catalog missions", "count", len(out))
	return &daemonpb.ListCatalogMissionsResponse{Missions: out}, nil
}

// RenderCatalogMission implements DaemonServiceServer.RenderCatalogMission.
//
// Rendered server-side, which is the point. Render validates the parameter map
// against what THAT mission declares in its own CUE: an unknown key is refused,
// never dropped, and that refusal is the smuggling defence. No mission declares
// a target or a host, so a dropped `host:` key would leave a caller believing
// it had redirected the scan. Every missing key is reported together, so a
// caller wiring this up sees each field it forgot rather than one per attempt.
func (s *DaemonServer) RenderCatalogMission(
	ctx context.Context,
	req *daemonpb.RenderCatalogMissionRequest,
) (*daemonpb.RenderCatalogMissionResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"name is required (checked-in missions: %s)", strings.Join(missioncatalog.Names(), ", "))
	}

	src, err := missioncatalog.Source(name)
	if err != nil {
		// Source already names what the catalog does ship, which is what a
		// caller needs after a typo.
		return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
	}

	def, err := missioncatalog.Render(ctx, name, req.GetParams())
	if err != nil {
		// InvalidArgument, not Internal: every way Render fails here is
		// something the CALLER sent — an unknown key, a missing one, or a value
		// that is only whitespace.
		return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
	}

	s.logger.Debug("rendered a catalog mission", "mission", name, "params", len(req.GetParams()))
	return &daemonpb.RenderCatalogMissionResponse{Mission: def, Source: src}, nil
}
