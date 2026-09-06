// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — team_object_ref.go
//
// The gRPC-boundary wrapper around authz.TeamObject / authz.TeamIDFromObject.
//
// Team FGA object ids are tenant-namespaced: `team:<tenant>/<team_id>`. The
// derivation itself lives in internal/platform/authz/objects.go, which is this
// repo's single source of truth for FGA object references — four call sites
// once derived component objects four different ways and a can_execute check
// silently never matched the seeded tuple (gibson#694), and a tenant-qualified
// id joined with ":" instead of "/" was rejected by OpenFGA so every such write
// failed silently (gibson#1024). Team objects are derived in three packages
// (here, ModelAccessService, the budget team resolver), so they belong there
// too rather than in a second local definition that could drift.
//
// What this file adds is the RPC contract: authz returns a plain error so it
// stays free of gRPC, and a handler needs a status code. A bad team_id is the
// caller's fault (InvalidArgument); a bad tenant slug is not — it comes from
// requireCallerTenant, i.e. the ext-authz context — so it is a daemon-side
// invariant break (Internal). Both are refused: writing `team:a/b/ops` would
// create an object no read path can attribute, which is the condition the
// namespace exists to remove.
package admin

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// teamRef builds the tenant-namespaced FGA object reference for a team.
//
// tenantID is the caller's own tenant as returned by requireCallerTenant — bare
// slug or already "tenant:"-prefixed, both accepted for the same reason
// tenantRefFromID accepts both. teamID is the caller-supplied bare id.
func teamRef(tenantID, teamID string) (string, error) {
	tenantSlug := stripFGATypePrefix(tenantID, "tenant")

	// Validate the tenant segment on its own first, so its failure can be
	// reported as Internal rather than blamed on the caller's team_id.
	if _, err := authz.TeamObject(tenantSlug, "probe"); err != nil {
		return "", status.Errorf(codes.Internal,
			"caller tenant is not a usable team-namespace segment: %v", err)
	}

	obj, err := authz.TeamObject(tenantSlug, teamID)
	if err != nil {
		if errors.Is(err, authz.ErrInvalidTeamSegment) {
			return "", status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return "", status.Errorf(codes.Internal, "derive team object: %v", err)
	}
	return obj, nil
}

// teamIDFromRef returns the bare team id for a reference belonging to tenantID,
// and false for anything else — another tenant's object, or a legacy
// un-namespaced one.
func teamIDFromRef(tenantID, ref string) (string, bool) {
	return authz.TeamIDFromObject(stripFGATypePrefix(tenantID, "tenant"), ref)
}
