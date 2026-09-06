// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

// scope.go: the UUID-set-subset check gibson#1358's mission-origination scope
// rule needs. This is the whole check — the design work was defining what
// "the parent's target set" IS (Mission.TargetSet, mission.go), not writing
// ⊆. Kept as a free function rather than a Mission method because both sides
// of the comparison are plain []types.ID (a candidate child target set does
// not need to be an actual Mission to be checked against one), which keeps
// this usable from the mission-origination handler (gibson#1358 PR4) without
// constructing a throwaway Mission just to hold a target list.

import "github.com/zeroroot-ai/gibson/internal/infra/types"

// TargetSetSubset reports whether every ID in child also appears in parent —
// the "child ⊆ parent" scope check gibson#1358's owner decision requires
// server-side for mission origination: a component-originated child
// mission's target UUID set must be a subset of the originating mission's
// target set, and scope-widening always requires a human (no code path
// grows the child's set beyond what this reports true for).
//
// An empty (or nil) child set is trivially a subset of anything — naming no
// targets claims no additional scope. A nil or empty parent set means the
// parent has no targets, so only an empty child set is a subset of it: a
// non-empty child against an empty parent is always false, never "vacuously
// allowed".
//
// Nothing here resolves names — every ID is expected to already be the
// canonical target UUID (workspace convention: "nothing resolves names").
// Duplicate IDs on either side do not affect the result.
func TargetSetSubset(child, parent []types.ID) bool {
	if len(child) == 0 {
		return true
	}
	if len(parent) == 0 {
		return false
	}
	allowed := make(map[types.ID]struct{}, len(parent))
	for _, id := range parent {
		allowed[id] = struct{}{}
	}
	for _, id := range child {
		if _, ok := allowed[id]; !ok {
			return false
		}
	}
	return true
}
