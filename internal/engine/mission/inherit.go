// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// InheritConstraints returns the constraints of a child mission that a parent
// mission originates (gibson#1469). The child keeps every field that it sets. It
// takes the health hold and the restart rules of the parent for each one that it
// leaves unset, because the fix loop reads the hold of the mission that delivered
// a merge request, and that mission is the child that the fix agent originates. A
// child with no constraints gets those fields of the parent and nothing else: the
// budgets and the other limits of the parent are not copied, because the ledger
// grants the child its own budget.
//
// Neither argument is changed. A nil parent returns the child as it is.
func InheritConstraints(child, parent *missionv1.MissionConstraints) *missionv1.MissionConstraints {
	if parent == nil {
		return child
	}
	var out *missionv1.MissionConstraints
	if child != nil {
		out = proto.Clone(child).(*missionv1.MissionConstraints) //nolint:forcetypeassert // Clone returns the same type
	} else {
		out = &missionv1.MissionConstraints{}
	}
	if out.GetHealthHold().AsDuration() <= 0 && parent.GetHealthHold().AsDuration() > 0 {
		out.HealthHold = proto.Clone(parent.GetHealthHold()).(*durationpb.Duration) //nolint:forcetypeassert // same type
	}
	if out.GetRestartPolicy() == missionv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED {
		out.RestartPolicy = parent.GetRestartPolicy()
	}
	if out.GetRestartLimit().AsDuration() <= 0 && parent.GetRestartLimit().AsDuration() > 0 {
		out.RestartLimit = proto.Clone(parent.GetRestartLimit()).(*durationpb.Duration) //nolint:forcetypeassert // same type
	}
	if out.GetRestartWindow() == nil && parent.GetRestartWindow() != nil {
		out.RestartWindow = proto.Clone(parent.GetRestartWindow()).(*missionv1.RestartWindow) //nolint:forcetypeassert // same type
	}
	return out
}
