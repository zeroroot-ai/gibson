// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func TestInheritConstraints(t *testing.T) {
	parent := &missionv1.MissionConstraints{
		HealthHold:    durationpb.New(2 * time.Minute),
		RestartPolicy: missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW,
		RestartLimit:  durationpb.New(5 * time.Minute),
		RestartWindow: &missionv1.RestartWindow{},
		MaxTokens:     1000,
	}

	// A child with no constraints takes the hold and the restart rules, and no budget.
	got := InheritConstraints(nil, parent)
	assert.Equal(t, 2*time.Minute, got.GetHealthHold().AsDuration())
	assert.Equal(t, 5*time.Minute, got.GetRestartLimit().AsDuration())
	assert.Equal(t, missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW, got.GetRestartPolicy())
	assert.NotNil(t, got.GetRestartWindow())
	assert.Zero(t, got.GetMaxTokens(), "the budget of the parent is not copied")

	// A child that sets its own keeps it, and takes only what it leaves unset.
	child := &missionv1.MissionConstraints{HealthHold: durationpb.New(30 * time.Second), MaxTokens: 50}
	got = InheritConstraints(child, parent)
	assert.Equal(t, 30*time.Second, got.GetHealthHold().AsDuration())
	assert.Equal(t, 5*time.Minute, got.GetRestartLimit().AsDuration())
	assert.EqualValues(t, 50, got.GetMaxTokens())

	// The arguments do not change.
	assert.Equal(t, 30*time.Second, child.GetHealthHold().AsDuration())
	assert.Nil(t, child.GetRestartLimit())
	assert.Equal(t, 2*time.Minute, parent.GetHealthHold().AsDuration())

	// No parent: the child as it is. A parent with nothing to give gives nothing.
	assert.Same(t, child, InheritConstraints(child, nil))
	assert.Zero(t, InheritConstraints(nil, &missionv1.MissionConstraints{MaxTokens: 5}).GetHealthHold().AsDuration())
}
