// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func recordWith(t *testing.T, c *missionv1.MissionConstraints) *mission.Mission {
	t.Helper()
	raw, err := mission.MarshalDefinitionJSON(&missionv1.MissionDefinition{Name: "fix", Constraints: c})
	require.NoError(t, err)
	return &mission.Mission{MissionDefinitionJSON: string(raw)}
}

func TestFixHoldOf_TheHoldTimeIsAConstraintOfTheMission(t *testing.T) {
	got, err := fixHoldOf(recordWith(t, &missionv1.MissionConstraints{HealthHold: durationpb.New(45 * time.Minute)}))
	require.NoError(t, err)
	assert.Equal(t, 45*time.Minute, got, "the fix loop gets the hold of the mission")
}

func TestFixHoldOf_AMissionWithNoHoldStatesNone(t *testing.T) {
	for name, rec := range map[string]*mission.Mission{
		"no definition":  {},
		"no constraints": recordWith(t, nil),
		"no hold":        recordWith(t, &missionv1.MissionConstraints{}),
		"a zero hold":    recordWith(t, &missionv1.MissionConstraints{HealthHold: durationpb.New(0)}),
	} {
		got, err := fixHoldOf(rec)
		require.NoError(t, err, name)
		assert.Zero(t, got, "%s: zero means that the fix loop uses the default hold of %v", name, fixloop.DefaultPolicy().HoldTime)
	}
}

func TestFixHoldOf_ADefinitionThatDoesNotParseIsAnError(t *testing.T) {
	_, err := fixHoldOf(&mission.Mission{MissionDefinitionJSON: `{not json`})
	require.Error(t, err)
}

func TestFixHold_RefusalsAreErrorsAndNoMissionStatesNoHold(t *testing.T) {
	ctx := context.Background()
	d := &daemonImpl{}

	got, err := d.fixHold(ctx, "acme", "")
	require.NoError(t, err)
	assert.Zero(t, got, "a finding with no fix mission states no hold")

	_, err = d.fixHold(ctx, "acme", "0e4f7f5e-6f5c-4c43-9f0a-1c0b3a3f9a11")
	require.Error(t, err, "no pool: the record of the mission cannot be read")
}

// A record that is gone gives ErrHoldNotFound, so the fix loop uses the upper bound.
// Any other read error does not, so the fix loop reads again.
func TestFixHold_AGoneRecordIsNotFoundAndAnyOtherErrorIsNot(t *testing.T) {
	ctx := context.Background()
	const missionID = "0e4f7f5e-6f5c-4c43-9f0a-1c0b3a3f9a11"
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	d := &daemonImpl{pool: dataPlane{conn: conn}}

	_, err := d.fixHold(ctx, "acme", missionID)
	require.ErrorIs(t, err, fixloop.ErrHoldNotFound, "the record is gone")

	d.pool = dataPlane{err: errors.New("not provisioned")}
	_, err = d.fixHold(ctx, "acme", missionID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, fixloop.ErrHoldNotFound, "a pool that fails is a transient error")
}
