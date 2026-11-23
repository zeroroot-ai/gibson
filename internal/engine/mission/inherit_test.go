// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

const (
	allowed   = missionv1.RestartPolicy_RESTART_POLICY_ALLOWED
	forbidden = missionv1.RestartPolicy_RESTART_POLICY_FORBIDDEN
	inWindow  = missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW
	unset     = missionv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED
)

func dur(d time.Duration) *durationpb.Duration { return durationpb.New(d) }

func win(start, end string) *missionv1.RestartWindow {
	return &missionv1.RestartWindow{Start: start, End: end}
}

func inherit(t *testing.T, child, parent *missionv1.MissionConstraints) *missionv1.MissionConstraints {
	t.Helper()
	got, err := InheritConstraints(child, parent)
	require.NoError(t, err)
	return got
}

// A child with no constraints takes the hold and the restart rules of its parent,
// and no budget.
func TestInheritConstraints_AChildWithNoConstraintsTakesTheParentRules(t *testing.T) {
	parent := &missionv1.MissionConstraints{
		HealthHold: dur(2 * time.Minute), RestartLimit: dur(5 * time.Minute),
		RestartPolicy: inWindow, RestartWindow: win("02:00", "04:00"), MaxTokens: 1000,
	}
	got := inherit(t, nil, parent)
	assert.Equal(t, 2*time.Minute, got.GetHealthHold().AsDuration())
	assert.Equal(t, 5*time.Minute, got.GetRestartLimit().AsDuration())
	assert.Equal(t, inWindow, got.GetRestartPolicy())
	assert.Equal(t, "02:00", got.GetRestartWindow().GetStart())
	assert.Zero(t, got.GetMaxTokens(), "the budget of the parent is not copied")
}

// The stricter value wins: a child cannot shorten the hold, raise the restart limit,
// loosen the policy or widen the window.
func TestInheritConstraints_AChildCannotLoosenWhatTheParentSet(t *testing.T) {
	parent := &missionv1.MissionConstraints{
		HealthHold: dur(10 * time.Minute), RestartLimit: dur(5 * time.Minute),
		RestartPolicy: inWindow, RestartWindow: win("02:00", "04:00"),
	}

	t.Run("the hold", func(t *testing.T) {
		got := inherit(t, &missionv1.MissionConstraints{HealthHold: dur(time.Minute)}, parent)
		assert.Equal(t, 10*time.Minute, got.GetHealthHold().AsDuration(), "a shorter hold of the child loses")
		got = inherit(t, &missionv1.MissionConstraints{HealthHold: dur(20 * time.Minute)}, parent)
		assert.Equal(t, 20*time.Minute, got.GetHealthHold().AsDuration(), "a longer hold of the child wins")
	})
	t.Run("the restart limit", func(t *testing.T) {
		got := inherit(t, &missionv1.MissionConstraints{RestartLimit: dur(30 * time.Minute)}, parent)
		assert.Equal(t, 5*time.Minute, got.GetRestartLimit().AsDuration(), "a higher limit of the child loses")
		got = inherit(t, &missionv1.MissionConstraints{RestartLimit: dur(time.Minute)}, parent)
		assert.Equal(t, time.Minute, got.GetRestartLimit().AsDuration(), "a lower limit of the child wins")
	})
	t.Run("the policy", func(t *testing.T) {
		got := inherit(t, &missionv1.MissionConstraints{RestartPolicy: allowed}, parent)
		assert.Equal(t, inWindow, got.GetRestartPolicy(), "ALLOWED under IN_WINDOW is IN_WINDOW")
		assert.Equal(t, "02:00", got.GetRestartWindow().GetStart())
		got = inherit(t, &missionv1.MissionConstraints{RestartPolicy: allowed}, &missionv1.MissionConstraints{RestartPolicy: forbidden})
		assert.Equal(t, forbidden, got.GetRestartPolicy(), "ALLOWED under FORBIDDEN is FORBIDDEN")
		assert.Nil(t, got.GetRestartWindow())
		got = inherit(t, &missionv1.MissionConstraints{RestartPolicy: allowed}, &missionv1.MissionConstraints{HealthHold: dur(time.Minute)})
		assert.Equal(t, forbidden, got.GetRestartPolicy(), "ALLOWED under an unset policy is FORBIDDEN")
		got = inherit(t, &missionv1.MissionConstraints{RestartPolicy: forbidden}, &missionv1.MissionConstraints{RestartPolicy: allowed})
		assert.Equal(t, forbidden, got.GetRestartPolicy(), "a stricter child keeps its rule")
		got = inherit(t, nil, &missionv1.MissionConstraints{HealthHold: dur(time.Minute)})
		assert.Equal(t, unset, got.GetRestartPolicy(), "no policy on either side stays unset")
	})
	t.Run("the window", func(t *testing.T) {
		wide := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("00:00", "12:00")}
		got := inherit(t, wide, parent)
		assert.Equal(t, win("02:00", "04:00").GetStart(), got.GetRestartWindow().GetStart(), "a wider window of the child is cut to the parent")
		assert.Equal(t, "04:00", got.GetRestartWindow().GetEnd())
		narrow := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("03:00", "03:30")}
		got = inherit(t, narrow, parent)
		assert.Equal(t, "03:00", got.GetRestartWindow().GetStart(), "a narrower window of the child wins")
		assert.Equal(t, "03:30", got.GetRestartWindow().GetEnd())
		apart := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("10:00", "11:00")}
		got = inherit(t, apart, parent)
		assert.Equal(t, forbidden, got.GetRestartPolicy(), "windows with nothing in common forbid a restart")
		assert.Nil(t, got.GetRestartWindow())
	})
	t.Run("two full days share the full day", func(t *testing.T) {
		full := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("00:00", "23:59")}
		got := inherit(t, full, full)
		assert.Equal(t, inWindow, got.GetRestartPolicy(), "both sides allow a restart at any time")
		assert.Equal(t, "00:00", got.GetRestartWindow().GetStart())
		assert.Equal(t, "23:59", got.GetRestartWindow().GetEnd())
		// A full day that starts at another minute is a full day too.
		shifted := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("10:00", "09:59")}
		got = inherit(t, shifted, full)
		assert.Equal(t, inWindow, got.GetRestartPolicy())
		assert.Equal(t, "00:00", got.GetRestartWindow().GetStart())
		// A full day against a part of the day gives the part.
		got = inherit(t, full, &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("02:00", "04:00")})
		assert.Equal(t, "02:00", got.GetRestartWindow().GetStart())
		assert.Equal(t, "04:00", got.GetRestartWindow().GetEnd())
	})
	t.Run("a window that crosses midnight", func(t *testing.T) {
		night := &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("22:00", "06:00")}
		got := inherit(t, &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("23:00", "23:30")}, night)
		assert.Equal(t, "23:00", got.GetRestartWindow().GetStart())
		got = inherit(t, &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("04:00", "23:00")},
			night)
		assert.Equal(t, forbidden, got.GetRestartPolicy(), "two ranges in common are not one window")
	})
}

// The policy and the window always travel as a pair, and the result is validated.
func TestInheritConstraints_ThePairHoldsAndAnInvalidResultIsRefused(t *testing.T) {
	// A child that is in a window with no window of its own, under a parent that is
	// not, ends with a policy and a window that agree.
	got := inherit(t, &missionv1.MissionConstraints{RestartPolicy: inWindow, RestartWindow: win("01:00", "02:00")},
		&missionv1.MissionConstraints{RestartPolicy: allowed})
	assert.Equal(t, inWindow, got.GetRestartPolicy())
	assert.NotNil(t, got.GetRestartWindow())
	got = inherit(t, &missionv1.MissionConstraints{RestartPolicy: allowed, RestartWindow: win("01:00", "02:00")},
		&missionv1.MissionConstraints{RestartPolicy: allowed})
	assert.Nil(t, got.GetRestartWindow(), "a window with a policy that is not IN_WINDOW is dropped")

	// A child whose own constraints are invalid is refused.
	_, err := InheritConstraints(&missionv1.MissionConstraints{HealthHold: dur(48 * time.Hour)},
		&missionv1.MissionConstraints{HealthHold: dur(time.Minute)})
	require.Error(t, err, "a hold over 24 hours is invalid")
}

// The arguments do not change, and a nil parent returns the child.
func TestInheritConstraints_DoesNotChangeItsArguments(t *testing.T) {
	child := &missionv1.MissionConstraints{HealthHold: dur(30 * time.Second), MaxTokens: 50}
	parent := &missionv1.MissionConstraints{HealthHold: dur(2 * time.Minute), RestartLimit: dur(5 * time.Minute)}
	got := inherit(t, child, parent)
	assert.EqualValues(t, 50, got.GetMaxTokens())
	assert.Equal(t, 30*time.Second, child.GetHealthHold().AsDuration())
	assert.Nil(t, child.GetRestartLimit())
	assert.Equal(t, 2*time.Minute, parent.GetHealthHold().AsDuration())
	same, err := InheritConstraints(child, nil)
	require.NoError(t, err)
	assert.Same(t, child, same)
}

// The parent constraints are the definition, with the record filling what it leaves.
func TestParentConstraints_DefinitionThenRecord(t *testing.T) {
	def, err := MarshalDefinitionJSON(&missionv1.MissionDefinition{
		Name: "p", Constraints: &missionv1.MissionConstraints{HealthHold: dur(time.Minute)},
	})
	require.NoError(t, err)
	p := &Mission{MissionDefinitionJSON: string(def), Constraints: &missionv1.MissionConstraints{
		HealthHold: dur(9 * time.Minute), RestartLimit: dur(7 * time.Minute),
	}}
	got, err := ParentConstraints(p)
	require.NoError(t, err)
	assert.Equal(t, time.Minute, got.GetHealthHold().AsDuration(), "the definition wins")
	assert.Equal(t, 7*time.Minute, got.GetRestartLimit().AsDuration(), "the record fills what the definition leaves")

	got, err = ParentConstraints(&Mission{Constraints: p.Constraints})
	require.NoError(t, err)
	assert.Equal(t, 9*time.Minute, got.GetHealthHold().AsDuration())
	_, err = ParentConstraints(&Mission{MissionDefinitionJSON: "{not json"})
	require.Error(t, err)
}
