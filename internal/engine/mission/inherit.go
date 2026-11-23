// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// InheritConstraints returns the constraints of a child mission that a parent
// mission originates (gibson#1469). The stricter value always wins, because an
// agent builds the constraints of the child and must never loosen what a person set
// on the parent:
//
//   - health_hold is the larger of the two. A child cannot shorten the hold.
//   - restart_limit is the smaller non-zero value. A child cannot raise the limit.
//   - restart_policy is the stricter of the two. An unset policy means FORBIDDEN, so
//     ALLOWED under a parent that is FORBIDDEN or unset becomes FORBIDDEN. When
//     neither side sets a policy, the child keeps none.
//   - restart_window travels with the policy as one pair, so the rule
//     (restart_policy == IN_WINDOW) == has(restart_window) always holds. A child
//     cannot widen the window of the parent. Two windows with no single range in
//     common give FORBIDDEN.
//
// The budgets and the other limits of the parent are not copied, because the ledger
// grants the child its own budget. The merged constraints are validated, and an
// invalid result is an error, so a child never starts with constraints that the
// platform refuses. Neither argument is changed. A nil parent returns the child.
func InheritConstraints(child, parent *missionv1.MissionConstraints) (*missionv1.MissionConstraints, error) {
	if parent == nil {
		return child, nil
	}
	out := &missionv1.MissionConstraints{}
	if child != nil {
		//nolint:forcetypeassert // Clone returns the type of its argument
		out = proto.Clone(child).(*missionv1.MissionConstraints)
	}
	out.HealthHold = largerDuration(child.GetHealthHold(), parent.GetHealthHold())
	out.RestartLimit = smallerNonZeroDuration(child.GetRestartLimit(), parent.GetRestartLimit())
	policy, window := stricterRestart(child, parent)
	out.RestartPolicy, out.RestartWindow = policy, window
	if err := protovalidate.Validate(out); err != nil {
		return nil, fmt.Errorf("mission: the constraints of the child do not hold with those of the parent: %w", err)
	}
	return out, nil
}

// largerDuration returns the larger of two durations, or nil when neither is set.
func largerDuration(a, b *durationpb.Duration) *durationpb.Duration {
	switch {
	case a.AsDuration() <= 0 && b.AsDuration() <= 0:
		return a
	case a.AsDuration() >= b.AsDuration():
		return a
	}
	return durationpb.New(b.AsDuration())
}

// smallerNonZeroDuration returns the smaller of the values that are set.
func smallerNonZeroDuration(a, b *durationpb.Duration) *durationpb.Duration {
	switch {
	case a.AsDuration() <= 0 && b.AsDuration() <= 0:
		return a
	case a.AsDuration() <= 0:
		return durationpb.New(b.AsDuration())
	case b.AsDuration() <= 0:
		return a
	case a.AsDuration() <= b.AsDuration():
		return a
	}
	return durationpb.New(b.AsDuration())
}

// restartRank orders the policies from the laxest to the strictest. An unset
// policy is FORBIDDEN.
func restartRank(p missionv1.RestartPolicy) int {
	switch p {
	case missionv1.RestartPolicy_RESTART_POLICY_ALLOWED:
		return 0
	case missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW:
		return 1
	default:
		return 2
	}
}

// stricterRestart returns the policy and the window of the child after the policy
// of the parent applies. The two come back as a pair.
func stricterRestart(child, parent *missionv1.MissionConstraints) (missionv1.RestartPolicy, *missionv1.RestartWindow) {
	unset := missionv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED
	if child.GetRestartPolicy() == unset {
		// The child states no policy, so it takes the pair of the parent as it is.
		if parent.GetRestartPolicy() == missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW {
			if w, ok := cloneWindow(parent.GetRestartWindow()); ok {
				return parent.GetRestartPolicy(), w
			}
			return missionv1.RestartPolicy_RESTART_POLICY_FORBIDDEN, nil
		}
		return parent.GetRestartPolicy(), nil
	}
	forbidden := missionv1.RestartPolicy_RESTART_POLICY_FORBIDDEN
	switch max(restartRank(child.GetRestartPolicy()), restartRank(parent.GetRestartPolicy())) {
	case 0:
		return missionv1.RestartPolicy_RESTART_POLICY_ALLOWED, nil
	case 1:
		window, ok := narrowWindow(child, parent)
		if !ok {
			return forbidden, nil
		}
		return missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW, window
	}
	return forbidden, nil
}

// narrowWindow returns the window of the stricter side when only one side is in a
// window, and the range that two windows share when both are. It returns false when
// the sides have no single range in common, or a window is missing or malformed.
func narrowWindow(child, parent *missionv1.MissionConstraints) (*missionv1.RestartWindow, bool) {
	inWindow := missionv1.RestartPolicy_RESTART_POLICY_IN_WINDOW
	switch {
	case parent.GetRestartPolicy() == inWindow && child.GetRestartPolicy() == inWindow:
		return commonWindow(child.GetRestartWindow(), parent.GetRestartWindow())
	case parent.GetRestartPolicy() == inWindow:
		return cloneWindow(parent.GetRestartWindow())
	default:
		return cloneWindow(child.GetRestartWindow())
	}
}

func cloneWindow(w *missionv1.RestartWindow) (*missionv1.RestartWindow, bool) {
	if _, ok := windowMinutes(w); !ok {
		return nil, false
	}
	//nolint:forcetypeassert // Clone returns the type of its argument
	return proto.Clone(w).(*missionv1.RestartWindow), true
}

const minutesPerDay = 24 * 60

// windowMinutes returns the minutes of the day that a window covers. A window whose
// end is before its start crosses midnight.
func windowMinutes(w *missionv1.RestartWindow) ([minutesPerDay]bool, bool) {
	var set [minutesPerDay]bool
	start, ok1 := parseClock(w.GetStart())
	end, ok2 := parseClock(w.GetEnd())
	if w == nil || !ok1 || !ok2 {
		return set, false
	}
	for m := start; ; m = (m + 1) % minutesPerDay {
		set[m] = true
		if m == end {
			break
		}
	}
	return set, true
}

func parseClock(s string) (int, bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

func formatClock(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

// commonWindow returns the one range that two windows share. It returns false when
// they share nothing, or when the shared minutes are not one range.
func commonWindow(a, b *missionv1.RestartWindow) (*missionv1.RestartWindow, bool) {
	sa, ok1 := windowMinutes(a)
	sb, ok2 := windowMinutes(b)
	if !ok1 || !ok2 {
		return nil, false
	}
	var both [minutesPerDay]bool
	count := 0
	for m := range both {
		both[m] = sa[m] && sb[m]
		if both[m] {
			count++
		}
	}
	if count == 0 {
		return nil, false
	}
	// A range starts at a covered minute whose previous minute is not covered. One
	// start means one range. A full day has no start, and cannot arise from two
	// windows that each end before the day is full.
	starts, startAt := 0, 0
	for m := range both {
		if both[m] && !both[(m+minutesPerDay-1)%minutesPerDay] {
			starts++
			startAt = m
		}
	}
	if starts != 1 {
		return nil, false
	}
	end := startAt
	for both[(end+1)%minutesPerDay] {
		end = (end + 1) % minutesPerDay
	}
	return &missionv1.RestartWindow{Start: formatClock(startAt), End: formatClock(end)}, true
}

// ParentConstraints returns the constraints that a child inherits from a parent
// mission record: the constraints of its stored definition, with any field that the
// definition leaves unset taken from the constraints of the record. A definition
// that cannot be parsed is an error, so a child never starts with the constraints of
// a mission that could not be checked.
func ParentConstraints(parent *Mission) (*missionv1.MissionConstraints, error) {
	var fromDefinition *missionv1.MissionConstraints
	if parent.MissionDefinitionJSON != "" {
		def, err := UnmarshalDefinitionJSON([]byte(parent.MissionDefinitionJSON))
		if err != nil {
			return nil, fmt.Errorf("mission: originate: parse the definition of parent mission %s: %w", parent.ID, err)
		}
		fromDefinition = def.GetConstraints()
	}
	if fromDefinition == nil {
		return parent.Constraints, nil
	}
	if parent.Constraints == nil {
		return fromDefinition, nil
	}
	// The definition wins. A field that it leaves unset comes from the record.
	merged, ok := proto.Clone(fromDefinition).(*missionv1.MissionConstraints)
	if !ok {
		return nil, fmt.Errorf("mission: clone the constraints of parent mission %s", parent.ID)
	}
	if merged.GetHealthHold().AsDuration() <= 0 {
		merged.HealthHold = parent.Constraints.GetHealthHold()
	}
	if merged.GetRestartLimit().AsDuration() <= 0 {
		merged.RestartLimit = parent.Constraints.GetRestartLimit()
	}
	if merged.GetRestartPolicy() == missionv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED {
		merged.RestartPolicy = parent.Constraints.GetRestartPolicy()
		merged.RestartWindow = parent.Constraints.GetRestartWindow()
	}
	return merged, nil
}
