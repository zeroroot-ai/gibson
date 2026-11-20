// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"time"
)

// event_facts.go gives a reader of the Timeline the typed facts of one event:
// its time, and the finding and the merge request that it is about. The
// dashboard reads them from GetTimeline instead of the printed form of the
// event (dashboard#393).

// EventTime returns the time that the event holds. It reads the field At, then
// EvidenceAt, then RecordedAtUnixNano. It returns the zero time for an event
// that holds none of them.
func EventTime(ev Event) time.Time {
	v := reflect.ValueOf(ev)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return time.Time{}
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return time.Time{}
	}
	for _, name := range []string{"At", "EvidenceAt"} {
		if f := v.FieldByName(name); f.IsValid() {
			if t, ok := f.Interface().(time.Time); ok && !t.IsZero() {
				return t.UTC()
			}
		}
	}
	if f := v.FieldByName("RecordedAtUnixNano"); f.IsValid() && f.Kind() == reflect.Int64 && f.Int() != 0 {
		return time.Unix(0, f.Int()).UTC()
	}
	return time.Time{}
}

// EventSubject returns the finding and the merge request that the event is
// about. Each is empty when the event names none.
func EventSubject(ev Event) (findingID, mergeRequest string) {
	switch e := deref(ev).(type) {
	case FindingRaised:
		return e.ID, ""
	case FindingStatusChanged:
		return e.ID, e.MergeRequest
	case CheckRerun:
		return e.ID, ""
	case MergeRequestObserved:
		return "", e.Key
	case DeployObserved:
		return "", e.MergeRequest
	case FixReverted:
		return "", e.MergeRequest
	case RevertRequested:
		return "", e.MergeRequest
	}
	switch e := ev.(type) {
	case FindingPrioritized:
		return e.ID, ""
	case *FindingPrioritized:
		return e.ID, ""
	case FixClaimed:
		return e.ID, ""
	case *FixClaimed:
		return e.ID, ""
	case FixClaimReleased:
		return e.ID, ""
	case *FixClaimReleased:
		return e.ID, ""
	case HealthObserved:
		return "", e.MergeRequest
	case *HealthObserved:
		return "", e.MergeRequest
	case HealthUnavailable:
		return "", e.MergeRequest
	case *HealthUnavailable:
		return "", e.MergeRequest
	case MergeRequestQueued:
		return "", e.MergeRequest
	case *MergeRequestQueued:
		return "", e.MergeRequest
	case MergeGranted:
		return "", e.MergeRequest
	case *MergeGranted:
		return "", e.MergeRequest
	}
	return "", ""
}

// FindingEventIndexes returns the positions of the events of one finding: the
// events that name it, and the events of each merge request that a status
// change of the finding names. A merge request is known from its first status
// change on, in Timeline order.
func FindingEventIndexes(events []Event, findingID string) []int {
	if findingID == "" {
		return nil
	}
	mrs := map[string]bool{}
	var out []int
	for i, ev := range events {
		f, mr := EventSubject(ev)
		switch {
		case f == findingID:
			if mr != "" {
				mrs[mr] = true
			}
			out = append(out, i)
		case f == "" && mr != "" && mrs[mr]:
			out = append(out, i)
		}
	}
	return out
}
