// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
	"time"
)

// The events of one finding are the events that name it and the events of the
// merge request of its fix. The events of another finding stay out, also when
// they share a merge request (dashboard#393).
func TestFindingEventIndexes_KeepsTheEventsOfOneFinding(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	events := []Event{
		/* 0 */ FindingRaised{ID: "f1", At: at},
		/* 1 */ FindingRaised{ID: "f2", At: at},
		/* 2 */ MergeRequestObserved{Key: "mr-1", State: "merged", At: at}, // before f1 knows mr-1
		/* 3 */ FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at},
		/* 4 */ FindingStatusChanged{ID: "f2", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at},
		/* 5 */ &MergeRequestObserved{Key: "mr-1", State: "merged", At: at},
		/* 6 */ DeployObserved{MergeRequest: "mr-1", At: at},
		/* 7 */ HealthObserved{MergeRequest: "mr-1", Held: false, At: at},
		/* 8 */ RevertRequested{MergeRequest: "mr-1", At: at},
		/* 9 */ FixReverted{MergeRequest: "mr-1", At: at},
		/* 10 */ CheckRerun{ID: "f1", EvidenceAt: at},
		/* 11 */ DeployObserved{MergeRequest: "mr-2", At: at},
	}
	got := FindingEventIndexes(events, "f1")
	want := []int{0, 3, 5, 6, 7, 8, 9, 10}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes = %v, want %v", got, want)
	}
	if FindingEventIndexes(events, "") != nil {
		t.Fatal("no finding must keep no event")
	}
}

func TestEventTime_ReadsTheTimeOfTheEvent(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	if got := EventTime(DeployObserved{At: at}); !got.Equal(at) {
		t.Errorf("At: %v", got)
	}
	if got := EventTime(&CheckRerun{EvidenceAt: at}); !got.Equal(at) {
		t.Errorf("EvidenceAt: %v", got)
	}
	if got := EventTime(AgentToolCallObserved{RecordedAtUnixNano: at.UnixNano()}); !got.Equal(at) {
		t.Errorf("RecordedAtUnixNano: %v", got)
	}
	if got := EventTime(FindingPrioritized{ID: "f1"}); !got.IsZero() {
		t.Errorf("an event with no time: %v", got)
	}
}
