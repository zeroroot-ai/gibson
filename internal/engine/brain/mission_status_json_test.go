// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"testing"
)

func TestMissionStatusUnmarshalMapsOldNames(t *testing.T) {
	tests := []struct {
		stored string
		want   MissionStatus
	}{
		{`"pending"`, MissionSubmitted},
		{`"running"`, MissionWorking},
		{`"submitted"`, MissionSubmitted},
		{`"working"`, MissionWorking},
		{`"paused"`, MissionPaused},
		{`"completed"`, MissionCompleted},
		{`"failed"`, MissionFailed},
	}
	for _, tt := range tests {
		t.Run(tt.stored, func(t *testing.T) {
			var got MissionStatus
			if err := json.Unmarshal([]byte(tt.stored), &got); err != nil {
				t.Fatalf("unmarshal %s: %v", tt.stored, err)
			}
			if got != tt.want {
				t.Errorf("status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMissionStatusUnmarshalRejectsANonString(t *testing.T) {
	var got MissionStatus
	if err := json.Unmarshal([]byte(`7`), &got); err == nil {
		t.Fatal("unmarshal of a number returned no error")
	}
}

// A stored snapshot of the old shape restores to the new state.
func TestRestoreOfASnapshotWithOldMissionStateNames(t *testing.T) {
	var data struct {
		Missions []MissionSnapshot `json:"missions"`
	}
	stored := `{"missions":[{"ID":"m1","Status":"pending"},{"ID":"m2","Status":"running"}]}`
	if err := json.Unmarshal([]byte(stored), &data); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if data.Missions[0].Status != MissionSubmitted || data.Missions[1].Status != MissionWorking {
		t.Errorf("statuses = %q and %q, want submitted and working",
			data.Missions[0].Status, data.Missions[1].Status)
	}
}

// A stored mission.done event of the old shape folds to the new state.
func TestFoldOfAStoredEventWithAnOldMissionStateName(t *testing.T) {
	stored := []byte(`{"kind":"mission.done","payload":{"ID":"m1","Outcome":"running"}}`)
	ev, err := DecodeEvent(stored)
	if err != nil {
		t.Fatalf("decode event: %v", err)
	}
	done, ok := ev.(MissionDone)
	if !ok {
		t.Fatalf("decoded %T, want MissionDone", ev)
	}
	if done.Outcome != MissionWorking {
		t.Errorf("outcome = %q, want %q", done.Outcome, MissionWorking)
	}
}
