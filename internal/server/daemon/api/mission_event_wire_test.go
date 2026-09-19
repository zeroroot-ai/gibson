// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import "testing"

// TestMissionEventWireData: the projector's status payload reaches the wire
// when no JSON data is present, JSON data still wins, and an event with
// neither carries no map.
func TestMissionEventWireData(t *testing.T) {
	t.Parallel()
	status := &MissionEventData{EventType: "status", Payload: map[string]any{"status": "failed"}}
	got := missionEventWireData(status)
	if got == nil || got.GetEntries()["status"].GetStringValue() != "failed" {
		t.Fatalf("status payload not on the wire: %v", got)
	}
	withJSON := &MissionEventData{EventType: "node_completed", Data: `{"k":"v"}`, Payload: map[string]any{"status": "ignored"}}
	got = missionEventWireData(withJSON)
	if got == nil || got.GetEntries()["k"].GetStringValue() != "v" || got.GetEntries()["status"] != nil {
		t.Fatalf("json data must win: %v", got)
	}
	if missionEventWireData(&MissionEventData{EventType: "mission.started"}) != nil {
		t.Fatal("no data and no payload must yield no map")
	}
}
