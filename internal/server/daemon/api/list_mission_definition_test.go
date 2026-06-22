// Package api — list_mission_definition_test.go unit tests for DaemonService.ListMissionDefinitions.
package api

import (
	"context"
	"testing"
	"time"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// TestListMissionDefinitions_MissionDefinitionIdPropagated verifies that the
// MissionDefinitionId field in each MissionDefinitionInfo is populated from
// the daemon-returned MissionDefinitionID (gibson#438).
func TestListMissionDefinitions_MissionDefinitionIdPropagated(t *testing.T) {
	t.Parallel()

	const defID = "def-01ABCXYZ"
	now := time.Now().Truncate(time.Second)

	daemon := &mockDaemon{
		listMissionDefinitionsFn: func(_ context.Context, _, _ int) ([]MissionDefinitionData, int, error) {
			return []MissionDefinitionData{
				{
					MissionDefinitionID: defID,
					Name:                "my-def",
					Version:             "1.0.0",
					Description:         "test def",
					Source:              "github.com/example/def",
					InstalledAt:         now,
					UpdatedAt:           now,
					NodeCount:           3,
				},
			}, 1, nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)

	resp, err := server.ListMissionDefinitions(context.Background(), &daemonpb.ListMissionDefinitionsRequest{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetMissions()) != 1 {
		t.Fatalf("expected 1 mission definition, got %d", len(resp.GetMissions()))
	}
	got := resp.GetMissions()[0].GetMissionDefinitionId()
	if got != defID {
		t.Fatalf("expected mission_definition_id %q, got %q", defID, got)
	}
}
