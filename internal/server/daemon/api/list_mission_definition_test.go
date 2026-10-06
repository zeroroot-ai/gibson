// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — list_mission_definition_test.go unit tests for DaemonService.ListMissionDefinitions.
package api

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

	resp, err := server.ListMissionDefinitions(context.Background(), &daemonpb.ListMissionDefinitionsRequest{PageSize: 10})
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

// Two pages of one list give each definition once, the last page has no
// next token, and a token that the daemon did not write is InvalidArgument
// (ADR-0028, rule 3, gibson#874).
func TestListMissionDefinitions_TwoPagesGiveEachItemOnce(t *testing.T) {
	t.Parallel()

	all := []MissionDefinitionData{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	daemon := &mockDaemon{
		listMissionDefinitionsFn: func(_ context.Context, limit, offset int) ([]MissionDefinitionData, int, error) {
			end := min(offset+limit, len(all))
			if offset >= len(all) {
				return nil, len(all), nil
			}
			return all[offset:end], len(all), nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)

	seen := map[string]int{}
	token := ""
	for page := 0; ; page++ {
		if page > 2 {
			t.Fatal("more than two pages")
		}
		resp, err := server.ListMissionDefinitions(context.Background(),
			&daemonpb.ListMissionDefinitionsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, m := range resp.GetMissions() {
			seen[m.GetName()]++
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	for _, d := range all {
		if seen[d.Name] != 1 {
			t.Fatalf("definition %s seen %d times", d.Name, seen[d.Name])
		}
	}

	_, err := server.ListMissionDefinitions(context.Background(),
		&daemonpb.ListMissionDefinitionsRequest{PageToken: "not-a-token"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad token: code %v, want InvalidArgument", status.Code(err))
	}
}

// The mission list and the mission history refuse a page token that the
// daemon did not write, and a full page carries a next page token.
func TestMissionLists_PageTokens(t *testing.T) {
	t.Parallel()
	daemon := &mockDaemon{}
	server := NewDaemonServer(daemon, nil, nil)
	ctx := context.Background()

	if _, err := server.ListMissions(ctx, &daemonpb.ListMissionsRequest{PageToken: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("ListMissions bad token: code %v", status.Code(err))
	}
	if _, err := server.GetMissionHistory(ctx, &daemonpb.GetMissionHistoryRequest{Name: "m", PageToken: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("GetMissionHistory bad token: code %v", status.Code(err))
	}
	resp, err := server.GetMissionHistory(ctx, &daemonpb.GetMissionHistoryRequest{Name: "m", PageSize: 5})
	if err != nil || resp.GetNextPageToken() != "" {
		t.Errorf("empty history: %v, token %q", err, resp.GetNextPageToken())
	}
}
