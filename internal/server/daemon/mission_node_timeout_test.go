// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"
	"time"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A live coding-agent session is one AGENT node that runs for hours. Its node
// declares that in MissionNode.timeout, and before gibson#1602 that value
// stopped here: the projection dropped it, so the dispatch could never be bound
// by anything but one harness-wide default. These tests pin the first link of
// that chain.

func TestMissionDefinitionToProjected_CarriesTheNodeTimeout(t *testing.T) {
	node := agentNode("zerocool")
	node.Timeout = durationpb.New(8 * time.Hour)

	proj, err := missionDefinitionToProjected(&missionpb.MissionDefinition{
		Id:    "m1",
		Nodes: map[string]*missionpb.MissionNode{"watch": node},
	}, "")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(proj.Nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(proj.Nodes))
	}
	if got := proj.Nodes[0].Timeout; got != 8*time.Hour {
		t.Fatalf("node timeout = %s, want 8h — the node's declared bound must reach the brain", got)
	}
}

func TestMissionDefinitionToProjected_NoTimeoutIsZeroNotAnExpiry(t *testing.T) {
	// Zero has to mean "the node declared none" so the dispatch boundary can
	// decide per kind. Reading it as "expire now" would fail every node that
	// does not set one.
	proj, err := missionDefinitionToProjected(&missionpb.MissionDefinition{
		Id:    "m1",
		Nodes: map[string]*missionpb.MissionNode{"a": toolNode("nmap")},
	}, "")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if got := proj.Nodes[0].Timeout; got != 0 {
		t.Fatalf("node timeout = %s, want 0 for a node that declared none", got)
	}
}

func TestNodeTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   *durationpb.Duration
		want time.Duration
	}{
		{"absent", nil, 0},
		{"zero", durationpb.New(0), 0},
		// A negative duration is malformed, not an instruction to expire at
		// once: treat it the same as absent rather than failing every dispatch.
		{"negative", durationpb.New(-time.Second), 0},
		{"positive", durationpb.New(90 * time.Minute), 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nodeTimeout(&missionpb.MissionNode{Timeout: tc.in})
			if got != tc.want {
				t.Fatalf("nodeTimeout = %s, want %s", got, tc.want)
			}
		})
	}
}
