// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import "testing"

// TestTierDefaults_TeamFitsKindBudget pins the team-tier Neo4j CPU
// request small enough to schedule on a single-node kind dev cluster
// where the rest of the platform (Zitadel, CNPG, Vault, Envoy, daemon,
// dashboard, ext-authz, …) already consumes the bulk of node CPU. See
// tenant-operator#61.
//
// If this drifts upward, every team-tier signup on the dev cluster
// hits FailedScheduling: Insufficient cpu and Provision wedges at
// the Neo4j wait-for-ready step.
func TestTierDefaults_TeamFitsKindBudget(t *testing.T) {
	cases := []struct {
		tier        string
		wantStorage string
		wantCPU     string
		wantMemory  string
	}{
		{"team", "10Gi", "100m", "1Gi"},
		{"org", "50Gi", "500m", "4Gi"},
		{"enterprise", "200Gi", "1", "8Gi"},
		{"enterprise-deploy", "200Gi", "1", "8Gi"},
		// legacy ids alias to enterprise behaviour
		{"platform", "200Gi", "1", "8Gi"},
		{"public-sector", "200Gi", "1", "8Gi"},
		// unknown / legacy team-like tiers fall through to team defaults
		{"", "10Gi", "100m", "1Gi"},
		{"free", "10Gi", "100m", "1Gi"},
		{"solo", "10Gi", "100m", "1Gi"},
	}
	for _, tc := range cases {
		t.Run(tc.tier, func(t *testing.T) {
			storage, cpu, memory := tierDefaults(tc.tier)
			if storage != tc.wantStorage {
				t.Errorf("storage = %q, want %q", storage, tc.wantStorage)
			}
			if cpu != tc.wantCPU {
				t.Errorf("cpu = %q, want %q", cpu, tc.wantCPU)
			}
			if memory != tc.wantMemory {
				t.Errorf("memory = %q, want %q", memory, tc.wantMemory)
			}
		})
	}
}
