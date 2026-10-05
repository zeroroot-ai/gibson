// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"slices"
	"testing"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// Every field here is one a wrong value would break silently rather than
// loudly, which is why they are asserted together rather than trusted to a
// method chain nobody reads.
func TestNewRunMissionContext_CarriesWhatARunNeeds(t *testing.T) {
	m := &mission.Mission{
		ID:        types.NewID(),
		Name:      "cluster-assessment",
		TenantID:  "tenant-acme",
		CreatedBy: principal.Principal{Kind: principal.User, ID: "alice"},
	}
	run := &mission.MissionRun{RunNumber: 7}
	def := &missionpb.MissionDefinition{
		Secrets: &missionpb.MissionSecrets{
			Tools: []string{"cred:goat-cluster"},
			Tool:  map[string]*missionpb.SecretNames{"kube-bench": {Names: []string{"cred:kube-bench-only"}}},
		},
	}

	got := newRunMissionContext(m, run, def, "run-77")

	if got.ID != m.ID {
		t.Errorf("ID = %v, want %v", got.ID, m.ID)
	}
	if got.Name != "cluster-assessment" {
		t.Errorf("Name = %q", got.Name)
	}
	// A wrong tenant shows one tenant's run on another's console.
	if got.TenantID != "tenant-acme" {
		t.Errorf("TenantID = %q, want the mission's tenant", got.TenantID)
	}
	// The model gate decides for this person on every slot resolution of the
	// run. Without it the gate cannot name who asked (hosted#358).
	if got.CreatedBy != m.CreatedBy {
		t.Errorf("CreatedBy = %+v, want the mission's creator %+v", got.CreatedBy, m.CreatedBy)
	}
	// Mission-scoped GraphRAG storage keys by this.
	if got.MissionRunID != "run-77" {
		t.Errorf("MissionRunID = %q", got.MissionRunID)
	}
	// Mission memory queries key by this.
	if got.RunNumber != 7 {
		t.Errorf("RunNumber = %d, want 7", got.RunNumber)
	}

	// The declaration reached the context, through the union a dispatch reads.
	want := []string{"cred:goat-cluster", "cred:kube-bench-only"}
	if names := got.Secrets.ForTool("kube-bench"); !slices.Equal(names, want) {
		t.Errorf("ForTool(kube-bench) = %v, want %v", names, want)
	}
	if names := got.Secrets.ForTool("trivy-k8s"); !slices.Equal(names, []string{"cred:goat-cluster"}) {
		t.Errorf("ForTool(trivy-k8s) = %v, want only the tool-wide name", names)
	}
}

// A mission with no secrets block hands nothing to anything, which is how every
// mission written before the field existed must keep behaving.
func TestNewRunMissionContext_NoDeclarationHandsNothing(t *testing.T) {
	got := newRunMissionContext(
		&mission.Mission{ID: types.NewID(), TenantID: "t"},
		&mission.MissionRun{RunNumber: 1},
		&missionpb.MissionDefinition{},
		"run-1",
	)

	if got.Secrets.Declares() {
		t.Errorf("a definition with no secrets block declared something: %+v", got.Secrets)
	}
}
