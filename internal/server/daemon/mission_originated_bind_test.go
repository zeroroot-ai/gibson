// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// childWithPlaceholder is a stored mission whose definition still carries a
// {{target.*}} placeholder — exactly what Originator.buildChild writes, since the
// originator holds no target store and binds nothing.
func childWithPlaceholder(t *testing.T, targetID types.ID) *mission.Mission {
	t.Helper()
	def := &missionpb.MissionDefinition{
		Id:   "child",
		Name: "child-scan",
		Nodes: map[string]*missionpb.MissionNode{
			"scan": {
				Id:   "scan",
				Type: missionpb.NodeType_NODE_TYPE_TOOL,
				Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
					ToolName: "nmap",
					Input:    map[string]string{"target": "{{target.host}}"},
				}},
			},
		},
	}
	defJSON, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	return &mission.Mission{
		ID:                    types.NewID(),
		TenantID:              "tenant-a",
		Name:                  "child-scan",
		TargetID:              targetID,
		MissionDefinitionJSON: string(defJSON),
	}
}

// bindTestManager returns a manager whose only wired dependency is a target store
// that answers for one target.
func bindTestManager(id types.ID, target *types.Target) *missionManager {
	return &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			if got != id {
				return nil, errTargetNotFoundForTest
			}
			return target, nil
		}},
	}
}

var errTargetNotFoundForTest = errNotFoundForTest{}

type errNotFoundForTest struct{}

func (errNotFoundForTest) Error() string { return "target not found" }

// A child mission carrying a placeholder binds against its own target. Before
// this the originate path never bound anything, and the projection backstop
// refused the child rather than dispatching it against the literal text
// "{{target.host}}" (gibson#529).
func TestBindStoredDefinition_ChildBindsAgainstItsOwnTarget(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	m := bindTestManager(childTarget, &types.Target{
		ID:       childTarget,
		TenantID: "tenant-a",
		Name:     "child-host",
		Type:     "kubernetes",
		URL:      "https://10.60.0.99:6443",
	})

	def, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	in := def.GetNodes()["scan"].GetToolConfig().GetInput()["target"]
	if strings.Contains(in, "{{target.") {
		t.Fatalf("the placeholder survived binding: %q", in)
	}
	if !strings.Contains(in, "10.60.0.99") {
		t.Errorf("bound input = %q, want the child's own host", in)
	}
}

// The parent's target is never used. A child narrowed to a different target in the
// parent's set has to reach its own host, and a child dispatched against the
// parent's would assess the wrong one and report the result as the child's.
func TestBindStoredDefinition_TheParentsTargetIsNotReused(t *testing.T) {
	parentTarget := types.NewID()
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)

	// The store answers for BOTH, so nothing but the mission's own TargetID can
	// decide which one is bound.
	m := &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			switch got {
			case parentTarget:
				return &types.Target{ID: parentTarget, TenantID: "tenant-a", Name: "parent-host", URL: "https://10.60.0.1:6443"}, nil
			case childTarget:
				return &types.Target{ID: childTarget, TenantID: "tenant-a", Name: "child-host", URL: "https://10.60.0.2:6443"}, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}

	def, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	in := def.GetNodes()["scan"].GetToolConfig().GetInput()["target"]
	if strings.Contains(in, "10.60.0.1") {
		t.Errorf("the child bound to the PARENT's host: %q", in)
	}
	if !strings.Contains(in, "10.60.0.2") {
		t.Errorf("bound input = %q, want the child's host 10.60.0.2", in)
	}
}

// The bound definition is written back onto the record, so the stored run, the
// projection and the dispatcher all read one bound copy — the same rule the
// submit path follows.
func TestBindStoredDefinition_WritesTheBoundCopyBackOntoTheRecord(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	before := rec.MissionDefinitionJSON
	m := bindTestManager(childTarget, &types.Target{
		ID: childTarget, TenantID: "tenant-a", Name: "child-host", URL: "https://10.60.0.7:6443",
	})

	if _, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec.MissionDefinitionJSON == before {
		t.Fatal("the record still holds the unbound definition; a later reader would bind it again or not at all")
	}
	if strings.Contains(rec.MissionDefinitionJSON, "{{target.") {
		t.Errorf("the stored definition still carries a placeholder: %s", rec.MissionDefinitionJSON)
	}
	if got := rec.Metadata["target_ref"]; got != "https://10.60.0.7:6443" {
		t.Errorf("target_ref = %v, want the child's own reference", got)
	}
}

// A mission with no target is refused by name rather than bound against nothing.
// Binding against a nil target is what produced "{{target.host}}" as a hostname.
func TestBindStoredDefinition_RefusesAMissionWithNoTarget(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	rec.TargetID = ""
	m := bindTestManager(types.NewID(), &types.Target{})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal for a mission that names no target")
	}
	if !strings.Contains(err.Error(), "names no target") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// A mission with no definition is refused. It used to reach missionManager.Run
// through a temp file and fail there with "mission definition not found", naming
// a temp path instead of the mission.
func TestBindStoredDefinition_RefusesAMissionWithNoDefinition(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	rec.MissionDefinitionJSON = ""
	m := bindTestManager(rec.TargetID, &types.Target{ID: rec.TargetID, TenantID: "tenant-a"})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal for a mission with no definition")
	}
	if !strings.Contains(err.Error(), "has no definition") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// A target the tenant does not own is refused. A stored TargetID is not a licence
// to read a target — the resolution goes through the same ownership check the
// submit path uses.
func TestBindStoredDefinition_RefusesATargetTheTenantDoesNotOwn(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	m := bindTestManager(childTarget, &types.Target{
		ID: childTarget, TenantID: "someone-else", Name: "not-ours", URL: "https://10.0.0.1:6443",
	})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal when the mission's target belongs to another tenant")
	}
	// The refusal must be about ownership. A test that accepts any error would
	// pass on a nil store or a typo in the fixture and prove nothing.
	if !strings.Contains(err.Error(), "resolve target") {
		t.Errorf("the refusal is not the ownership check: %v", err)
	}
	t.Logf("ownership refusal: %v", err)
}

// The projection backstop stays. It is the thing that made the unbound-child gap
// visible instead of silent, and it is the guard that catches the next path that
// forgets to bind.
func TestProjection_BackstopStillRefusesAnUnboundNode(t *testing.T) {
	_, _, _, err := nodeKindTargetInput(&missionpb.MissionNode{
		Id:   "scan",
		Type: missionpb.NodeType_NODE_TYPE_TOOL,
		Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
			ToolName: "nmap",
			Input:    map[string]string{"target": "{{target.host}}"},
		}},
	})
	if err == nil {
		t.Fatal("the backstop accepted a node that was never bound")
	}
	if !strings.Contains(err.Error(), "never bound") {
		t.Errorf("the refusal does not say the node was unbound: %v", err)
	}
}
