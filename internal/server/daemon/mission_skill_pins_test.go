// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

type pinRecorder struct {
	agentskillstore.Store // the test calls Resolve only
	resolved              []string
	missing               string
}

func (p *pinRecorder) Resolve(_ context.Context, _, _, name string) (string, error) {
	if name == p.missing {
		return "", agentskillstore.ErrNotFound
	}
	p.resolved = append(p.resolved, name)
	return "sha256:" + name, nil
}

func defWithTools(tools ...string) *missionpb.MissionDefinition {
	return &missionpb.MissionDefinition{Dependencies: &missionpb.MissionDependencies{Tools: tools}}
}

func TestSkillIDsOf_TakesOnlySkillEntriesOnce(t *testing.T) {
	got, err := skillIDsOf(defWithTools("nmap", "skill:triage", "mcp:gh:issue", "skill:review", "skill:triage"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"skill:triage", "skill:review"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSkillIDsOf_RefusesABadName(t *testing.T) {
	if _, err := skillIDsOf(defWithTools("skill:Bad_Name")); err == nil {
		t.Fatal("want an error")
	}
}

func TestPinMissionSkills_PinsEachSkillAtStart(t *testing.T) {
	rec := &pinRecorder{}
	ids, err := pinMissionSkills(context.Background(), rec, "acme", "m1", defWithTools("skill:triage", "nmap"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids, []string{"skill:triage"}) || !reflect.DeepEqual(rec.resolved, []string{"triage"}) {
		t.Fatalf("ids %v resolved %v", ids, rec.resolved)
	}
}

func TestPinMissionSkills_AMissingSkillFailsTheStart(t *testing.T) {
	rec := &pinRecorder{missing: "triage"}
	_, err := pinMissionSkills(context.Background(), rec, "acme", "m1", defWithTools("skill:triage"))
	if !errors.Is(err, agentskillstore.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestPinMissionSkills_NoSkillsNeedsNoStore(t *testing.T) {
	ids, err := pinMissionSkills(context.Background(), nil, "acme", "m1", defWithTools("nmap"))
	if err != nil || ids != nil {
		t.Fatalf("ids %v err %v", ids, err)
	}
	if _, err := pinMissionSkills(context.Background(), nil, "acme", "m1", defWithTools("skill:a")); err == nil {
		t.Fatal("a skill with no store must fail")
	}
}
