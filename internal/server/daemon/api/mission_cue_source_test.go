// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// cueSourceFixture is a small mission. Its compiled definition is what a
// client sends beside it.
const cueSourceFixture = `
import (
	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"
)

mission: missionv1.#MissionDefinition & {
	name:    "cue-source-check"
	version: "1.0.0"
	nodes: {
		fix: {
			id:   "fix"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: "bank/core"
				spec: {
					goal: "Fix it."
					repositories: [{
						name:         "repo"
						connectorRef: "connector/forge"
						project:      "group/repo"
						deliverable:  jobv1.#DELIVERABLE_KIND_MERGE_REQUEST
					}]
				}
			}
		}
	}
	entryPoints: ["fix"]
	exitPoints: ["fix"]
}
`

// compiledFixture returns the definition that cueSourceFixture compiles to.
func compiledFixture(t *testing.T) *missionpb.MissionDefinition {
	t.Helper()
	def, err := cueruntime.Export(context.Background(), cueSourceFixture)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return def
}

// tamperedFixture returns the compiled definition with one changed goal, so
// it no longer matches the source.
func tamperedFixture(t *testing.T) *missionpb.MissionDefinition {
	t.Helper()
	def, ok := proto.Clone(compiledFixture(t)).(*missionpb.MissionDefinition)
	if !ok {
		t.Fatal("clone is not a MissionDefinition")
	}
	def.GetNodes()["fix"].GetJobConfig().GetSpec().Goal = "Delete every branch."
	return def
}

func TestCreateMissionDefinition_TheSourceMustCompileToTheDefinition(t *testing.T) {
	t.Parallel()
	stored := 0
	server := NewDaemonServer(&mockDaemon{
		createMissionDefinitionFn: func(_ context.Context, _ CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error) {
			stored++
			return CreateMissionDefinitionResultData{MissionDefinitionID: "def-1"}, nil
		},
	}, nil, nil)

	cases := []struct {
		name   string
		source string
		def    *missionpb.MissionDefinition
		want   codes.Code
	}{
		{"agree", cueSourceFixture, compiledFixture(t), codes.OK},
		{"no source", "", tamperedFixture(t), codes.OK},
		{"disagree", cueSourceFixture, tamperedFixture(t), codes.InvalidArgument},
		{"does not compile", "mission: {", compiledFixture(t), codes.InvalidArgument},
	}
	for _, c := range cases {
		before := stored
		_, err := server.CreateMissionDefinition(context.Background(), &daemonpb.CreateMissionDefinitionRequest{
			Definition: c.def,
			CueSource:  c.source,
		})
		if got := status.Code(err); got != c.want {
			t.Fatalf("%s: code = %v (err=%v), want %v", c.name, got, err, c.want)
		}
		if c.want != codes.OK && stored != before {
			t.Fatalf("%s: a refused request reached the store", c.name)
		}
	}
}

func TestUpdateMissionDefinition_TheSourceMustCompileToTheDefinition(t *testing.T) {
	t.Parallel()
	stored := 0
	server := NewDaemonServer(&mockDaemon{
		updateMissionDefinitionFn: func(_ context.Context, _ UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error) {
			stored++
			return UpdateMissionDefinitionResultData{MissionDefinitionID: "def-1"}, nil
		},
	}, nil, nil)

	_, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: tamperedFixture(t),
		CueSource:  cueSourceFixture,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("disagree: err = %v, want InvalidArgument", err)
	}
	if stored != 0 {
		t.Fatal("a refused update reached the store")
	}

	_, err = server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: compiledFixture(t),
		CueSource:  cueSourceFixture,
	})
	if err != nil {
		t.Fatalf("agree: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored = %d, want 1", stored)
	}
}
