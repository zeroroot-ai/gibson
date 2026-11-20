// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"strings"
	"testing"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// The fix mission is one job node on a bank, with one repository that
// delivers a merge request, and the finding as its input. This is the shape
// that fix-agent internal/code built as a raw definition, so the daemon links
// the merge request to the finding when the job closes.
func TestFixMission_IsOneJobWithAMergeRequestForTheFinding(t *testing.T) {
	t.Parallel()
	def, err := Render(context.Background(), "fix", paramsFor(t, "fix"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(def.GetNodes()) != 1 {
		t.Fatalf("nodes = %d, want one job node", len(def.GetNodes()))
	}
	node := def.GetNodes()["fix"]
	if node.GetType() != missionpb.NodeType_NODE_TYPE_JOB {
		t.Fatalf("node type = %v, want a job", node.GetType())
	}
	job := node.GetJobConfig()
	if job.GetBankRef() != "bank/coding" {
		t.Errorf("bank = %q", job.GetBankRef())
	}
	spec := job.GetSpec()
	if got := spec.GetInputs(); len(got) != 1 || got[0] != "finding-42" {
		t.Errorf("inputs = %v, want the finding", got)
	}
	repos := spec.GetRepositories()
	if len(repos) != 1 {
		t.Fatalf("repositories = %d, want one", len(repos))
	}
	r := repos[0]
	if r.GetDeliverable() != jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST ||
		r.GetConnectorRef() != "connector/gitlab-fixloop" || r.GetProject() != "examplebank/customer-portal" ||
		r.GetBaseBranch() != "main" {
		t.Errorf("repository = %+v", r)
	}
	if !strings.Contains(spec.GetGoal(), `Weakness: "CVE-2025-1234"`) || !strings.Contains(spec.GetGoal(), "Do not merge.") {
		t.Errorf("goal does not carry the brief and the rules:\n%s", spec.GetGoal())
	}
	if spec.GetAcceptance() != nil {
		t.Error("the fix job must have no acceptance step: the pipeline is the check")
	}
}

// A missing parameter refuses the render (ADR-0118).
func TestFixMission_AMissingParameterRefusesTheRender(t *testing.T) {
	t.Parallel()
	for name := range paramsFor(t, "fix") {
		p := paramsFor(t, "fix")
		delete(p, name)
		if _, err := Render(context.Background(), "fix", p); err == nil {
			t.Errorf("render with no %s: want an error", name)
		}
	}
}
