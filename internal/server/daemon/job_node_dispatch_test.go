// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
)

// verifierHarness answers the two dispatches a verifier can be.
type verifierHarness struct {
	gibsonharness.AgentHarness
	toolOut  string
	toolErr  error
	agentOut map[string]any
	agentErr error
	called   []string
}

func (h *verifierHarness) CallToolProto(_ context.Context, name string, _, response proto.Message) error {
	h.called = append(h.called, "tool/"+name)
	if h.toolErr != nil {
		return h.toolErr
	}
	resp, _ := response.(*toolpb.ExecuteResponse)
	resp.OutputJson = h.toolOut
	return nil
}

func (h *verifierHarness) DelegateToAgent(_ context.Context, name string, _ agent.Task) (agent.Result, error) {
	h.called = append(h.called, "agent/"+name)
	if h.agentErr != nil {
		return agent.Result{}, h.agentErr
	}
	return agent.Result{Output: h.agentOut}, nil
}

// TestHarnessVerifier_DispatchesToolOrAgentAndParsesTheReport asserts a
// verifier ref picks the dispatch, a bare name is an agent, and a report
// that is not the structured shape fails the pass with a clear error.
func TestHarnessVerifier_DispatchesToolOrAgentAndParsesTheReport(t *testing.T) {
	ctx := context.Background()
	payload := jobnode.VerifyPayload{JobID: "job-1", Goal: "fix", Pass: 1}

	h := &verifierHarness{toolOut: `{"pass": true, "score": 0.9, "report": "green"}`}
	r, err := (&harnessVerifier{harness: h}).Verify(ctx, "tool/verify", payload)
	if err != nil || !r.Pass || r.Score != 0.9 || r.Report != "green" || h.called[0] != "tool/verify" {
		t.Fatalf("tool: %+v, %v, %v", r, err, h.called)
	}

	h = &verifierHarness{agentOut: map[string]any{"pass": false, "score": 0.2, "report": "red"}}
	r, err = (&harnessVerifier{harness: h}).Verify(ctx, "reviewer", payload)
	if err != nil || r.Pass || r.Score != 0.2 || h.called[0] != "agent/reviewer" {
		t.Fatalf("agent: %+v, %v, %v", r, err, h.called)
	}

	h = &verifierHarness{toolOut: `{"verdict": "fine"}`}
	if _, err := (&harnessVerifier{harness: h}).Verify(ctx, "tool/verify", payload); err == nil || !strings.Contains(err.Error(), "lacks pass or score") {
		t.Fatalf("an unstructured report must fail the pass: %v", err)
	}
	h = &verifierHarness{toolOut: "not json"}
	if _, err := (&harnessVerifier{harness: h}).Verify(ctx, "tool/verify", payload); err == nil {
		t.Fatal("a non-JSON report must fail the pass")
	}
	if _, err := (&harnessVerifier{harness: &verifierHarness{toolErr: errors.New("down")}}).Verify(ctx, "tool/verify", payload); err == nil {
		t.Fatal("a tool failure must be reported")
	}
	if _, err := (&harnessVerifier{harness: &verifierHarness{agentErr: errors.New("down")}}).Verify(ctx, "agent/reviewer", payload); err == nil {
		t.Fatal("an agent failure must be reported")
	}
	if _, err := (&harnessVerifier{harness: h}).Verify(ctx, "plugin/x", payload); err == nil {
		t.Fatal("a plugin is not a verifier kind")
	}
}

// TestDispatchJob_RunsTheLoopOverTheStore asserts the brain's job arm reads
// the node config, opens the job on the named bank as the mission, and
// reports the close as the work result.
func TestDispatchJob_RunsTheLoopOverTheStore(t *testing.T) {
	jobs := newFakeJobStore()
	// The member answers every turn at once: the fake store marks the job
	// waiting as soon as it is opened or sent to.
	jobs.onOpen = func(j *job.Job) { jobs.appendEvent(j.ID, job.EventState, job.StateWaiting, "", 0) }
	jobs.onSend = func(id string) { jobs.appendEvent(id, job.EventState, job.StateWaiting, "", 0) }
	b := newBrainExecutor(nil, testObsLogger().Slog())
	b.jobs = func() (job.Store, error) { return jobs, nil }
	h := &verifierHarness{toolOut: `{"pass": true, "score": 0.95, "report": "green"}`}
	bind := &missionBinding{ctx: context.Background(), tenant: "acme", harness: h}

	cfg, _ := protojson.Marshal(&missionpb.JobNodeConfig{BankRef: "bank-1", Spec: &jobpb.JobSpec{
		Goal: "fix the build", Acceptance: &jobpb.Acceptance{VerifierComponent: "tool/verify", PassingScore: 0.8, MaxPasses: 2},
	}})
	out, err := b.dispatchJob(bind, brain.DispatchRequest{WorkID: "run-1/fix", MissionID: "run-1", Kind: "job", Target: "bank-1", Input: string(cfg)})
	if err != nil {
		t.Fatalf("dispatchJob: %v", err)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["verdict"] != "accomplished" || summary["passes"].(float64) != 1 {
		t.Errorf("summary = %v", summary)
	}
	opened := jobs.jobs[summary["job_id"].(string)]
	if opened.OpenedBy.ID != "mission:run-1" || opened.Spec.GetContext()["node_id"].GetStringValue() != "fix" {
		t.Errorf("opened = %+v", opened)
	}

	if _, err := b.dispatchJob(bind, brain.DispatchRequest{Input: "not json", Target: "bank-1"}); err == nil {
		t.Error("a broken node config must be reported")
	}
	b.jobs = func() (job.Store, error) { return nil, errors.New("no pool") }
	if _, err := b.dispatchJob(bind, brain.DispatchRequest{Input: string(cfg), Target: "bank-1"}); err == nil {
		t.Error("no store must be reported")
	}
	b.jobs = nil
	if _, err := b.dispatchJob(bind, brain.DispatchRequest{Input: string(cfg), Target: "bank-1"}); err == nil {
		t.Error("an unwired store must be reported")
	}
}

func TestNodeIDOf(t *testing.T) {
	if got := nodeIDOf("run-1/fix", "run-1"); got != "fix" {
		t.Errorf("nodeIDOf = %q", got)
	}
	if got := nodeIDOf("fix", ""); got != "fix" {
		t.Errorf("nodeIDOf = %q", got)
	}
}
