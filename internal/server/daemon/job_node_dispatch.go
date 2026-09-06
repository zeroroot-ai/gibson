// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
)

// dispatchJob runs one job node (ADR-0019 decisions 10, 12 and 15,
// gibson#1713): the loop lives in jobnode, the store and the verifier are
// the daemon's. The node's declared timeout bounds the whole loop.
func (b *brainExecutor) dispatchJob(bind *missionBinding, req brain.DispatchRequest) (string, error) {
	if b.jobs == nil {
		return "", errors.New("job node: this daemon serves no jobs")
	}
	store, err := b.jobs()
	if err != nil {
		return "", fmt.Errorf("job node: %w", err)
	}
	cfg := &missionpb.JobNodeConfig{}
	if err := protojson.Unmarshal([]byte(req.Input), cfg); err != nil {
		return "", fmt.Errorf("job node: read the node config: %w", err)
	}

	ctx := bind.ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	out, err := jobnode.Run(ctx, jobnode.Input{
		TenantID:     bind.tenant,
		MissionRunID: req.MissionID,
		NodeID:       nodeIDOf(req.WorkID, req.MissionID),
		BankID:       req.Target,
		Spec:         cfg.GetSpec(),
		// The mission is the opener and the scorer: it opened the job, so it
		// may close it (ADR-0019 decision 3).
		Opener:   job.Principal{Kind: job.PrincipalService, ID: "mission:" + req.MissionID},
		Ops:      store,
		Verifier: &harnessVerifier{harness: bind.harness, timeout: req.Timeout},
	})
	if err != nil && !errors.Is(err, jobnode.ErrClosedElsewhere) {
		return "", fmt.Errorf("job node: run the job on bank %s: %w", req.Target, err)
	}
	summary, merr := json.Marshal(map[string]any{
		"job_id": out.Result.JobID, "verdict": string(out.Result.Verdict), "score": out.Result.Score,
		"passes": out.Passes, "deliverables": out.Result.Deliverables, "report": out.Report,
	})
	if merr != nil {
		return "", fmt.Errorf("job node: render the outcome: %w", merr)
	}
	return string(summary), nil
}

// nodeIDOf strips the mission prefix a WorkID carries.
func nodeIDOf(workID, missionID string) string {
	return strings.TrimPrefix(workID, missionID+"/")
}

// harnessVerifier dispatches the acceptance verifier as a normal tool or
// agent dispatch through the mission's harness, so the dispatch gate applies
// to it as to any other component (ADR-0019 decision 12).
//
// The component ref is "kind/name". A bare name is an agent.
type harnessVerifier struct {
	harness gibsonharness.AgentHarness
	timeout time.Duration
}

func (v *harnessVerifier) Verify(ctx context.Context, component string, payload jobnode.VerifyPayload) (jobnode.Report, error) {
	kind, name := splitComponentRef(component)
	input, err := json.Marshal(payload)
	if err != nil {
		return jobnode.Report{}, fmt.Errorf("render the verify payload: %w", err)
	}
	switch kind {
	case "tool":
		resp := &toolpb.ExecuteResponse{}
		if err := v.harness.CallToolProto(ctx, name, &toolpb.ExecuteRequest{InputJson: string(input)}, resp); err != nil {
			return jobnode.Report{}, fmt.Errorf("tool %q: %w", name, err)
		}
		if e := resp.GetError(); e != nil && e.GetMessage() != "" {
			return jobnode.Report{}, fmt.Errorf("tool %q reported: %s", name, e.GetMessage())
		}
		return parseReport([]byte(resp.GetOutputJson()))
	case "agent":
		res, err := v.harness.DelegateToAgent(ctx, name, agent.Task{
			Goal:    "Judge the job and answer with {pass, score, report}: " + string(input),
			Context: map[string]any{"job_id": payload.JobID, "pass": payload.Pass},
			Timeout: v.timeout,
		})
		if err != nil {
			return jobnode.Report{}, fmt.Errorf("agent %q: %w", name, err)
		}
		out, err := json.Marshal(res.Output)
		if err != nil {
			return jobnode.Report{}, fmt.Errorf("agent %q: render its output: %w", name, err)
		}
		return parseReport(out)
	default:
		return jobnode.Report{}, fmt.Errorf("verifier %q: unknown component kind %q (want tool/<name> or agent/<name>)", component, kind)
	}
}

// splitComponentRef reads "kind/name". A bare name is an agent.
func splitComponentRef(ref string) (kind, name string) {
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return "agent", ref
}

// parseReport reads the verifier's structured answer. Anything else fails the
// pass with a clear error: a verifier that did not answer the question did
// not judge the work.
func parseReport(raw []byte) (jobnode.Report, error) {
	var probe struct {
		Pass   *bool    `json:"pass"`
		Score  *float64 `json:"score"`
		Report string   `json:"report"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return jobnode.Report{}, fmt.Errorf("the verifier's report is not JSON: %w", err)
	}
	if probe.Pass == nil || probe.Score == nil {
		return jobnode.Report{}, fmt.Errorf("the verifier's report lacks pass or score: %s", truncate(string(raw), 200))
	}
	return jobnode.Report{Pass: *probe.Pass, Score: *probe.Score, Report: probe.Report}, nil
}
