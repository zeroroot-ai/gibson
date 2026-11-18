//go:build llm_integration

// Real-model validation for the brain Decider (gibson#851). Excluded from the
// default build. Run it against a live model gateway:
//
//	GIBSON_LIVE_GATEWAY_URL=https://gateway.example \
//	GIBSON_LIVE_GATEWAY_GRANT=<daemon call grant> \
//	GIBSON_LIVE_PROVIDER=claude GIBSON_LIVE_MODEL=claude-haiku-4-5 \
//	  go test -tags=llm_integration -run TestDeciderLLM ./internal/server/daemon/ -v
//
// It proves that the prompt of the Decider (buildDeciderPrompt), the structured
// schema (deciderDecision) and the parser (parseDecision) give an actionable
// decision from a real model. A unit test with a stub model cannot show this.
// The call goes through the same modelclient that brainExecutor.Decide uses.
package daemon

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
)

// staticGrant is a grant source that gives one fixed token.
type staticGrant string

func (g staticGrant) Grant(context.Context, modelclient.Caller) (string, error) {
	return string(g), nil
}

// liveEnv returns the value of a required environment variable. The test fails
// when it is not set, because a skipped live test proves nothing.
func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: this test needs a live model gateway", name)
	}
	return v
}

// decideWithRealLLM mirrors brainExecutor.Decide: build the prompt, ask for
// structured output through the gateway client, parse the decision.
func decideWithRealLLM(t *testing.T, mc brain.MissionContext) brain.DeciderOutput {
	t.Helper()
	client, err := modelclient.New(modelclient.Config{
		BaseURL: liveEnv(t, "GIBSON_LIVE_GATEWAY_URL"),
		Grants:  staticGrant(liveEnv(t, "GIBSON_LIVE_GATEWAY_GRANT")),
	})
	if err != nil {
		t.Fatalf("construct the model client: %v", err)
	}
	target := modelclient.Target{
		Tenant: "live", Provider: liveEnv(t, "GIBSON_LIVE_PROVIDER"), Model: liveEnv(t, "GIBSON_LIVE_MODEL"),
	}
	name, schema, err := gibsonharness.StructuredSchema(deciderDecision{})
	if err != nil {
		t.Fatalf("schema of the decision: %v", err)
	}
	msgs := buildDeciderPrompt(mc)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := client.Respond(ctx,
		modelclient.Caller{Tenant: "live", Mission: mc.MissionID, Task: "decide-live", Purpose: "brain-decider"},
		target,
		modelclient.Request{
			MaxOutputTokens: 1024,
			Input:           deciderInput(msgs),
			Text:            modelclient.JSONSchemaFormat(name, schema),
		})
	if err != nil {
		t.Fatalf("structured call of the gateway: %v", err)
	}
	var d deciderDecision
	if err := json.Unmarshal([]byte(resp.OutputText()), &d); err != nil {
		t.Fatalf("structured decision is not JSON: %v\n---\n%s", err, resp.OutputText())
	}
	t.Logf("LLM decision: %+v", d)
	return parseDecision(&d)
}

func TestDeciderLLM_DispatchesAgentTowardGoal(t *testing.T) {
	out := decideWithRealLLM(t, brain.MissionContext{
		MissionID: "m1",
		Goal:      "Get a shell on the web host 10.0.0.5 (it runs OpenSSH 8.9 on 22 and nginx on 80).",
		Work: []brain.WorkSnapshot{
			{ID: "recon", Kind: "tool", Target: "nmap", State: brain.WorkDone, Result: "10.0.0.5: 22/ssh OpenSSH 8.9, 80/http nginx"},
		},
		Hosts:        []brain.HostSnapshot{{Address: "10.0.0.5", OpenPorts: []int{22, 80}}},
		Capabilities: []brain.Capability{{Kind: "agent", Name: "exploit-agent", Description: "attempts to exploit a host to gain a shell"}},
	})
	if len(out.Dispatches) == 0 {
		t.Fatalf("expected the Decider to dispatch toward the goal, got %+v", out)
	}
	if out.Dispatches[0].Target != "exploit-agent" {
		t.Errorf("expected dispatch of the enrolled exploit-agent, got %q", out.Dispatches[0].Target)
	}
}

func TestDeciderLLM_CompletesWhenGoalMet(t *testing.T) {
	out := decideWithRealLLM(t, brain.MissionContext{
		MissionID: "m1",
		Goal:      "Get a shell on 10.0.0.5.",
		Work: []brain.WorkSnapshot{
			{ID: "x", Kind: "agent", Target: "exploit-agent", State: brain.WorkDone, Result: "SUCCESS: obtained root shell on 10.0.0.5 via CVE-2024-1234"},
		},
		Capabilities: []brain.Capability{{Kind: "agent", Name: "exploit-agent", Description: "exploit a host"}},
	})
	if out.Complete == nil {
		t.Fatalf("expected the Decider to complete when the goal is met, got %+v", out)
	}
	t.Logf("completed: outcome=%s reason=%s", out.Complete.Outcome, out.Complete.Reason)
}
