//go:build llm_integration

// Real-LLM validation for the brain Decider (gibson#851). Excluded from the
// default build; run with a live key:
//
//	ANTHROPIC_API_KEY=$(cat ~/.claude/zero-day.claude.tok) \
//	  go test -tags=llm_integration -run TestDeciderLLM ./internal/daemon/ -v
//
// It proves the Decider's prompt (buildDeciderPrompt) + structured schema
// (deciderDecision) + parser (parseDecision) produce an actionable decision when
// run against the real model — the one piece unit tests with a stub LLM cannot
// cover.
package daemon

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/llm/providers"
	gibsontypes "github.com/zeroroot-ai/gibson/internal/types"
)

const integrationModel = "claude-haiku-4-5-20251001"

func newAnthropicForTest(t *testing.T) *providers.AnthropicProvider {
	t.Helper()
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		t.Skip("ANTHROPIC_API_KEY not set")
	}
	p, err := providers.NewAnthropicProvider(llm.ProviderConfig{
		Type:         "anthropic",
		APIKey:       key,
		DefaultModel: integrationModel,
	})
	if err != nil {
		t.Fatalf("construct anthropic provider: %v", err)
	}
	return p
}

// deciderResponseFormat is the structured-output schema for deciderDecision —
// the same provider-native structured path brainExecutor.Decide uses (via the
// harness CompleteStructuredAny), which forces schema-conforming JSON.
func deciderResponseFormat() *gibsontypes.ResponseFormat {
	str := func() *gibsontypes.JSONSchema { return &gibsontypes.JSONSchema{Type: "string"} }
	return &gibsontypes.ResponseFormat{
		Type: gibsontypes.ResponseFormatJSONSchema,
		Name: "decider_decision",
		Schema: &gibsontypes.JSONSchema{
			Type: "object",
			Properties: map[string]*gibsontypes.JSONSchema{
				"action": {Type: "string", Description: "dispatch, complete, or wait"},
				"kind":   {Type: "string", Description: "agent, tool, or plugin (when dispatch)"},
				"target": str(), "input": str(), "outcome": str(), "reason": str(),
			},
			Required: []string{"action"},
		},
		Strict: true,
	}
}

// decideWithRealLLM mirrors brainExecutor.Decide: build the prompt, request
// provider-native structured output, parse.
func decideWithRealLLM(t *testing.T, p *providers.AnthropicProvider, mc brain.MissionContext) brain.DeciderOutput {
	t.Helper()
	msgs := buildDeciderPrompt(mc)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := p.CompleteStructured(ctx, llm.CompletionRequest{
		Model:          integrationModel,
		SystemPrompt:   msgs[0].Content,
		Messages:       []llm.Message{{Role: llm.RoleUser, Content: msgs[1].Content}},
		MaxTokens:      1024,
		ResponseFormat: deciderResponseFormat(),
	})
	if err != nil {
		t.Fatalf("llm structured complete: %v", err)
	}
	raw := strings.TrimSpace(resp.Message.Content)
	var d deciderDecision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("structured decision not parseable JSON: %v\n---\n%s", err, raw)
	}
	t.Logf("LLM decision: %+v", d)
	return parseDecision(&d)
}

func TestDeciderLLM_DispatchesAgentTowardGoal(t *testing.T) {
	p := newAnthropicForTest(t)
	out := decideWithRealLLM(t, p, brain.MissionContext{
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
	p := newAnthropicForTest(t)
	out := decideWithRealLLM(t, p, brain.MissionContext{
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
