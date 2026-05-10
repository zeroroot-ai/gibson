// Tests for the dispatch policy gate. Each row in the matrix below is a
// terminal state from design §"Dispatch policy state diagram"; missing or
// extra rows MUST be a build break (every transition has a corresponding
// code branch and a corresponding test).
//
// Spec: setec-sandbox-prod-default §C3 (R3.1, R3.3).
package dispatch

import (
	"context"
	"testing"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

// shortcuts for readability
const (
	modeUnspec    = componentpb.DispatchMode_DISPATCH_MODE_UNSPECIFIED
	modeSandboxed = componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED
	modePlugin    = componentpb.DispatchMode_DISPATCH_MODE_PLUGIN
	modeAgent     = componentpb.DispatchMode_DISPATCH_MODE_AGENT

	trustUnspec    = componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED
	trustTrusted   = componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
	trustUntrusted = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
)

func TestPolicy_Decide_StateDiagram(t *testing.T) {
	cases := []struct {
		name           string
		mode           componentpb.DispatchMode
		trust          componentpb.ContentTrust
		sandboxHealthy bool
		overrideActive bool
		strict         bool // Config.StrictDefaultUntrusted

		wantAllowed bool
		wantReason  string
	}{
		// 1. UNSPECIFIED dispatch mode is the highest-priority deny.
		{
			name:        "DenyUnknownMode (UNSPECIFIED + TRUSTED)",
			mode:        modeUnspec,
			trust:       trustTrusted,
			wantAllowed: false,
			wantReason:  ReasonDispatchModeUnspecified,
		},
		{
			name:        "DenyUnknownMode (UNSPECIFIED + UNTRUSTED + override)",
			mode:        modeUnspec,
			trust:       trustUntrusted,
			overrideActive: true,
			wantAllowed: false,
			wantReason:  ReasonDispatchModeUnspecified,
		},

		// 2a. Override flips UNTRUSTED+PLUGIN/AGENT to allow.
		{
			name:           "Allowed via override (UNTRUSTED + PLUGIN)",
			mode:           modePlugin,
			trust:          trustUntrusted,
			overrideActive: true,
			wantAllowed:    true,
		},
		{
			name:           "Allowed via override (UNTRUSTED + AGENT)",
			mode:           modeAgent,
			trust:          trustUntrusted,
			overrideActive: true,
			wantAllowed:    true,
		},
		{
			name:           "Allowed via override (UNTRUSTED + SANDBOXED, sandbox healthy redundant)",
			mode:           modeSandboxed,
			trust:          trustUntrusted,
			sandboxHealthy: true,
			overrideActive: true,
			wantAllowed:    true,
		},

		// 2b. UNTRUSTED + SANDBOXED depends on sandbox health.
		{
			name:           "Allowed (UNTRUSTED + SANDBOXED, healthy)",
			mode:           modeSandboxed,
			trust:          trustUntrusted,
			sandboxHealthy: true,
			wantAllowed:    true,
		},
		{
			name:           "DenySandboxUnavailable (UNTRUSTED + SANDBOXED, unhealthy)",
			mode:           modeSandboxed,
			trust:          trustUntrusted,
			sandboxHealthy: false,
			wantAllowed:    false,
			wantReason:     ReasonSandboxUnavailable,
		},

		// 2c. UNTRUSTED + PLUGIN/AGENT (no override) is the canonical deny.
		{
			name:        "DenyUntrustedNotSandboxed (UNTRUSTED + PLUGIN, no override)",
			mode:        modePlugin,
			trust:       trustUntrusted,
			wantAllowed: false,
			wantReason:  ReasonUntrustedRequiresSandbox,
		},
		{
			name:        "DenyUntrustedNotSandboxed (UNTRUSTED + AGENT, no override)",
			mode:        modeAgent,
			trust:       trustUntrusted,
			wantAllowed: false,
			wantReason:  ReasonUntrustedRequiresSandbox,
		},

		// 3. TRUSTED runs in any explicit mode.
		{
			name:        "Allowed (TRUSTED + SANDBOXED, healthy ignored)",
			mode:        modeSandboxed,
			trust:       trustTrusted,
			wantAllowed: true,
		},
		{
			name:        "Allowed (TRUSTED + PLUGIN)",
			mode:        modePlugin,
			trust:       trustTrusted,
			wantAllowed: true,
		},
		{
			name:        "Allowed (TRUSTED + AGENT)",
			mode:        modeAgent,
			trust:       trustTrusted,
			wantAllowed: true,
		},

		// 4. UNSPECIFIED ContentTrust + relaxed default = TRUSTED treatment.
		{
			name:        "UNSPECIFIED trust acts as TRUSTED by default (PLUGIN allowed)",
			mode:        modePlugin,
			trust:       trustUnspec,
			wantAllowed: true,
		},
		{
			name:           "UNSPECIFIED trust acts as TRUSTED by default (SANDBOXED allowed even if !healthy)",
			mode:           modeSandboxed,
			trust:          trustUnspec,
			sandboxHealthy: false,
			wantAllowed:    true, // relaxed default: TRUSTED ignores SandboxHealthy
		},

		// 5. UNSPECIFIED ContentTrust + strict default = UNTRUSTED treatment.
		{
			name:        "UNSPECIFIED trust acts as UNTRUSTED under strict (PLUGIN denied)",
			mode:        modePlugin,
			trust:       trustUnspec,
			strict:      true,
			wantAllowed: false,
			wantReason:  ReasonUntrustedRequiresSandbox,
		},
		{
			name:           "UNSPECIFIED trust acts as UNTRUSTED under strict (SANDBOXED + healthy allowed)",
			mode:           modeSandboxed,
			trust:          trustUnspec,
			sandboxHealthy: true,
			strict:         true,
			wantAllowed:    true,
		},
		{
			name:           "UNSPECIFIED trust acts as UNTRUSTED under strict (SANDBOXED + !healthy denied)",
			mode:           modeSandboxed,
			trust:          trustUnspec,
			sandboxHealthy: false,
			strict:         true,
			wantAllowed:    false,
			wantReason:     ReasonSandboxUnavailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPolicy(Config{StrictDefaultUntrusted: tc.strict})
			got := p.Decide(context.Background(), Input{
				Tenant:         "t1",
				Mission:        "m1",
				Step:           "s1",
				Tool:           "tool1",
				ToolMode:       tc.mode,
				ContentTrust:   tc.trust,
				SandboxHealthy: tc.sandboxHealthy,
				OverrideActive: tc.overrideActive,
			})
			if got.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (Reason=%q)", got.Allowed, tc.wantAllowed, got.Reason)
			}
			if !tc.wantAllowed && got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if tc.wantAllowed && got.Reason != "" {
				t.Errorf("Allowed should have empty Reason, got %q", got.Reason)
			}
			// ChosenMode mirrors the input mode in every terminal except when
			// the gate refuses to guess (UNSPECIFIED) — there it preserves
			// the input value too (UNSPECIFIED).
			if got.ChosenMode != tc.mode {
				t.Errorf("ChosenMode = %v, want %v", got.ChosenMode, tc.mode)
			}
		})
	}
}

// TestPolicy_Decide_Determinism verifies the gate is a pure function:
// repeated calls with the same input return the same output.
func TestPolicy_Decide_Determinism(t *testing.T) {
	p := NewPolicy(Config{})
	in := Input{
		Tenant:         "t",
		ToolMode:       modeSandboxed,
		ContentTrust:   trustUntrusted,
		SandboxHealthy: true,
	}
	first := p.Decide(context.Background(), in)
	for i := 0; i < 100; i++ {
		got := p.Decide(context.Background(), in)
		if got != first {
			t.Fatalf("non-deterministic Decide on iteration %d: %+v != %+v", i, got, first)
		}
	}
}
