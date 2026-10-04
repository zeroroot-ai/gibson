// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// gibson#485: a tool could not receive a secret at all. The only place an
// author could put one was ToolNodeConfig.input, which lives in the mission
// definition — stored, listed, rendered, validated and displayed.

func scopes() MissionSecretScopes {
	return MissionSecretScopes{
		Mission: []string{"shared-ca"},
		Tools:   []string{"tool-wide"},
		Tool:    map[string][]string{"kube-bench": {"goat-kubeconfig"}},
		Agents:  []string{"agent-wide"},
		Agent:   map[string][]string{"recon": {"shodan"}},
		Plugins: []string{"plugin-wide"},
		Plugin:  map[string][]string{"osv": {"osv-token"}},
	}
}

// The scopes UNION. "Tool-wide" means every tool sees it, so a per-tool entry
// adds rather than replaces — a declaration that silently removed access
// granted one line above would be unreadable off the file.
func TestScopesUnion(t *testing.T) {
	s := scopes()

	for _, c := range []struct {
		what string
		got  []string
		want []string
	}{
		{"named tool", s.ForTool("kube-bench"), []string{"goat-kubeconfig", "shared-ca", "tool-wide"}},
		{"unnamed tool", s.ForTool("nmap"), []string{"shared-ca", "tool-wide"}},
		{"named agent", s.ForAgent("recon"), []string{"agent-wide", "shared-ca", "shodan"}},
		{"named plugin", s.ForPlugin("osv"), []string{"osv-token", "plugin-wide", "shared-ca"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.what, c.got, c.want)
		}
	}
}

// A tool must not receive another KIND's secrets.
func TestScopesDoNotLeakAcrossKinds(t *testing.T) {
	s := scopes()
	for _, bad := range []string{"agent-wide", "shodan", "plugin-wide", "osv-token"} {
		if slices.Contains(s.ForTool("kube-bench"), bad) {
			t.Errorf("a tool was handed %q, which belongs to another kind", bad)
		}
	}
	if slices.Contains(s.ForAgent("recon"), "goat-kubeconfig") {
		t.Error("an agent was handed a tool's secret")
	}
}

// Sorted and de-duplicated, so two runs of one mission hand a tool the same
// thing in the same order rather than whatever the map iteration produced.
func TestScopesAreSortedAndDeduplicated(t *testing.T) {
	s := MissionSecretScopes{
		Mission: []string{"b", "a"},
		Tools:   []string{"a"},
		Tool:    map[string][]string{"t": {"b", "c", "a"}},
	}
	if got := s.ForTool("t"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("got %v, want a deduplicated sort [a b c]", got)
	}
}

// An empty name is dropped. It can never resolve, and carrying it would turn a
// typo in a mission file into a store failure at dispatch.
func TestScopesDropEmptyNames(t *testing.T) {
	s := MissionSecretScopes{Mission: []string{"", "  ", "real"}}
	if got := s.ForTool("t"); !slices.Equal(got, []string{"real"}) {
		t.Errorf("got %v, want only [real]", got)
	}
}

func TestDeclares(t *testing.T) {
	if (MissionSecretScopes{}).Declares() {
		t.Error("a zero declaration reported that it declares something")
	}
	if (MissionSecretScopes{Tool: map[string][]string{"t": {}}}).Declares() {
		t.Error("an empty per-name list reported that it declares something")
	}
	if !(MissionSecretScopes{Tools: []string{"x"}}).Declares() {
		t.Error("a real declaration reported that it declares nothing")
	}
}

// ── dispatch ────────────────────────────────────────────────────────────────

type stubCreds struct {
	values map[string]string
	err    error
	asked  []string
}

func (s *stubCreds) GetCredential(_ context.Context, name string) (*types.Credential, string, error) {
	s.asked = append(s.asked, name)
	if s.err != nil {
		// Deliberately returns whatever it holds ALONGSIDE the error, so the
		// error check is tested independently of the empty-value check.
		return nil, s.values[name], s.err
	}
	v, ok := s.values[name]
	if !ok {
		return nil, "", errors.New("no such secret")
	}
	return nil, v, nil
}

func harnessWithSecrets(s MissionSecretScopes, creds CredentialStore) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		missionCtx:     MissionContext{Secrets: s},
		missionSecrets: creds,
		logger:         slog.New(slog.DiscardHandler),
	}
}

// The whole point: a tool receives the value, and the mission never carried it.
func TestAddDeclaredSecrets_HandsTheToolItsSecrets(t *testing.T) {
	creds := &stubCreds{values: map[string]string{
		"shared-ca":       "CA-PEM",
		"tool-wide":       "TW",
		"goat-kubeconfig": "KUBECONFIG",
	}}
	h := harnessWithSecrets(scopes(), creds)

	spec := sandboxed.ToolSpec{Env: map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}}
	if err := h.addDeclaredSecrets(context.Background(), "kube-bench", &spec); err != nil {
		t.Fatalf("addDeclaredSecrets: %v", err)
	}

	for k, want := range map[string]string{
		"GIBSON_SECRET_SHARED_CA":       "CA-PEM",
		"GIBSON_SECRET_TOOL_WIDE":       "TW",
		"GIBSON_SECRET_GOAT_KUBECONFIG": "KUBECONFIG",
		"GIBSON_TOOL_NAME":              "kube-bench",
	} {
		if got := spec.Env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// Nothing from another kind was even asked for.
	for _, bad := range []string{"agent-wide", "shodan", "plugin-wide", "osv-token"} {
		if slices.Contains(creds.asked, bad) {
			t.Errorf("the store was asked for %q, which belongs to another kind", bad)
		}
	}
}

// A mission that declares nothing dispatches exactly as before, and the store
// is not consulted at all.
func TestAddDeclaredSecrets_NoDeclarationIsANoOp(t *testing.T) {
	creds := &stubCreds{}
	h := harnessWithSecrets(MissionSecretScopes{}, creds)

	spec := sandboxed.ToolSpec{}
	if err := h.addDeclaredSecrets(context.Background(), "nmap", &spec); err != nil {
		t.Fatalf("a mission with no declaration failed to dispatch: %v", err)
	}
	if len(spec.Env) != 0 || len(creds.asked) != 0 {
		t.Errorf("env=%v asked=%v; both must be empty", spec.Env, creds.asked)
	}
}

// EVERY failure refuses the dispatch. A tool promised a credential that
// silently ran without one does not fail — it authenticates to nothing, finds
// nothing, and reports a clean result for a scan that never happened.
func TestAddDeclaredSecrets_EveryFailureRefusesTheDispatch(t *testing.T) {
	declared := MissionSecretScopes{Tool: map[string][]string{"kube-bench": {"goat-kubeconfig"}}}

	cases := map[string]*DefaultAgentHarness{
		"no store wired": harnessWithSecrets(declared, nil),
		"store errors": harnessWithSecrets(declared,
			&stubCreds{err: errors.New("openbao is sealed")}),
		"secret is absent": harnessWithSecrets(declared,
			&stubCreds{values: map[string]string{}}),
		"secret resolves empty": harnessWithSecrets(declared,
			&stubCreds{values: map[string]string{"goat-kubeconfig": ""}}),

		// A store that returns an error AND a value. No real store should, but
		// this is the only case where the error check and the empty-value check
		// differ, so it is the one that proves the error check carries its own
		// weight: without it a tool would be handed data from a failed read.
		"store errors but also answers": harnessWithSecrets(declared,
			&stubCreds{err: errors.New("openbao is sealed"),
				values: map[string]string{"goat-kubeconfig": "STALE"}}),
	}

	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			spec := sandboxed.ToolSpec{}
			err := h.addDeclaredSecrets(context.Background(), "kube-bench", &spec)
			if err == nil {
				t.Fatal("dispatch was allowed without a declared secret")
			}
			if !strings.Contains(err.Error(), "goat-kubeconfig") && !strings.Contains(err.Error(), "secret(s)") {
				t.Errorf("the refusal does not say which secret: %v", err)
			}
			if _, leaked := spec.Env["GIBSON_SECRET_GOAT_KUBECONFIG"]; leaked {
				t.Error("a failed resolution still put something in the environment")
			}
		})
	}
}

// Two names that map to one env key are refused rather than letting one win. A
// tool handed the wrong credential under the right name is worse than a
// refusal.
func TestAddDeclaredSecrets_RefusesAnEnvKeyCollision(t *testing.T) {
	h := harnessWithSecrets(
		MissionSecretScopes{Tools: []string{"a-b", "a.b"}},
		&stubCreds{values: map[string]string{"a-b": "1", "a.b": "2"}},
	)

	err := h.addDeclaredSecrets(context.Background(), "kube-bench", &sandboxed.ToolSpec{})
	if err == nil {
		t.Fatal("a collision was accepted; one secret silently won")
	}
	if !strings.Contains(err.Error(), "GIBSON_SECRET_A_B") {
		t.Errorf("the refusal does not name the colliding key: %v", err)
	}
}

// A secret's VALUE must never appear in an error, which is logged.
func TestAddDeclaredSecrets_ARefusalNeverCarriesTheValue(t *testing.T) {
	const secret = "s3cr3t-kubeconfig-bytes"
	h := harnessWithSecrets(
		MissionSecretScopes{Tools: []string{"a-b", "a.b"}},
		&stubCreds{values: map[string]string{"a-b": secret, "a.b": secret}},
	)

	err := h.addDeclaredSecrets(context.Background(), "kube-bench", &sandboxed.ToolSpec{})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal leaks the secret value: %v", err)
	}
}

func TestSecretEnvKey(t *testing.T) {
	for in, want := range map[string]string{
		"goat-kubeconfig":  "GIBSON_SECRET_GOAT_KUBECONFIG",
		"cred:openai-prod": "GIBSON_SECRET_CRED_OPENAI_PROD",
		"already_fine":     "GIBSON_SECRET_ALREADY_FINE",
		"weird name!@#":    "GIBSON_SECRET_WEIRD_NAME___",
		"UPPER":            "GIBSON_SECRET_UPPER",
		"digits123":        "GIBSON_SECRET_DIGITS123",
	} {
		if got := secretEnvKey(in); got != want {
			t.Errorf("secretEnvKey(%q) = %q, want %q", in, got, want)
		}
	}
}
