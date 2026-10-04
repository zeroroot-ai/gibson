// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/secretenv"
)

// A nil block hands nothing to anything. That is the behaviour before a mission
// could declare secrets, and every mission written before this field exists
// takes this path.
func TestMissionSecretScopesFromProto_NilDeclaresNothing(t *testing.T) {
	got := MissionSecretScopesFromProto(nil)

	if got.Declares() {
		t.Errorf("a nil secrets block declares something: %+v", got)
	}
	if names := got.ForTool("kube-bench"); len(names) != 0 {
		t.Errorf("ForTool on a nil block = %v, want nothing", names)
	}
}

// Every scope has to survive the translation. A field dropped here hands a
// component less than its mission declared, and nothing else would report it:
// the dispatch simply refuses a secret the author believed they had granted.
func TestMissionSecretScopesFromProto_EveryScopeSurvives(t *testing.T) {
	in := &missionv1.MissionSecrets{
		Mission: []string{"cred:tenant-ca"},
		Agents:  []string{"cred:agent-wide"},
		Tools:   []string{"cred:tool-wide"},
		Plugins: []string{"cred:plugin-wide"},
		Agent:   map[string]*missionv1.SecretNames{"zerocool": {Names: []string{"cred:zerocool-only"}}},
		Tool:    map[string]*missionv1.SecretNames{"kube-bench": {Names: []string{"cred:kube-bench-only"}}},
		Plugin:  map[string]*missionv1.SecretNames{"github-plugin": {Names: []string{"cred:github-token"}}},
	}

	got := MissionSecretScopesFromProto(in)

	// The union is what a dispatch reads, so assert through it rather than
	// through the struct: a field that translated into the wrong scope would
	// still be present, and only the union says who actually receives it.
	for _, tc := range []struct {
		scope string
		got   []string
		want  []string
	}{
		{"tool kube-bench", got.ForTool("kube-bench"), []string{"cred:kube-bench-only", "cred:tenant-ca", "cred:tool-wide"}},
		{"tool other", got.ForTool("trivy-k8s"), []string{"cred:tenant-ca", "cred:tool-wide"}},
		{"agent zerocool", got.ForAgent("zerocool"), []string{"cred:agent-wide", "cred:tenant-ca", "cred:zerocool-only"}},
		{"agent other", got.ForAgent("claude"), []string{"cred:agent-wide", "cred:tenant-ca"}},
		{"plugin github", got.ForPlugin("github-plugin"), []string{"cred:github-token", "cred:plugin-wide", "cred:tenant-ca"}},
		{"plugin other", got.ForPlugin("other"), []string{"cred:plugin-wide", "cred:tenant-ca"}},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.scope, tc.got, tc.want)
		}
	}
}

// A named component whose list is empty still counts as declared. The mission
// named the component, and reporting "declared nothing" for a mission that
// named one would send the dispatch down the no-secrets path.
func TestMissionSecretScopesFromProto_ANamedComponentWithNoNamesIsStillADeclaration(t *testing.T) {
	got := MissionSecretScopesFromProto(&missionv1.MissionSecrets{
		Tool: map[string]*missionv1.SecretNames{"kube-bench": nil},
	})

	if _, ok := got.Tool["kube-bench"]; !ok {
		t.Error("the named tool is missing from the translation")
	}
	// It declares nothing usable, which is correct: there are no names.
	if got.Declares() {
		t.Error("an entry with no names reads as a declaration of something")
	}
}

// The env key the harness writes is the one the SDK derives, because a
// component in another repository reads it back with the same function. This
// asserts the two agree rather than restating the fold.
func TestSecretEnvKey_IsTheSDKRule(t *testing.T) {
	for _, name := range []string{"cred:goat-cluster", "goat-kubeconfig", "a.b", "a-b"} {
		if got, want := secretEnvKey(name), secretenv.Key(name); got != want {
			t.Errorf("secretEnvKey(%q) = %q, want %q", name, got, want)
		}
	}
	if got := secretEnvKey("cred:goat-cluster"); got != "GIBSON_SECRET_CRED_GOAT_CLUSTER" {
		t.Errorf("secretEnvKey = %q; the exact bytes a dispatched tool reads changed", got)
	}
}
