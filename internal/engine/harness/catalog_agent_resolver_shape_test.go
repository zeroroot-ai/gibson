// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// shapedEntry mirrors the shipped claude manifest: one block per login shape,
// plus one unshaped block that every shape needs.
func shapedEntry() componentcatalog.AgentEntry {
	return componentcatalog.AgentEntry{
		ID:    "claude",
		Image: "ghcr.io/zeroroot-ai/zerocool-claude-agent@sha256:abc",
		Credentials: []componentcatalog.CredentialRequirement{
			{Shape: componentcatalog.LoginShapeAPIKey, Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Key: "api_key"},
			{Shape: componentcatalog.LoginShapeBedrock, Provider: "bedrock", Envs: []componentcatalog.CredentialEnv{
				{Key: "aws_access_key_id", Env: "AWS_ACCESS_KEY_ID"},
				{Key: "aws_secret_access_key", Env: "AWS_SECRET_ACCESS_KEY"},
				{Key: "aws_session_token", Env: "AWS_SESSION_TOKEN", Optional: true},
				{Key: "aws_region", Env: "AWS_REGION"},
			}},
			{Shape: componentcatalog.LoginShapeVertex, Provider: "vertex", Envs: []componentcatalog.CredentialEnv{
				{Key: "google_application_credentials_json", Env: "GOOGLE_APPLICATION_CREDENTIALS_JSON"},
				{Key: "vertex_region", Env: "CLOUD_ML_REGION"},
				{Key: "vertex_project_id", Env: "ANTHROPIC_VERTEX_PROJECT_ID"},
			}},
			{Shape: componentcatalog.LoginShapeFoundry, Provider: "foundry", Envs: []componentcatalog.CredentialEnv{
				{Key: "foundry_api_key", Env: "ANTHROPIC_FOUNDRY_API_KEY"},
				{Key: "foundry_resource", Env: "ANTHROPIC_FOUNDRY_RESOURCE"},
			}},
			{Provider: "github", Env: "GITHUB_TOKEN", Key: "api_key"},
		},
	}
}

func shapedResolver(t *testing.T, values map[string]string) *CatalogAgentResolver {
	t.Helper()
	entry := shapedEntry()
	return &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup:       func(id string) (componentcatalog.AgentEntry, bool) { return entry, id == "claude" },
		credentials:  &stubCredentialSource{values: values},
	}
}

func envKeys(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k := range env {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestResolveAgentLaunchSpec_ByLoginShape: each shape injects exactly its own
// block, its route flag and the unshaped block — and nothing else.
func TestResolveAgentLaunchSpec_ByLoginShape(t *testing.T) {
	values := map[string]string{
		"acme|anthropic|api_key":                          "sk-ant",
		"acme|github|api_key":                             "ghp-1",
		"acme|bedrock|aws_access_key_id":                  "AKIA",
		"acme|bedrock|aws_secret_access_key":              "secret",
		"acme|bedrock|aws_region":                         "us-east-1",
		"acme|vertex|google_application_credentials_json": `{"type":"service_account"}`,
		"acme|vertex|vertex_region":                       "us-east5",
		"acme|vertex|vertex_project_id":                   "proj",
		"acme|foundry|foundry_api_key":                    "fk",
		"acme|foundry|foundry_resource":                   "res",
	}
	cases := []struct {
		shape string
		want  []string
	}{
		{componentcatalog.LoginShapeAPIKey, []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}},
		{"", []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}},
		{componentcatalog.LoginShapeBedrock, []string{
			"AWS_ACCESS_KEY_ID", "AWS_REGION", "AWS_SECRET_ACCESS_KEY",
			"CLAUDE_CODE_USE_BEDROCK", "GITHUB_TOKEN"}},
		{componentcatalog.LoginShapeVertex, []string{
			"ANTHROPIC_VERTEX_PROJECT_ID", "CLAUDE_CODE_USE_VERTEX", "CLOUD_ML_REGION",
			"GITHUB_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS_JSON"}},
		{componentcatalog.LoginShapeFoundry, []string{
			"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_RESOURCE",
			"CLAUDE_CODE_USE_FOUNDRY", "GITHUB_TOKEN"}},
		{componentcatalog.LoginShapeSubscription, []string{"GITHUB_TOKEN"}},
	}
	for _, tc := range cases {
		name := tc.shape
		if name == "" {
			name = "unset defaults to api_key"
		}
		t.Run(name, func(t *testing.T) {
			r := shapedResolver(t, values)
			spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude", LoginShape: tc.shape})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got := envKeys(spec.Env); !equalStrings(got, tc.want) {
				t.Fatalf("env = %v, want exactly %v", got, tc.want)
			}
		})
	}
}

// TestResolveAgentLaunchSpec_SubscriptionSetsNoAnthropicVariable: an API key
// beats the person's own sign-in in -p mode, so the subscription shape must
// yield no Anthropic variable at all.
func TestResolveAgentLaunchSpec_SubscriptionSetsNoAnthropicVariable(t *testing.T) {
	r := shapedResolver(t, map[string]string{"acme|github|api_key": "ghp-1"})
	spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude", LoginShape: componentcatalog.LoginShapeSubscription})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for k := range spec.Env {
		if k == "ANTHROPIC_API_KEY" || k == "ANTHROPIC_AUTH_TOKEN" || k == "CLAUDE_CODE_USE_BEDROCK" {
			t.Fatalf("subscription must set no model credential; got %q", k)
		}
	}
}

// TestResolveAgentLaunchSpec_SubscriptionRefusesAnUnshapedModelCredential: a
// manifest cannot slip a key past the subscription shape by leaving the block
// unshaped.
func TestResolveAgentLaunchSpec_SubscriptionRefusesAnUnshapedModelCredential(t *testing.T) {
	entry := componentcatalog.AgentEntry{
		ID: "claude", Image: "ghcr.io/x/c@sha256:abc",
		Credentials: []componentcatalog.CredentialRequirement{
			{Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Key: "api_key"},
		},
	}
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup:       func(string) (componentcatalog.AgentEntry, bool) { return entry, true },
		credentials:  &stubCredentialSource{values: map[string]string{"acme|anthropic|api_key": "sk"}},
	}
	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude", LoginShape: componentcatalog.LoginShapeSubscription})
	if !errors.Is(err, ErrSubscriptionShapeCredential) {
		t.Fatalf("err = %v, want ErrSubscriptionShapeCredential", err)
	}
}

// TestResolveAgentLaunchSpec_UnknownLoginShape: a launch naming a shape the
// platform does not have is refused before anything is resolved.
func TestResolveAgentLaunchSpec_UnknownLoginShape(t *testing.T) {
	r := shapedResolver(t, map[string]string{})
	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude", LoginShape: "oauth"})
	if !errors.Is(err, ErrUnknownLoginShape) {
		t.Fatalf("err = %v, want ErrUnknownLoginShape", err)
	}
}

// TestResolveAgentLaunchSpec_RequiredShapeFieldMissing: a required field of the
// chosen shape refuses the launch, while the optional session token does not.
func TestResolveAgentLaunchSpec_RequiredShapeFieldMissing(t *testing.T) {
	r := shapedResolver(t, map[string]string{
		"acme|github|api_key":                "ghp-1",
		"acme|bedrock|aws_access_key_id":     "AKIA",
		"acme|bedrock|aws_secret_access_key": "secret",
		// aws_region absent, aws_session_token absent
	})
	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude", LoginShape: componentcatalog.LoginShapeBedrock})
	if !errors.Is(err, ErrTenantCredentialMissing) {
		t.Fatalf("err = %v, want ErrTenantCredentialMissing for the absent region", err)
	}
}

// TestResolveAgentLaunchSpec_ByInstanceMode: one image carries both shapes, so
// the mode selects the command and the launcher tells the process which it is.
func TestResolveAgentLaunchSpec_ByInstanceMode(t *testing.T) {
	entry := componentcatalog.AgentEntry{
		ID: "claude", Image: "ghcr.io/x/c@sha256:abc",
		Command:       []string{"node", "/app/dist/sandbox.js"},
		MemberCommand: []string{"node", "/app/dist/member-main.js"},
	}
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup:       func(string) (componentcatalog.AgentEntry, bool) { return entry, true },
	}
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	for name, tc := range map[string]struct {
		mode string
		want []string
	}{
		"unset defaults to one-shot": {"", entry.Command},
		"one-shot":                   {ModeOneShot, entry.Command},
		"member":                     {ModeMember, entry.MemberCommand},
	} {
		t.Run(name, func(t *testing.T) {
			spec, err := r.ResolveAgentLaunchSpec(ctx, AgentLaunchRequest{AgentName: "claude", Mode: tc.mode})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(spec.Command) != len(tc.want) || spec.Command[1] != tc.want[1] {
				t.Fatalf("command = %v, want %v", spec.Command, tc.want)
			}
			if spec.Mode != tc.mode {
				t.Errorf("mode = %q, want %q; the launcher injects it", spec.Mode, tc.mode)
			}
		})
	}
}

// TestResolveAgentLaunchSpec_MemberModeNeedsAMemberCommand: an agent with no
// member driver is refused by name rather than launched as a one-shot that
// would exit at once.
func TestResolveAgentLaunchSpec_MemberModeNeedsAMemberCommand(t *testing.T) {
	entry := componentcatalog.AgentEntry{
		ID: "zerocool", Image: "ghcr.io/x/z@sha256:abc",
		Command: []string{"node", "/app/dist/serve-agent.js"},
	}
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup:       func(string) (componentcatalog.AgentEntry, bool) { return entry, true },
	}
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := r.ResolveAgentLaunchSpec(ctx, AgentLaunchRequest{AgentName: "zerocool", Mode: ModeMember})
	if !errors.Is(err, ErrNoMemberCommand) {
		t.Fatalf("err = %v, want ErrNoMemberCommand", err)
	}
}

// TestResolveAgentLaunchSpec_UnknownInstanceMode asserts that a mode the
// manifest does not name is refused rather than mapped to a default.
func TestResolveAgentLaunchSpec_UnknownInstanceMode(t *testing.T) {
	r := shapedResolver(t, map[string]string{})
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := r.ResolveAgentLaunchSpec(ctx, AgentLaunchRequest{AgentName: "claude", Mode: "daemon"})
	if !errors.Is(err, ErrUnknownInstanceMode) {
		t.Fatalf("err = %v, want ErrUnknownInstanceMode", err)
	}
}

func TestIsInstanceMode(t *testing.T) {
	for _, m := range []string{"", ModeOneShot, ModeMember} {
		if !IsInstanceMode(m) {
			t.Errorf("%q must be an instance mode", m)
		}
	}
	if IsInstanceMode("daemon") {
		t.Error("daemon is not an instance mode")
	}
}
