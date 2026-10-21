// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestResolveAgentLaunchSpec_ShippedClaudeManifestSubscriptionHoldsNoModelCredential
// asserts the claim of a subscription bank on the shipped claude manifest: the
// member environment holds no API key, no auth token and no route flag. The
// tenant here HOLDS an anthropic key, a header and a Bedrock key set, so the
// test fails if any of them reaches a subscription member.
func TestResolveAgentLaunchSpec_ShippedClaudeManifestSubscriptionHoldsNoModelCredential(t *testing.T) {
	entry, ok := componentcatalog.LookupAgent("claude")
	if !ok {
		t.Fatal("the claude manifest is not in the embedded catalog")
	}
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup:       func(string) (componentcatalog.AgentEntry, bool) { return entry, true },
		credentials: &stubCredentialSource{values: map[string]string{
			"acme|anthropic|api_key":             "sk-ant",
			"acme|anthropic|custom_headers":      "anthropic-workspace-id: wrkspc_test",
			"acme|bedrock|aws_access_key_id":     "AKIA",
			"acme|bedrock|aws_secret_access_key": "secret",
			"acme|bedrock|aws_region":            "us-east-1",
			"acme|foundry|foundry_api_key":       "fk",
			"acme|foundry|foundry_resource":      "res",
		}},
	}
	spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"),
		AgentLaunchRequest{AgentName: "claude", Mode: ModeMember, LoginShape: componentcatalog.LoginShapeSubscription})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for k := range spec.Env {
		if modelCredentialEnvs[k] || strings.HasPrefix(k, "CLAUDE_CODE_USE_") ||
			strings.HasPrefix(k, "AWS_") || strings.HasPrefix(k, "ANTHROPIC_") {
			t.Errorf("a subscription member holds %q in its environment", k)
		}
	}
}

// TestResolveAgentLaunchSpec_SubscriptionRefusesAStaticModelCredential: a
// manifest cannot slip a model credential past the subscription shape through
// its static env. This is the failing fixture of the final environment check.
func TestResolveAgentLaunchSpec_SubscriptionRefusesAStaticModelCredential(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"} {
		t.Run(name, func(t *testing.T) {
			entry := componentcatalog.AgentEntry{
				ID: "claude", Image: "ghcr.io/x/c@sha256:abc",
				Env: map[string]string{name: "x"},
			}
			r := &CatalogAgentResolver{
				sandboxClass: "agent",
				lookup:       func(string) (componentcatalog.AgentEntry, bool) { return entry, true },
				credentials:  &stubCredentialSource{values: map[string]string{}},
			}
			_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"),
				AgentLaunchRequest{AgentName: "claude", LoginShape: componentcatalog.LoginShapeSubscription})
			if !errors.Is(err, ErrSubscriptionShapeCredential) {
				t.Fatalf("err = %v, want ErrSubscriptionShapeCredential", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the error must name %s, got %v", name, err)
			}
		})
	}
}
