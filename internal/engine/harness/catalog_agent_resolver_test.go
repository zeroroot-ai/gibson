// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestCatalogAgentResolver_KnownAgent proves the resolver returns the manifest's
// image, the configured sandbox class, the egress ceiling built from egressAllow
// and the manifest model for an agent that is in the catalog.
func TestCatalogAgentResolver_KnownAgent(t *testing.T) {
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup: func(id string) (componentcatalog.AgentEntry, bool) {
			if id != "zerocool" {
				return componentcatalog.AgentEntry{}, false
			}
			return componentcatalog.AgentEntry{
				ID:          "zerocool",
				Image:       "ghcr.io/zeroroot-ai/zerocool@sha256:abc",
				Model:       "sonnet",
				EgressAllow: []string{"api.anthropic.com:443"},
			}, true
		},
	}
	spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "tenant-acme"), AgentLaunchRequest{AgentName: "zerocool"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if spec.Image != "ghcr.io/zeroroot-ai/zerocool@sha256:abc" {
		t.Errorf("image = %q", spec.Image)
	}
	if spec.SandboxClass != "agent" {
		t.Errorf("sandbox class = %q, want agent", spec.SandboxClass)
	}
	if spec.Model != "sonnet" {
		t.Errorf("model = %q", spec.Model)
	}
	if len(spec.Egress) != 1 || spec.Egress[0].Host != "api.anthropic.com" || spec.Egress[0].Port != 443 {
		t.Errorf("egress = %+v", spec.Egress)
	}
}

// TestCatalogAgentResolver_UnknownAgent proves an agent with no manifest is a
// clear error, so the harness denies the sandboxed dispatch fail-closed.
func TestCatalogAgentResolver_UnknownAgent(t *testing.T) {
	r := &CatalogAgentResolver{
		sandboxClass: "agent",
		lookup: func(string) (componentcatalog.AgentEntry, bool) {
			return componentcatalog.AgentEntry{}, false
		},
	}
	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "tenant-acme"), AgentLaunchRequest{AgentName: "ghost"})
	if !errors.Is(err, ErrAgentNotInCatalog) {
		t.Fatalf("want ErrAgentNotInCatalog, got %v", err)
	}
}

// TestNewCatalogAgentResolver_DefaultsClass proves an empty configured class
// defaults to "agent" so a launch never inherits the cluster-default isolation
// posture (ADR-0052).
func TestNewCatalogAgentResolver_DefaultsClass(t *testing.T) {
	if got := NewCatalogAgentResolver("", nil).sandboxClass; got != defaultCatalogAgentSandboxClass {
		t.Errorf("default class = %q, want %q", got, defaultCatalogAgentSandboxClass)
	}
	if got := NewCatalogAgentResolver("gvisor-strict", nil).sandboxClass; got != "gvisor-strict" {
		t.Errorf("configured class = %q, want gvisor-strict", got)
	}
}

type stubCredentialSource struct {
	values map[string]string // key: tenant|provider|key
	err    error
	calls  []string
}

func (s *stubCredentialSource) ResolveProviderCredential(_ context.Context, tenant, provider, key string) (string, error) {
	s.calls = append(s.calls, tenant+"|"+provider+"|"+key)
	if s.err != nil {
		return "", s.err
	}
	return s.values[tenant+"|"+provider+"|"+key], nil
}

// TestCatalogAgentResolver_TenantCredentials: a manifest that declares a
// credential gets the DISPATCHING tenant's own provider key injected into the
// launch env (gibson#1621 decision 12), and a tenant without that provider is
// refused before launch.
func TestCatalogAgentResolver_TenantCredentials(t *testing.T) {
	entry := componentcatalog.AgentEntry{
		ID:    "claude",
		Image: "ghcr.io/zeroroot-ai/zerocool-claude-agent@sha256:abc",
		Credentials: []componentcatalog.CredentialRequirement{
			{Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Key: "api_key"},
		},
	}
	lookup := func(id string) (componentcatalog.AgentEntry, bool) { return entry, id == "claude" }

	t.Run("injects the tenant's key", func(t *testing.T) {
		src := &stubCredentialSource{values: map[string]string{"acme|anthropic|api_key": "sk-ant-acme"}}
		r := &CatalogAgentResolver{sandboxClass: "agent", lookup: lookup, credentials: src}
		spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude"})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if spec.Env["ANTHROPIC_API_KEY"] != "sk-ant-acme" {
			t.Fatalf("env = %+v, want the tenant's key under ANTHROPIC_API_KEY", spec.Env)
		}
		if len(src.calls) != 1 || src.calls[0] != "acme|anthropic|api_key" {
			t.Fatalf("calls = %v, want one lookup for the dispatching tenant", src.calls)
		}
	})

	t.Run("a tenant without the provider is refused, not launched with an empty key", func(t *testing.T) {
		src := &stubCredentialSource{err: fmt.Errorf("%w: no anthropic provider", ErrTenantCredentialMissing)}
		r := &CatalogAgentResolver{sandboxClass: "agent", lookup: lookup, credentials: src}
		_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude"})
		if !errors.Is(err, ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want ErrTenantCredentialMissing", err)
		}
	})

	t.Run("no credential source wired is a refusal too", func(t *testing.T) {
		r := &CatalogAgentResolver{sandboxClass: "agent", lookup: lookup}
		if _, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude"}); err == nil {
			t.Fatal("want an error when the manifest needs credentials and no source is wired")
		}
	})

	t.Run("a manifest without credentials touches no source", func(t *testing.T) {
		plain := entry
		plain.Credentials = nil
		src := &stubCredentialSource{}
		r := &CatalogAgentResolver{sandboxClass: "agent", lookup: func(string) (componentcatalog.AgentEntry, bool) { return plain, true }, credentials: src}
		spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude"})
		if err != nil || len(spec.Env) != 0 || len(src.calls) != 0 {
			t.Fatalf("spec.Env=%v calls=%v err=%v; want no env and no lookup", spec.Env, src.calls, err)
		}
	})
}

// TestCatalogAgentResolver_EmptyCredentialValue: a source that answers with
// an empty string is still a missing credential; nothing launches with an
// empty key.
func TestCatalogAgentResolver_EmptyCredentialValue(t *testing.T) {
	entry := componentcatalog.AgentEntry{
		ID: "claude", Image: "ghcr.io/x/c@sha256:abc",
		Credentials: []componentcatalog.CredentialRequirement{{Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Key: "api_key"}},
	}
	src := &stubCredentialSource{values: map[string]string{}}
	r := &CatalogAgentResolver{sandboxClass: "agent", lookup: func(string) (componentcatalog.AgentEntry, bool) { return entry, true }, credentials: src}
	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "claude"})
	if !errors.Is(err, ErrTenantCredentialMissing) {
		t.Fatalf("err = %v, want ErrTenantCredentialMissing for an empty value", err)
	}
}

// TestCatalogAgentResolver_SizesTheSandbox: setec refuses vcpu < 1, so an
// unsized manifest takes the agent defaults, and a sized one is passed through.
func TestCatalogAgentResolver_SizesTheSandbox(t *testing.T) {
	unsized := &CatalogAgentResolver{sandboxClass: "agent", lookup: func(string) (componentcatalog.AgentEntry, bool) {
		return componentcatalog.AgentEntry{ID: "a", Image: "ghcr.io/x@sha256:a", Command: []string{"node", "a.js"}}, true
	}}
	spec, err := unsized.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "t"), AgentLaunchRequest{AgentName: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.VCPU != DefaultAgentVCPU || spec.Memory != DefaultAgentMemory {
		t.Fatalf("unsized: vcpu=%d memory=%q, want defaults %d/%s", spec.VCPU, spec.Memory, DefaultAgentVCPU, DefaultAgentMemory)
	}
	sized := &CatalogAgentResolver{sandboxClass: "agent", lookup: func(string) (componentcatalog.AgentEntry, bool) {
		return componentcatalog.AgentEntry{ID: "a", Image: "ghcr.io/x@sha256:a", Command: []string{"node", "a.js"}, Resources: componentcatalog.AgentResources{VCPU: 3, Memory: "6Gi"}}, true
	}}
	spec, err = sized.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "t"), AgentLaunchRequest{AgentName: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.VCPU != 3 || spec.Memory != "6Gi" || len(spec.Command) != 2 {
		t.Fatalf("sized: %+v", spec)
	}
}
