// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// stubModelResolver is a hand-driven TenantModelResolver: it records what it
// was asked and answers with what the test wants the tenant's model to be.
type stubModelResolver struct {
	model  string
	window int
	err    error

	calls         int
	gotTenant     string
	gotPinned     string
	gotMinContext int
}

func (s *stubModelResolver) ResolveAgentModel(_ context.Context, tenant, pinned string, minContextWindow int) (model string, contextWindow int, err error) {
	s.calls++
	s.gotTenant = tenant
	s.gotPinned = pinned
	s.gotMinContext = minContextWindow
	if s.err != nil {
		return "", 0, s.err
	}
	return s.model, s.window, nil
}

// resolverForAgent builds a CatalogAgentResolver over one synthetic manifest,
// bypassing the embedded catalog so a test does not have to ship a manifest.
func resolverForAgent(entry componentcatalog.AgentEntry) *CatalogAgentResolver {
	r := NewCatalogAgentResolver("agent", nil)
	r.lookup = func(id string) (componentcatalog.AgentEntry, bool) {
		if id == entry.ID {
			return entry, true
		}
		return componentcatalog.AgentEntry{}, false
	}
	return r
}

func floorAgent(minContext int) componentcatalog.AgentEntry {
	return componentcatalog.AgentEntry{
		ID:               "triage",
		Image:            "ghcr.io/zeroroot-ai/triage@sha256:abc",
		Command:          []string{"/triage"},
		DispatchMode:     componentcatalog.DispatchModeSandboxed,
		MinContextWindow: minContext,
	}
}

// The refusal is the whole feature: a model under the floor does not error on
// its own, it truncates, and the run returns a short answer that reads as
// success. Nothing downstream can tell the difference, so the dispatch has to
// stop here.
func TestResolveAgentLaunchSpec_ModelUnderFloorIsRefused(t *testing.T) {
	t.Parallel()

	models := &stubModelResolver{model: "small-model", window: 8192}
	r := resolverForAgent(floorAgent(32000)).WithTenantModelResolver(models)

	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err == nil {
		t.Fatal("a model below the manifest floor must refuse the dispatch, got nil error")
	}
	if !errors.Is(err, ErrModelBelowFloor) {
		t.Fatalf("error = %v; want ErrModelBelowFloor", err)
	}
	// The message must name the floor, the model and the window it actually
	// has: an operator reading this at 2am needs to know which of the two to
	// change, and "dispatch failed" tells them neither.
	for _, want := range []string{"32000", "small-model", "8192", "acme"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
}

func TestResolveAgentLaunchSpec_ModelMeetingFloorIsUsed(t *testing.T) {
	t.Parallel()

	models := &stubModelResolver{model: "big-model", window: 200000}
	r := resolverForAgent(floorAgent(32000)).WithTenantModelResolver(models)

	spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err != nil {
		t.Fatalf("ResolveAgentLaunchSpec: %v", err)
	}
	// The resolved model, not the manifest's, is what the sandbox runs under —
	// otherwise the check would pass against one model and the agent would run
	// on another.
	if spec.Model != "big-model" {
		t.Errorf("spec.Model = %q; want the resolved model %q", spec.Model, "big-model")
	}
	if models.gotMinContext != 32000 {
		t.Errorf("resolver asked for min context %d; want 32000", models.gotMinContext)
	}
	if models.gotTenant != "acme" {
		t.Errorf("resolver asked for tenant %q; want acme", models.gotTenant)
	}
}

// An agent that declares no floor must dispatch exactly as it always has: no
// model resolution, no new failure mode, and the manifest's own model.
func TestResolveAgentLaunchSpec_NoFloorNeverResolvesAModel(t *testing.T) {
	t.Parallel()

	entry := floorAgent(0)
	entry.Model = "manifest-model"
	models := &stubModelResolver{model: "other", window: 200000}
	r := resolverForAgent(entry).WithTenantModelResolver(models)

	spec, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err != nil {
		t.Fatalf("ResolveAgentLaunchSpec: %v", err)
	}
	if models.calls != 0 {
		t.Errorf("model resolver was consulted %d times for an agent with no floor; want 0", models.calls)
	}
	if spec.Model != "manifest-model" {
		t.Errorf("spec.Model = %q; want the manifest's %q", spec.Model, "manifest-model")
	}
}

// With no resolver wired the floor cannot be checked. Launching anyway would
// report success over a truncation nobody can observe, so an unverifiable floor
// and a satisfied one must not behave the same.
func TestResolveAgentLaunchSpec_FloorWithNoResolverIsRefused(t *testing.T) {
	t.Parallel()

	r := resolverForAgent(floorAgent(32000))

	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err == nil {
		t.Fatal("a declared floor with no model resolver must refuse the dispatch, got nil error")
	}
	if !errors.Is(err, ErrModelBelowFloor) {
		t.Fatalf("error = %v; want ErrModelBelowFloor", err)
	}
	if !strings.Contains(err.Error(), "cannot be checked") {
		t.Errorf("error %q should say the floor could not be checked, not that the model is small", err.Error())
	}
}

// A resolver that fails (no provider configured, no model large enough) refuses
// the dispatch and keeps the underlying reason, because "no model has 32k" and
// "the tenant has no providers at all" need different fixes.
func TestResolveAgentLaunchSpec_ResolverErrorRefusesAndKeepsTheReason(t *testing.T) {
	t.Parallel()

	underlying := errors.New("no matching provider")
	models := &stubModelResolver{err: underlying}
	r := resolverForAgent(floorAgent(32000)).WithTenantModelResolver(models)

	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err == nil {
		t.Fatal("a failed model resolution must refuse the dispatch, got nil error")
	}
	if !errors.Is(err, underlying) {
		t.Fatalf("error = %v; want it to wrap %v", err, underlying)
	}
	if !strings.Contains(err.Error(), "32000") {
		t.Errorf("error %q does not name the floor that could not be met", err.Error())
	}
}

// The manifest's pinned model is passed through as the override: pinning names
// WHICH model, never whether it is big enough, so the floor still decides.
func TestResolveAgentLaunchSpec_PinnedModelIsStillMeasuredAgainstTheFloor(t *testing.T) {
	t.Parallel()

	entry := floorAgent(32000)
	entry.Model = "pinned-small"
	models := &stubModelResolver{model: "pinned-small", window: 4096}
	r := resolverForAgent(entry).WithTenantModelResolver(models)

	_, err := r.ResolveAgentLaunchSpec(auth.ContextWithTenantString(context.Background(), "acme"), AgentLaunchRequest{AgentName: "triage"})
	if err == nil {
		t.Fatal("a pinned model under the floor must still be refused, got nil error")
	}
	if !errors.Is(err, ErrModelBelowFloor) {
		t.Fatalf("error = %v; want ErrModelBelowFloor", err)
	}
	if models.gotPinned != "pinned-small" {
		t.Errorf("resolver was asked for pinned %q; want the manifest's pin", models.gotPinned)
	}
}
