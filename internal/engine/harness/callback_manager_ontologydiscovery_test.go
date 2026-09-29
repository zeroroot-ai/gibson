// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestCallbackManager_SetOntologyDiscovery proves the manager-level setter
// reaches the underlying callback service (ADR-0024 §2, ADR-0033 decision 2,
// gibson#391) — the same wiring contract SetBeliefSubstrate/SetProofSettlement
// use, exercised here before Start() (construction alone is enough:
// NewCallbackServerWithRegistry builds the service eagerly). Without this,
// ProposeOntologyExtension has no engine on any daemon that only calls
// CallbackManager (every real daemon) and always answers Unavailable.
func TestCallbackManager_SetOntologyDiscovery(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx).For("acme")
	m.SetOntologyDiscovery(engine)

	if m.server == nil || m.server.service == nil {
		t.Fatal("manager must construct its server/service eagerly")
	}
	if m.server.service.ontologyDiscovery == nil {
		t.Fatal("SetOntologyDiscovery must reach the underlying callback service")
	}

	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")
	if err := m.server.service.ontologyDiscovery.ProposeOntologyExtension(
		acmeCtx, taxonomy.ProposedNodeLabel, "CustomHost", "recon-agent", "seen it",
	); err != nil {
		t.Fatalf("ProposeOntologyExtension: %v", err)
	}
}

// TestCallbackManager_SetOntologyDiscovery_NilServerIsNoOp proves the setter
// is safe to call on a manager with no server (defensive guard, same shape as
// the other Set* methods).
func TestCallbackManager_SetOntologyDiscovery_NilServerIsNoOp(_ *testing.T) {
	m := &CallbackManager{logger: slog.Default()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.SetOntologyDiscovery(brain.NewRegistry(ctx).For("acme"))
}

// TestCallbackManager_OntologyDiscovery proves the getter is the read half of
// SetOntologyDiscovery: nil before anything is wired, and the exact value
// passed to SetOntologyDiscovery afterward. Unlike the setter, the getter is
// a request-path method that assumes a manager built through
// NewCallbackManager (ADR-0003).
func TestCallbackManager_OntologyDiscovery(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.Default())
	if got := m.OntologyDiscovery(); got != nil {
		t.Fatalf("OntologyDiscovery() before SetOntologyDiscovery = %v, want nil", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx).For("acme")
	m.SetOntologyDiscovery(engine)
	if got := m.OntologyDiscovery(); got != brain.OntologyDiscoveryEngine(engine) {
		t.Fatalf("OntologyDiscovery() = %v, want the exact value passed to SetOntologyDiscovery", got)
	}
}
