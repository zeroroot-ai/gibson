// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// An empty catalog (this change's shipped state, gibson#381) produces no
// tuples — a no-op converge, not an error.
func TestSeedDomainPackCatalogGate_EmptyCatalogIsNoOp(t *testing.T) {
	a := &gateSeedAuthorizer{}
	if err := seedDomainPackCatalogGate(context.Background(), a, ontology.NewDomainPackCatalog(), slog.Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(a.writes) != 0 {
		t.Fatalf("an empty catalog must write no tuples, got %+v", a.writes)
	}
}

// A non-empty catalog seeds one platform_enabled tuple per pack, on its
// canonical component:domainpack/<name> object — the same generic
// reconciler.SeedComponentCatalogGate the connector/agent/tool/plugin
// catalogs use, unlike seedComponentCatalogGate no image verification runs
// first (a Domain Pack is data, never an executable image).
func TestSeedDomainPackCatalogGate_SeedsCatalogEntries(t *testing.T) {
	a := &gateSeedAuthorizer{}
	catalog := ontology.NewDomainPackCatalog(
		ontology.DomainPack{Name: "main", Version: 1},
		ontology.DomainPack{Name: "k8s", Version: 1},
	)

	if err := seedDomainPackCatalogGate(context.Background(), a, catalog, slog.Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if len(a.writes) != 2 {
		t.Fatalf("writes = %+v, want 2 tuples (one per catalog pack)", a.writes)
	}
	seen := map[string]bool{}
	for _, w := range a.writes {
		if w.User != "system_tenant:_system" || w.Relation != "platform_enabled" {
			t.Fatalf("unexpected tuple %+v", w)
		}
		seen[w.Object] = true
	}
	if !seen["component:domainpack/main"] || !seen["component:domainpack/k8s"] {
		t.Fatalf("expected platform_enabled tuples for both packs, got %+v", a.writes)
	}
}

// failingWriteAuthorizer answers ListObjects like gateSeedAuthorizer (nothing
// seeded yet) but fails every Write, exercising seedDomainPackCatalogGate's
// error path.
type failingWriteAuthorizer struct{ gateSeedAuthorizer }

var errCatalogGateWriteBoom = errors.New("fga write boom")

func (a *failingWriteAuthorizer) Write(context.Context, []authz.Tuple) error {
	return errCatalogGateWriteBoom
}

func TestSeedDomainPackCatalogGate_WrapsWriteError(t *testing.T) {
	a := &failingWriteAuthorizer{}
	catalog := ontology.NewDomainPackCatalog(ontology.DomainPack{Name: "main", Version: 1})

	err := seedDomainPackCatalogGate(context.Background(), a, catalog, slog.Default())
	if err == nil {
		t.Fatal("expected an error when the underlying authorizer.Write fails")
	}
}
