// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// gateSeedAuthorizer records writes and deletes. ListObjects answers existing,
// which is empty by default, so every embedded catalog entry counts as missing.
type gateSeedAuthorizer struct {
	authz.Authorizer
	existing []string
	writes   []authz.Tuple
	deletes  []authz.Tuple
}

func (a *gateSeedAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return a.existing, nil
}

func (a *gateSeedAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	a.deletes = append(a.deletes, tuples...)
	return nil
}

func (a *gateSeedAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.writes = append(a.writes, tuples...)
	return nil
}

// The startup seed writes one platform_enabled tuple per embedded catalog
// entry, on its canonical component:<kind>/<id> object. The catalog is
// multi-kind (ADR-0136): connectors AND the zerocool agent (ADR-0116), so the
// seed must cover every kind, not connectors only.
func TestSeedConnectorCatalogGate_SeedsEmbeddedCatalog(t *testing.T) {
	a := &gateSeedAuthorizer{}
	// An all-pass verifier: this test is about what the seed writes, not about
	// signature enforcement, which component_image_verification_test.go covers.
	if err := seedComponentCatalogGate(context.Background(), a, &stubVerifier{}, slog.Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(a.writes) == 0 {
		t.Fatal("embedded catalog must produce at least one tuple")
	}
	sawAgent := false
	for _, w := range a.writes {
		if w.User != "system_tenant:_system" || w.Relation != "platform_enabled" {
			t.Fatalf("unexpected tuple %+v", w)
		}
		if !strings.HasPrefix(w.Object, "component:") {
			t.Fatalf("object %q is not a canonical component object", w.Object)
		}
		if w.Object == "component:agent/zerocool" {
			sawAgent = true
		}
	}
	if !sawAgent {
		t.Error("the seed must platform_enable the zerocool agent (component:agent/zerocool), not connectors only")
	}
}

// A cluster that has the platform_enabled tuple of the OSV prototype loses it
// at the next seed, because the entry left the catalog (gibson#750). The seed
// keeps each listed entry and each Domain Pack, which another seed owns.
func TestSeedComponentCatalogGate_RemovesTheRetiredOSVConnector(t *testing.T) {
	a := &gateSeedAuthorizer{existing: []string{
		"component:connector/osv",
		"component:agent/zerocool",
		"component:domainpack/web",
	}}
	if err := seedComponentCatalogGate(context.Background(), a, &stubVerifier{}, slog.Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	want := authz.Tuple{User: "system_tenant:_system", Relation: "platform_enabled", Object: "component:connector/osv"}
	if len(a.deletes) != 1 || a.deletes[0] != want {
		t.Fatalf("deleted %+v, want only %+v", a.deletes, want)
	}
	for _, w := range a.writes {
		if w.Object == "component:connector/osv" {
			t.Fatal("the seed wrote a tuple for the retired OSV connector")
		}
	}
}
