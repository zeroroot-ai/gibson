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

// gateSeedAuthorizer records writes; ListObjects answers empty so every
// embedded catalog entry counts as missing.
type gateSeedAuthorizer struct {
	authz.Authorizer
	writes []authz.Tuple
}

func (a *gateSeedAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (a *gateSeedAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.writes = append(a.writes, tuples...)
	return nil
}

// The startup seed writes one platform_enabled tuple per embedded catalog
// entry, on its canonical component:<kind>/<id> object. The catalog is
// multi-kind (ADR-0015): connectors AND the zerocool agent (ADR-0016), so the
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
