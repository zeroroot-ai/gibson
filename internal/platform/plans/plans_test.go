// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package plans_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/plans"
)

// tierEnumMarker extracts the kubebuilder enum marker that generates the
// Tenant CRD's spec.tier enum. That marker is the operator-side mirror of
// plans.yaml; this test pins the daemon-side mirror in package plans to it so
// the two cannot drift.
var tierEnumMarker = regexp.MustCompile(`\+kubebuilder:validation:Enum=([a-z0-9;-]+)`)

func TestPlanIDsMatchCRDEnum(t *testing.T) {
	// internal/platform/plans -> repo root is three levels up.
	path := filepath.Join("..", "..", "..", "operators", "tenant", "api", "v1alpha1", "tenant_types.go")
	src, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path, test-only
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// The file carries several enum markers (tier, data-plane store state, …).
	// The tier one is the only marker that mentions the "team" plan.
	var enum []string
	for _, m := range tierEnumMarker.FindAllStringSubmatch(string(src), -1) {
		vals := strings.Split(m[1], ";")
		for _, v := range vals {
			if v == "team" {
				enum = vals
				break
			}
		}
	}
	if enum == nil {
		t.Fatalf("no tier kubebuilder enum marker found in %s", path)
	}

	got := plans.IDs()
	sort.Strings(got)
	sort.Strings(enum)

	if strings.Join(got, ",") != strings.Join(enum, ",") {
		t.Fatalf("plan id drift:\n  package plans: %v\n  Tenant CRD enum: %v\nplans.yaml changed without updating one of the two mirrors", got, enum)
	}
}

func TestLookupRejectsNonCanonicalIDs(t *testing.T) {
	for _, id := range []string{
		"",
		"   ",
		"Enterprise",       // case must match exactly
		"enterprise ",      // trailing space is trimmed, so this one SHOULD resolve
		"free",             // legacy id, remapped by the chart migrate Job
		"pro",              // legacy id
		"enterprise-cloud", // legacy id
		"../enterprise",
	} {
		_, ok := plans.Lookup(id)
		wantOK := id == "enterprise "
		if ok != wantOK {
			t.Errorf("Lookup(%q) ok = %v, want %v", id, ok, wantOK)
		}
	}
}

func TestSelfServeExcludesContactSalesPlan(t *testing.T) {
	p, ok := plans.Lookup("enterprise-deploy")
	if !ok {
		t.Fatal("enterprise-deploy must be a canonical plan (it is a valid Tenant tier)")
	}
	if p.SelfServe {
		t.Error("enterprise-deploy is contact-sales; it must not be self-serve acquirable")
	}
	if p.Paid {
		t.Error("enterprise-deploy has no Stripe product; it must not be marked Paid")
	}

	self := plans.SelfServeIDs()
	for _, id := range self {
		if id == "enterprise-deploy" {
			t.Fatal("SelfServeIDs must not include enterprise-deploy")
		}
	}
	if len(self) == 0 {
		t.Fatal("SelfServeIDs must not be empty")
	}
}

func TestEverySelfServePlanIsPaid(t *testing.T) {
	// A self-serve plan with Paid=false would be a free tier the billing gate
	// silently waves through. There is no free tier in plans.yaml; if one is
	// ever added, this test forces a deliberate decision here.
	for _, id := range plans.SelfServeIDs() {
		p, _ := plans.Lookup(id)
		if !p.Paid {
			t.Errorf("plan %q is self-serve but not Paid; the signup billing gate would not apply to it", id)
		}
	}
}
