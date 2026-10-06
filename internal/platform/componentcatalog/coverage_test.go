// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

func TestValidateCoverage(t *testing.T) {
	if err := validateCoverage("t", authz.KindTool, &CoverageDecl{Categories: []string{"reconnaissance"}, Techniques: []string{"port_scan"}}); err != nil {
		t.Fatalf("a valid block was refused: %v", err)
	}
	if err := validateCoverage("t", authz.KindTool, nil); err != nil {
		t.Fatalf("no block was refused: %v", err)
	}
	for name, c := range map[string]struct {
		kind string
		decl CoverageDecl
	}{
		"connector":         {authz.KindConnector, CoverageDecl{Categories: []string{"reconnaissance"}}},
		"unknown category":  {authz.KindTool, CoverageDecl{Categories: []string{"not_a_category"}}},
		"technique not ids": {authz.KindAgent, CoverageDecl{Techniques: []string{"port scan"}}},
	} {
		if err := validateCoverage("t", c.kind, &c.decl); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The tool manifests carry their coverage (gibson#716).
func TestLookupCoverage(t *testing.T) {
	decl, ok := LookupCoverage(authz.KindTool, "nmap")
	if !ok || len(decl.Categories) != 1 || decl.Categories[0] != "reconnaissance" {
		t.Fatalf("nmap coverage = %+v, %v", decl, ok)
	}
	if _, ok := LookupCoverage(authz.KindTool, "nuclei"); ok {
		t.Error("nuclei states no coverage")
	}
	if _, ok := LookupCoverage(authz.KindPlugin, "nmap"); ok {
		t.Error("the kind is part of the key")
	}
}
