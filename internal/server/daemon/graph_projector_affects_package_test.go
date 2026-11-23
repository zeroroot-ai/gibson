// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The Finding projection carries the Package key, and the Cypher uses the same
// parameter. A parameter in the query that the map does not hold would fail the
// write on the first Finding (gibson#1469).
func TestFindingUpsert_WritesAffectsPackage(t *testing.T) {
	params := findingUpsertParams(brain.FindingSnapshot{ID: "f1",
		Places:   []brain.FindingPlace{{Label: "Image", Key: "sha256:aa"}, {Label: "Repository", Key: "gitlab.com/g/p"}},
		Packages: []string{"pkg:apk/alpine/libx@1.0"}})
	if got := params["affects_images"].([]string); len(got) != 1 || got[0] != "sha256:aa" {
		t.Fatalf("affects_images = %v", got)
	}
	if got := params["affects_repositories"].([]string); len(got) != 1 || got[0] != "gitlab.com/g/p" {
		t.Fatalf("affects_repositories = %v", got)
	}
	if got := params["in_packages"].([]string); len(got) != 1 {
		t.Fatalf("in_packages = %v", got)
	}
	// A Package is data. The Cypher must not write AFFECTS to it.
	if !strings.Contains(upsertFindingCypher, "MERGE (f)-[:IN_PACKAGE]->(p)") || strings.Contains(upsertFindingCypher, "AFFECTS]->(p)") {
		t.Error("the Package edge must be IN_PACKAGE and never AFFECTS")
	}
	// A finding with no place passes empty lists, never nil.
	empty := findingUpsertParams(brain.FindingSnapshot{ID: "f2"})
	for _, k := range []string{"affects_images", "affects_repositories", "in_packages"} {
		if empty[k] == nil {
			t.Errorf("%s is nil for a finding with no place", k)
		}
	}
	for _, m := range regexp.MustCompile(`\$([a-z_]+)`).FindAllStringSubmatch(upsertFindingCypher, -1) {
		if _, ok := params[m[1]]; !ok {
			t.Errorf("the Cypher uses $%s and the parameter map has none", m[1])
		}
	}
}
