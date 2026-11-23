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
	params := findingUpsertParams(brain.FindingSnapshot{ID: "f1", AffectsPackage: "pkg:apk/alpine/libx@1.0"})
	if params["affects_package"] != "pkg:apk/alpine/libx@1.0" {
		t.Fatalf("affects_package = %v", params["affects_package"])
	}
	if !strings.Contains(upsertFindingCypher, "MERGE (f)-[:AFFECTS]->(p)") {
		t.Error("the Cypher writes no AFFECTS edge to a Package")
	}
	for _, m := range regexp.MustCompile(`\$([a-z_]+)`).FindAllStringSubmatch(upsertFindingCypher, -1) {
		if _, ok := params[m[1]]; !ok {
			t.Errorf("the Cypher uses $%s and the parameter map has none", m[1])
		}
	}
}
