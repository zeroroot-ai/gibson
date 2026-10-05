// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestGraphWrite_ViolationOutsideProjector is the mutation case: a package that
// is not the projector opens a Neo4j write transaction and MUST be flagged.
// Both routes to a write are covered (managed and explicit transaction), and
// the fixture's ExecuteRead call carries no `want`, so a rule that flagged
// every driver call indiscriminately would fail here too.
func TestGraphWrite_ViolationOutsideProjector(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.GraphWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/daemon/graphwriteviolation")
}

// TestGraphWrite_ProjectorAllowedNeighbourIsNot loads the daemon package, whose
// fixture holds two files: graph_projector_neo4j.go (allowed, no `want`) and
// grpc.go (flagged). Same package, opposite verdicts — which is the point: the
// allowance is the projector's files, not the package it happens to live in.
func TestGraphWrite_ProjectorAllowedNeighbourIsNot(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.GraphWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/daemon")
}

// TestGraphWrite_AdapterPackageHasNoAllowance loads the driver-adapter
// package. Its fixture holds a write through the read entry point (neo4j.go)
// and a new write method (extra_writer.go). Both are flagged: the adapter
// package has no allowance since Query became read-only (gibson#673).
func TestGraphWrite_AdapterPackageHasNoAllowance(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.GraphWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph")
}

// TestGraphWrite_MigrateExempt verifies cmd/gibson-migrate is untouched by the
// rule — schema DDL is operational, outside the data plane (ADR-0112).
func TestGraphWrite_MigrateExempt(t *testing.T) {
	testdata := analysistest.TestData()
	// No `want` comments — an exempt path produces zero diagnostics.
	analysistest.Run(t, testdata, checks.GraphWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/cmd/gibson-migrate/graphwritemigrate")
}

// TestGraphWrite_NoBaseline guards the decision that this analyzer ships with no
// baseline (ADR-0112). A baseline is a list of exceptions that never
// shrinks; if one is ever added, this test should be the thing that argues
// against it rather than a comment nobody reads.
func TestGraphWrite_NoBaseline(t *testing.T) {
	if checks.GraphWriteAnalyzer.Flags.Lookup("baseline") != nil {
		t.Fatal("graphwrite must not grow a baseline flag: by ADR-0112 there " +
			"are no pre-existing violations, and a baseline would only ever accumulate new ones")
	}
	if !strings.Contains(checks.GraphWriteAnalyzer.Doc, "ADR-0112") {
		t.Errorf("graphwrite doc must cite the ADR it enforces, got %q", checks.GraphWriteAnalyzer.Doc)
	}
}
