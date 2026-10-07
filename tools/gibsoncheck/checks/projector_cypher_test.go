// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestProjectorCypher is the failing fixture of gibson#993. In a projector
// file, a query built from input fails: passed to a forwarding helper, to the
// driver Run, or to the driver's query function, and so does a schema
// statement made from text outside its constructors. Constants, a forwarding
// cypher parameter and a converted schema statement pass. A file outside the
// projector is not checked.
func TestProjectorCypher(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ProjectorCypherAnalyzer,
		"projectorcypher/github.com/zeroroot-ai/gibson/internal/server/daemon")
}

// TestProjectorCypher_NoBaseline keeps the analyzer free of a baseline flag.
func TestProjectorCypher_NoBaseline(t *testing.T) {
	if checks.ProjectorCypherAnalyzer.Flags.Lookup("baseline") != nil {
		t.Fatal("projectorcypher must ship with no baseline (ADR-0112)")
	}
}
