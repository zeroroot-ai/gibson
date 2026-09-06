// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

func TestForbiddenImports(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ForbiddenImportsAnalyzer, "forbidden")
}

func TestNoTrustLocalhost(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.NoTrustLocalhostAnalyzer, "trustlocalhost")
}
