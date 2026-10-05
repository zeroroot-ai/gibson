// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// daemonImportPath is the import that ext-authz must never have.
const daemonImportPath = "github.com/zeroroot-ai/gibson/internal/server/daemon"

// extAuthzDir returns cmd/ext-authz, the directory of this file.
func extAuthzDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(thisFile)
}

// daemonImportFindings scans each scope directory, with all its
// sub-packages, for an import of the daemon. A scope directory that does not
// exist is an error. The walker skips such a directory with no message, and a
// guard that scans nothing can never fail.
func daemonImportFindings(repoRoot string, scopeDirs ...string) ([]astchecks.Finding, error) {
	for _, dir := range scopeDirs {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("scope directory %s: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("scope path %s is not a directory", dir)
		}
	}
	findings, err := astchecks.Walk(astchecks.WalkOpts{
		ScopeDirs: scopeDirs,
		RepoRoot:  repoRoot,
		Matchers: []astchecks.Matcher{
			astchecks.NewImportBoundary(
				"ext-authz must not import the gibson daemon (internal/server/daemon). "+
					"It is an independent authorization service (ADR-0056)",
				daemonImportPath,
			),
		},
		SkipTestFiles: false, // the boundary applies to test files too
		SkipGenerated: true,
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	return findings, nil
}

// TestNoDaemonImport asserts that ext-authz never links the gibson daemon.
//
// ext-authz lives in the gibson module (ADR-0056) and shares internal/infra.
// It stays an independent authorization service, so cmd/ext-authz and
// internal/server/extauthz, with all sub-packages, must not import
// internal/server/daemon. A type that both need belongs in the SDK. ext-authz
// gets the authz registry from the daemon at run time over mTLS.
func TestNoDaemonImport(t *testing.T) {
	cmdDir := extAuthzDir()
	repoRoot := filepath.Join(cmdDir, "..", "..")
	findings, err := daemonImportFindings(repoRoot,
		cmdDir,
		filepath.Join(repoRoot, "internal", "server", "extauthz"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("ext-authz imports the gibson daemon. Remove the import:\n%s",
			astchecks.RenderFindings(findings))
	}
}

// TestNoDaemonImport_FlagsTheFixture proves that the guard can fail: the
// fixture imports the daemon, and the guard reports it.
func TestNoDaemonImport_FlagsTheFixture(t *testing.T) {
	fixture := filepath.Join(extAuthzDir(), "testdata", "daemon_import")
	findings, err := daemonImportFindings(fixture, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("the guard found %d daemon imports in the fixture, want 1:\n%s",
			len(findings), astchecks.RenderFindings(findings))
	}
}

// TestNoDaemonImport_RefusesMissingScope proves that a scope directory that
// does not exist fails the guard. The guard scanned internal/extauthz, which
// did not exist, and passed for that reason.
func TestNoDaemonImport_RefusesMissingScope(t *testing.T) {
	missing := filepath.Join(extAuthzDir(), "..", "..", "internal", "extauthz")
	if _, err := daemonImportFindings(extAuthzDir(), missing); err == nil {
		t.Fatal("a scope directory that does not exist must fail the guard")
	}
}
