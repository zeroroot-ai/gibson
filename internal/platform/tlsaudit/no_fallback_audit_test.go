// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tlsaudit hosts the TLS no-fallback CI guard test for spec
// critical-tls-no-fallbacks (Component 6).
//
// The test walks THIS repository at HEAD and asserts three invariants:
//
//  1. Zero matches of `tls.RequestClientCert`, `tls.NoClientCert`,
//     `tls.VerifyClientCertIfGiven`, `tls.RequireAnyClientCert` outside
//     `*_test.go` files.
//
//  2. The harness callback listener
//     (internal/engine/harness/callback_server.go) contains both
//     `grpc.Creds(` and `tlsconfig.MTLSServerConfig(` — the listener is
//     SPIFFE-mTLS-wrapped (Component 1).
//
//  3. Every `reflection.Register(` call site in production code is preceded
//     within 5 source lines by an `os.Getenv("..._GRPC_REFLECTION")` gate
//     (Component 3 / Requirement 4).
//
// Until this change the guard could not fail. It ascended from cwd looking for
// the three pre-split workspace directories together, and skipped when it found
// none, which is every checkout of this repository and every CI runner. Its two
// file assertions named paths this module has not used since the monorepo
// layout landed, and assertion 3 treated a missing file as a pass. Three dead
// assertions reported green on every run.
//
// The rule in assertion 3 is now structural rather than a file list: any
// production file that gains a `reflection.Register(` call must gate it, so a
// new listener cannot escape the guard by living somewhere the list does not
// name.
//
// The test runs under `make test` and `make test-race`. It uses pure-Go
// filepath.WalkDir + os.ReadFile + simple substring/regexp matching — no
// shell-out, no path-skip lists for "known-safe" production files.
//
// This test lives in a dedicated leaf package so it has no transitive build
// dependency on the daemon production package. That keeps the audit runnable
// even when transient sibling-spec WIP breaks the daemon's import graph.
package tlsaudit

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bannedClientAuthLiterals are tls.Config.ClientAuth values that are forbidden
// in production code by spec critical-tls-no-fallbacks Requirement 3.1.
// `tls.RequireAndVerifyClientCert` (the only acceptable production value) is
// NOT on this list. Test files (*_test.go) are exempt.
var bannedClientAuthLiterals = []string{
	"tls.RequestClientCert",
	"tls.NoClientCert",
	"tls.VerifyClientCertIfGiven",
	"tls.RequireAnyClientCert",
}

// callbackServerPath is the harness callback listener, relative to the module
// root. Assertion 2 reads it directly, so a rename fails the test loudly
// instead of skipping it.
const callbackServerPath = "internal/engine/harness/callback_server.go"

// findRepoRoot ascends from cwd until it finds the directory that holds both a
// go.mod and this test's own package. The second condition pins it to THIS
// module: a go.mod alone would also match a nested module. It returns "" only
// when the test runs outside the module, which the caller treats as a failure
// rather than a skip.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		_, modErr := os.Stat(filepath.Join(dir, "go.mod"))
		_, selfErr := os.Stat(filepath.Join(dir, filepath.FromSlash("internal/platform/tlsaudit")))
		if modErr == nil && selfErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func walkProductionGoFiles(t *testing.T, roots []string, fn func(path string, contents []byte)) {
	t.Helper()
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					return filepath.SkipDir
				}
				return err
			}
			if d.IsDir() {
				name := d.Name()
				// Skip vendored / VCS / build / agent-worktree dirs. The
				// .worktrees directory holds concurrent agent worktrees with
				// snapshots of source — auditing them would double-count
				// findings that the parent tree already covers.
				if name == "vendor" || name == ".git" || name == "node_modules" || name == ".tmp" || name == "dist" || name == ".claude" || name == ".worktrees" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			fn(path, data)
			return nil
		})
		if walkErr != nil {
			t.Logf("walk %s: %v", root, walkErr)
		}
	}
}

// TestNoFallbackAudit is the repository-wide CI guard for spec
// critical-tls-no-fallbacks. See package doc.
func TestNoFallbackAudit(t *testing.T) {
	repoRoot := findRepoRoot(t)
	if repoRoot == "" {
		t.Fatal("module root (the directory holding this module's go.mod) not found from cwd")
	}
	t.Logf("repository root: %s", repoRoot)

	roots := []string{repoRoot}

	t.Run("no_banned_clientauth_literals", func(t *testing.T) {
		var violations []string
		walkProductionGoFiles(t, roots, func(path string, contents []byte) {
			body := string(contents)
			for _, banned := range bannedClientAuthLiterals {
				if strings.Contains(body, banned) {
					rel, err := filepath.Rel(repoRoot, path)
					if err != nil {
						rel = path
					}
					violations = append(violations,
						rel+" contains banned literal "+banned)
				}
			}
		})
		if len(violations) > 0 {
			t.Fatalf("spec critical-tls-no-fallbacks Requirement 3.1: "+
				"production code must not reference any of %v outside *_test.go.\n"+
				"Violations:\n  - %s\n"+
				"Use tls.RequireAndVerifyClientCert instead.",
				bannedClientAuthLiterals,
				strings.Join(violations, "\n  - "))
		}
	})

	t.Run("callback_server_is_spiffe_wrapped", func(t *testing.T) {
		path := filepath.Join(repoRoot, filepath.FromSlash(callbackServerPath))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", callbackServerPath, err)
		}
		body := string(data)
		for _, needle := range []string{"grpc.Creds(", "tlsconfig.MTLSServerConfig("} {
			if !strings.Contains(body, needle) {
				t.Errorf("spec critical-tls-no-fallbacks Component 1: "+
					"%s must contain %q (the SPIFFE-mTLS wrap)", callbackServerPath, needle)
			}
		}
	})

	t.Run("reflection_register_is_gated", func(t *testing.T) {
		reflectionLine := regexp.MustCompile(`reflection\.Register\(`)
		gateLine := regexp.MustCompile(`os\.Getenv\("[A-Z_]*GRPC_REFLECTION"\)`)
		sites := 0
		walkProductionGoFiles(t, roots, func(path string, contents []byte) {
			lines := strings.Split(string(contents), "\n")
			for i, line := range lines {
				if !reflectionLine.MatchString(line) {
					continue
				}
				sites++
				start := i - 5
				if start < 0 {
					start = 0
				}
				gated := false
				for j := start; j <= i; j++ {
					if gateLine.MatchString(lines[j]) {
						gated = true
						break
					}
				}
				if gated {
					continue
				}
				rel, err := filepath.Rel(repoRoot, path)
				if err != nil {
					rel = path
				}
				t.Errorf("spec critical-tls-no-fallbacks Component 3 / Requirement 4.1: "+
					"%s line %d has reflection.Register( without an "+
					"os.Getenv(\"..._GRPC_REFLECTION\") gate within 5 preceding lines",
					rel, i+1)
			}
		})
		// A guard that finds nothing to check is a guard that cannot fail.
		if sites == 0 {
			t.Fatal("no reflection.Register( call site found in production code; " +
				"the walk is broken or every listener moved, so this assertion checks nothing")
		}
		t.Logf("gated reflection.Register call sites checked: %d", sites)
	})
}
