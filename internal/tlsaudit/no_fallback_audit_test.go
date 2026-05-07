// Package tlsaudit hosts the TLS no-fallback CI guard test for spec
// critical-tls-no-fallbacks (Component 6).
//
// This test walks the workspace at HEAD and asserts three invariants:
//
//  1. Zero matches of `tls.RequestClientCert`, `tls.NoClientCert`,
//     `tls.VerifyClientCertIfGiven`, `tls.RequireAnyClientCert` outside
//     `*_test.go` files in core/, enterprise/, and opensource/.
//
//  2. The harness callback listener at
//     core/gibson/internal/harness/callback_server.go contains both
//     `grpc.Creds(` and `tlsconfig.MTLSServerConfig(` — the listener is
//     SPIFFE-mTLS-wrapped (Component 1).
//
//  3. Every `reflection.Register(` call site in
//     core/gibson/internal/harness/callback_server.go and
//     core/gibson/internal/daemon/grpc.go is preceded within 5 source
//     lines by `os.Getenv("GIBSON_GRPC_REFLECTION")` (Component 3 /
//     Requirement 4).
//
// The test runs under `make test` and `make test-race`. It uses pure-Go
// filepath.WalkDir + os.ReadFile + simple substring/regexp matching — no
// shell-out, no path-skip lists for "known-safe" production files.
//
// This test lives in a dedicated leaf package (internal/tlsaudit) — NOT
// internal/daemon — so it has no transitive build dependency on the daemon
// production package. That keeps the audit runnable even when transient
// sibling-spec WIP breaks the daemon's import graph.
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

// findWorkspaceRoot ascends from cwd until it finds a directory that contains
// every one of {core, enterprise, opensource}. Returns "" if none found —
// caller must handle that as a skip (the test cannot run outside the polyrepo
// workspace, e.g. when only the daemon tarball is unpacked in CI).
func findWorkspaceRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		hits := 0
		for _, sub := range []string{"core", "enterprise", "opensource"} {
			if info, err := os.Stat(filepath.Join(dir, sub)); err == nil && info.IsDir() {
				hits++
			}
		}
		if hits == 3 {
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
				// .claude directory holds concurrent agent worktrees with
				// snapshots of source — auditing them would double-count
				// findings that the parent tree already covers.
				if name == "vendor" || name == ".git" || name == "node_modules" || name == ".tmp" || name == "dist" || name == ".claude" {
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

// TestNoFallbackAudit is the workspace-wide CI guard for spec
// critical-tls-no-fallbacks. See package doc.
func TestNoFallbackAudit(t *testing.T) {
	wsRoot := findWorkspaceRoot()
	if wsRoot == "" {
		t.Skip("workspace root (core/+enterprise/+opensource/) not found from cwd; " +
			"this test must run from within the polyrepo workspace tree")
	}
	t.Logf("workspace root: %s", wsRoot)

	roots := []string{
		filepath.Join(wsRoot, "core"),
		filepath.Join(wsRoot, "enterprise"),
		filepath.Join(wsRoot, "opensource"),
	}

	t.Run("no_banned_clientauth_literals", func(t *testing.T) {
		var violations []string
		walkProductionGoFiles(t, roots, func(path string, contents []byte) {
			body := string(contents)
			for _, banned := range bannedClientAuthLiterals {
				if strings.Contains(body, banned) {
					rel, err := filepath.Rel(wsRoot, path)
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
		path := filepath.Join(wsRoot, "core", "gibson", "internal", "harness", "callback_server.go")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(data)
		for _, needle := range []string{"grpc.Creds(", "tlsconfig.MTLSServerConfig("} {
			if !strings.Contains(body, needle) {
				t.Errorf("spec critical-tls-no-fallbacks Component 1: "+
					"callback_server.go must contain %q (the SPIFFE-mTLS wrap)", needle)
			}
		}
	})

	t.Run("reflection_register_is_gated", func(t *testing.T) {
		gatedFiles := []string{
			filepath.Join(wsRoot, "core", "gibson", "internal", "harness", "callback_server.go"),
			filepath.Join(wsRoot, "core", "gibson", "internal", "daemon", "grpc.go"),
		}
		reflectionLine := regexp.MustCompile(`reflection\.Register\(`)
		gateLine := regexp.MustCompile(`os\.Getenv\("GIBSON_GRPC_REFLECTION"\)`)
		for _, path := range gatedFiles {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // file may not exist (e.g. running from a stripped tarball)
				}
				t.Fatalf("read %s: %v", path, err)
			}
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if !reflectionLine.MatchString(line) {
					continue
				}
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
				if !gated {
					rel, err := filepath.Rel(wsRoot, path)
					if err != nil {
						rel = path
					}
					t.Errorf("spec critical-tls-no-fallbacks Component 3 / Requirement 4.1: "+
						"%s line %d has reflection.Register( without an "+
						"os.Getenv(\"GIBSON_GRPC_REFLECTION\") gate within 5 preceding lines",
						rel, i+1)
				}
			}
		}
	})
}
