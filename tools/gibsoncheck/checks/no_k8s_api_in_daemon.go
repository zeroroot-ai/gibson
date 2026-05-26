package checks

import (
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// NoK8sAPIInDaemonAnalyzer enforces ADR-0023: the gibson daemon binary's
// source tree under github.com/zeroroot-ai/gibson/internal/** and
// github.com/zeroroot-ai/gibson/pkg/** does not import any Kubernetes
// API client construction surface.
//
// The principle: the daemon is a per-tenant gRPC request handler, not
// an orchestrator. Every K8s-shaped fact reaches the daemon via file
// mounts (ConfigMaps, Secrets projected as volumes), environment
// variables (small values projected by the chart), data-plane signals
// (broker_config rows, per-tenant DB pingability), or operator/CronJob
// emission. The daemon never instantiates a K8s client.
//
// Trigger: 2026-05-19T18:42Z testa123 incident — a single tenant CRD
// stuck mid-teardown crashed the daemon for every user because the
// daemon's startup mission-recovery loop enumerated Tenant CRDs via the
// dynamic K8s client and panicked on the broker's auth cache. ADR-0023
// removes the entire category of bug by making the daemon binary
// K8s-API-free at compile time.
//
// Allow-list (the rule SKIPS these paths even when they import K8s):
//   - github.com/zeroroot-ai/gibson/cmd/**       (administrative CLIs and
//     the sandbox-eviction-handler sidecar binary; per ADR-0023 §Allow-list)
//   - github.com/zeroroot-ai/gibson/tests/**     (e2e test fixtures)
//   - github.com/zeroroot-ai/gibson/tools/**     (build tools; including this analyzer)
//   - github.com/zeroroot-ai/gibson/internal/datapool/admin/**
//     (gated by adminpoolacquire — legitimate enumeration)
//   - github.com/zeroroot-ai/gibson/pkg/platform/saga/**
//     (operator-shared library; tenant-operator imports it)
//   - any file path containing "/testdata/"      (analysistest fixtures)
//
// Deferred-deletion file paths: NONE. S10 (gibson#212) landed and
// deleted both K8s key/crypto providers. The file-grained exemption
// list below is intentionally empty; new entries should not be added
// unless a future slice has a similar staged-rip need.
//
// Forbidden imports (the rule flags any of these in an in-scope file):
//   - k8s.io/client-go/                  (any subpackage)
//   - sigs.k8s.io/controller-runtime     (any subpackage)
//   - k8s.io/apimachinery/pkg/runtime    (dynamic runtime API surface)
//
// NOT forbidden:
//   - k8s.io/apimachinery/pkg/apis/meta/v1 (metav1 — type-only serialization)
//   - k8s.io/api/core/v1                   (corev1 — type-only)
//   - k8s.io/apimachinery/pkg/api/errors   (typed error-shape checks)
//
// Spec: ADR-0023 (gibson daemon does not consume the Kubernetes API at runtime).
var NoK8sAPIInDaemonAnalyzer = &analysis.Analyzer{
	Name: "nok8sapiindaemon",
	Doc:  "flag imports of k8s.io/client-go, sigs.k8s.io/controller-runtime, or k8s.io/apimachinery/pkg/runtime from gibson daemon source (ADR-0023)",
	Run:  runNoK8sAPIInDaemon,
}

// gibsonDaemonScopePrefixes lists the import-path prefixes that bring a
// package into scope for the no-k8s-api-in-daemon check. These match
// the daemon binary's build tree under the gibson repo's internal/ and
// pkg/ directories.
var gibsonDaemonScopePrefixes = []string{
	"github.com/zeroroot-ai/gibson/internal/",
	"github.com/zeroroot-ai/gibson/pkg/",
}

// noK8sAPIInDaemonExemptSubstrings lists package-path substrings (not
// file paths) that remove a package from scope even when a scope prefix
// matched. Substring matching means subpackages are also exempt.
var noK8sAPIInDaemonExemptSubstrings = []string{
	// Admin gate already enforces import restriction; admin code
	// legitimately enumerates tenants for CLI/migration paths.
	"/internal/datapool/admin",

	// Operator-shared saga library used by tenant-operator. The daemon
	// binary's build graph does not reach it; it's in pkg/ only because
	// the gibson repo currently houses the source.
	"/pkg/platform/saga",

	// Analyzer tests and analysistest fixtures.
	"/testdata/",

	// The analyzer itself.
	"/tools/gibsoncheck",
}

// noK8sAPIInDaemonExemptFiles lists EXACT relative file paths that are
// exempt from the rule pending their owning slice. These are
// file-grained exemptions (vs the package-grained list above) because
// the parent package contains other files that should stay in scope.
//
// REMOVE entries from this list as the corresponding deletion slices
// land. Each entry should reference its tracking issue in the comment.
// Currently empty: S10 (gibson#212) deleted the two K8s key/crypto
// provider files that previously needed an exemption.
var noK8sAPIInDaemonExemptFiles = []string{}

// forbiddenK8sImportPrefixes lists the import-path prefixes that the
// rule flags. Substring/prefix matching catches subpackages.
var forbiddenK8sImportPrefixes = []string{
	"k8s.io/client-go/",
	"sigs.k8s.io/controller-runtime",
	"k8s.io/apimachinery/pkg/runtime",
}

func runNoK8sAPIInDaemon(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// 1. In-scope?
	inScope := false
	for _, prefix := range gibsonDaemonScopePrefixes {
		if strings.HasPrefix(pkgPath, prefix) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil, nil
	}

	// 2. Package-grained exemption (the whole package is allowlisted)?
	for _, exempt := range noK8sAPIInDaemonExemptSubstrings {
		if strings.Contains(pkgPath, exempt) {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		// 3. File-grained exemption check. analysistest fixtures live
		// under /testdata/ which the substring list already exempts,
		// but real-tree files may need per-file exemptions during a
		// staged rip.
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			// Test files MAY import K8s for fake-client tests of
			// daemon-side legitimate code. The rule's intent is
			// runtime imports, not test infrastructure.
			continue
		}
		if isExemptFile(fname) {
			continue
		}

		// 4. Walk the imports and flag any forbidden prefix.
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			for _, forbidden := range forbiddenK8sImportPrefixes {
				if strings.HasPrefix(path, forbidden) {
					pass.Reportf(imp.Pos(),
						"forbidden import %q in %q: the gibson daemon binary does not consume the Kubernetes API at runtime per ADR-0023. Replacement patterns: chart-mounted ConfigMap/Secret volumes (file-mount), chart-projected env vars, data-plane signals (broker_config row, per-tenant DB ping), operator/CronJob emission, or node-local sidecar binaries.",
						path, pkgPath)
					break // one finding per import line
				}
			}
		}
	}

	return nil, nil
}

// isExemptFile checks if the (absolute or analysistest-virtual) file
// path matches any of the file-grained exemptions. Compares against
// the trailing relative path so analysistest's virtual GOPATH layout
// works the same as the real tree.
func isExemptFile(fname string) bool {
	clean := filepath.ToSlash(fname)
	for _, exempt := range noK8sAPIInDaemonExemptFiles {
		if strings.HasSuffix(clean, exempt) {
			return true
		}
	}
	return false
}
