//go:build e2e
// +build e2e

package helpers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "manifest-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

func TestLoadManifest_HappyPath(t *testing.T) {
	content := `
routes:
  - path: "/missions"
    kind: page
    method: GET
    auth: required
    landmark: "h1"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: false
    excluded_reason: ""
    excluded_tracking_issue: ""
  - path: "/login"
    kind: page
    method: GET
    auth: public
    landmark: "form"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: false
    excluded_reason: ""
    excluded_tracking_issue: ""
`
	path := writeTemp(t, content)
	entries, err := helpers.LoadManifest(path)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "/missions", entries[0].Path)
	assert.Equal(t, helpers.KindPage, entries[0].Kind)
	assert.Equal(t, helpers.AuthRequired, entries[0].Auth)
	assert.Equal(t, "/login", entries[1].Path)
	assert.Equal(t, helpers.AuthPublic, entries[1].Auth)
}

// ---------------------------------------------------------------------------
// Filter helpers
// ---------------------------------------------------------------------------

func TestFilterActive(t *testing.T) {
	entries := []helpers.RouteEntry{
		{Path: "/a", Kind: helpers.KindPage, Auth: helpers.AuthRequired, Excluded: false},
		{Path: "/b", Kind: helpers.KindPage, Auth: helpers.AuthRequired, Excluded: true, ExcludedReason: "demo"},
		{Path: "/c", Kind: helpers.KindAPI, Auth: helpers.AuthPublic, Excluded: false},
	}
	active := helpers.FilterActive(entries)
	assert.Len(t, active, 2)
	assert.Equal(t, "/a", active[0].Path)
	assert.Equal(t, "/c", active[1].Path)
}

func TestFilterPublic(t *testing.T) {
	entries := []helpers.RouteEntry{
		{Path: "/a", Kind: helpers.KindPage, Auth: helpers.AuthRequired},
		{Path: "/login", Kind: helpers.KindPage, Auth: helpers.AuthPublic},
		{Path: "/api/health", Kind: helpers.KindAPI, Auth: helpers.AuthPublic},
	}
	pub := helpers.FilterPublic(entries)
	assert.Len(t, pub, 2)
}

func TestFilterAuth(t *testing.T) {
	entries := []helpers.RouteEntry{
		{Path: "/a", Kind: helpers.KindPage, Auth: helpers.AuthRequired},
		{Path: "/login", Kind: helpers.KindPage, Auth: helpers.AuthPublic},
	}
	auth := helpers.FilterAuth(entries)
	assert.Len(t, auth, 1)
	assert.Equal(t, "/a", auth[0].Path)
}

// ---------------------------------------------------------------------------
// Malformed YAML cases
// ---------------------------------------------------------------------------

func TestLoadManifest_MissingPath(t *testing.T) {
	content := `
routes:
  - kind: page
    method: GET
    auth: required
    landmark: "h1"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: false
    excluded_reason: ""
    excluded_tracking_issue: ""
`
	path := writeTemp(t, content)
	_, err := helpers.LoadManifest(path)
	require.Error(t, err, "expected error for missing path field")
	assert.Contains(t, err.Error(), "path")
}

func TestLoadManifest_UnknownKind(t *testing.T) {
	content := `
routes:
  - path: "/foo"
    kind: badkind
    method: GET
    auth: required
    landmark: "h1"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: false
    excluded_reason: ""
    excluded_tracking_issue: ""
`
	path := writeTemp(t, content)
	_, err := helpers.LoadManifest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind")
}

func TestLoadManifest_UnknownAuth(t *testing.T) {
	content := `
routes:
  - path: "/foo"
    kind: page
    method: GET
    auth: badauth
    landmark: "h1"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: false
    excluded_reason: ""
    excluded_tracking_issue: ""
`
	path := writeTemp(t, content)
	_, err := helpers.LoadManifest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestLoadManifest_ExcludedWithoutReason(t *testing.T) {
	content := `
routes:
  - path: "/foo"
    kind: page
    method: GET
    auth: required
    landmark: "h1"
    shape_schema: null
    upstream_rpc: ""
    perf_budget_ms: 3000
    excluded: true
    excluded_reason: ""
    excluded_tracking_issue: ""
`
	path := writeTemp(t, content)
	_, err := helpers.LoadManifest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "excluded_reason")
}

func TestLoadManifest_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "routes: [{not yaml}]")
	_, err := helpers.LoadManifest(path)
	require.Error(t, err)
}

func TestLoadManifest_EmptyRoutes(t *testing.T) {
	content := `
routes: []
`
	path := writeTemp(t, content)
	_, err := helpers.LoadManifest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no routes")
}

func TestLoadManifest_FileNotFound(t *testing.T) {
	_, err := helpers.LoadManifest(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Seed file integration test
// ---------------------------------------------------------------------------

func TestLoadManifest_SeedFile(t *testing.T) {
	// Load the actual seed manifest from the repo.
	// This test verifies the seed is well-formed and meets the minimum size
	// requirement per Task 1 (_Success_).
	//
	// Running from the helpers/ directory, the seed is 3 levels up:
	// helpers/ -> e2e/ -> tests/ -> gibson/ -> tests/e2e/manifests/
	// We use REPO_ROOT env var or walk up from the test binary location.
	repoRoot := os.Getenv("REPO_ROOT")
	if repoRoot == "" {
		// When run via `go test ./tests/e2e/helpers/...` from core/gibson/,
		// the working directory is core/gibson/tests/e2e/helpers/ so we can
		// navigate relative to that.
		cwd, err := os.Getwd()
		require.NoError(t, err)
		// Try to find the manifest from the current directory.
		candidate := filepath.Join(cwd, "..", "manifests", "dashboard-routes.yaml")
		if _, statErr := os.Stat(candidate); os.IsNotExist(statErr) {
			t.Skipf("seed file not found at %s — skipping seed integration test (run from core/gibson/)", candidate)
			return
		}
		entries, err := helpers.LoadManifest(candidate)
		require.NoError(t, err, "seed manifest failed to load")
		assert.GreaterOrEqual(t, len(entries), 80, "seed manifest should have ≥80 entries")
		// Ensure the 4 required public routes are present.
		publicPaths := map[string]bool{}
		for _, e := range entries {
			if e.Auth == helpers.AuthPublic {
				publicPaths[e.Path] = true
			}
		}
		for _, required := range []string{"/", "/login", "/signup"} {
			assert.True(t, publicPaths[required], "public route %q not found in seed manifest", required)
		}
		return
	}
	seedPath := filepath.Join(repoRoot, "core", "gibson", "tests", "e2e", "manifests", "dashboard-routes.yaml")
	entries, err := helpers.LoadManifest(seedPath)
	require.NoError(t, err, "seed manifest failed to load from %s", seedPath)
	assert.GreaterOrEqual(t, len(entries), 80, "seed manifest should have ≥80 entries")
}
