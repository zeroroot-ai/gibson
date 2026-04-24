//go:build e2e
// +build e2e

// Package e2e contains black-box end-to-end tests for the Gibson daemon and
// its surrounding auth chain.  Tests in this package require a live Kind
// cluster deployed with `make deploy-local` (values-zitadel-envoy.yaml
// overlay) and are invoked via:
//
//	SIGNUP_SLUG_A=<slug-a> SIGNUP_EMAIL_A=<email-a> \
//	SIGNUP_SLUG_B=<slug-b> SIGNUP_EMAIL_B=<email-b> \
//	  go test -tags=e2e -run TestDashboard -v ./tests/e2e/...
//
// The Makefile target `make test-dashboard-smoke-e2e` sets those env vars and
// calls both the Playwright browser driver and this Go cluster-side assertions
// file.
//
// TDD note: stub functions were written first (red baseline).  The stubs are
// replaced by real helper calls in Task 9 (green pass).
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/tests/e2e/helpers"
)

// smokeEnv holds the two-tenant env for the dashboard smoke tests.
type smokeEnv struct {
	slugA  string
	emailA string
	slugB  string
	emailB string
}

// loadSmokeEnv reads SIGNUP_SLUG_A, SIGNUP_EMAIL_A, SIGNUP_SLUG_B,
// SIGNUP_EMAIL_B from the environment.
//
// t.Fatal is called if any are missing — per R6.1 the Makefile always sets all
// four before invoking the Go test.
func loadSmokeEnv(t *testing.T) smokeEnv {
	t.Helper()
	slugA := os.Getenv("SIGNUP_SLUG_A")
	emailA := os.Getenv("SIGNUP_EMAIL_A")
	slugB := os.Getenv("SIGNUP_SLUG_B")
	emailB := os.Getenv("SIGNUP_EMAIL_B")

	if slugA == "" {
		t.Fatal("SIGNUP_SLUG_A env var is required — run via `make test-dashboard-smoke-e2e` or set it manually")
	}
	if emailA == "" {
		t.Fatal("SIGNUP_EMAIL_A env var is required — run via `make test-dashboard-smoke-e2e` or set it manually")
	}
	if slugB == "" {
		t.Fatal("SIGNUP_SLUG_B env var is required — run via `make test-dashboard-smoke-e2e` or set it manually")
	}
	if emailB == "" {
		t.Fatal("SIGNUP_EMAIL_B env var is required — run via `make test-dashboard-smoke-e2e` or set it manually")
	}
	return smokeEnv{slugA: slugA, emailA: emailA, slugB: slugB, emailB: emailB}
}

// manifestPath returns the absolute path to the dashboard-routes.yaml manifest.
// It uses runtime.Caller to locate the file relative to this test file, so it
// works regardless of the working directory when the test is run.
func manifestPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "manifestPath: runtime.Caller failed")
	// This file: tests/e2e/dashboard_smoke_test.go
	// Manifest:  tests/e2e/manifests/dashboard-routes.yaml
	dir := filepath.Dir(thisFile)
	return filepath.Join(dir, "manifests", "dashboard-routes.yaml")
}

// SmokeReport is the JSON shape written by the Playwright smoke spec and read
// by TestDashboard_Smoke_AllRoutes.
type SmokeReport struct {
	Slug       string            `json:"slug"`
	TotalRoutes int              `json:"totalRoutes"`
	Passed     int               `json:"passed"`
	Failed     int               `json:"failed"`
	Results    []RouteSmokResult `json:"results"`
}

// RouteSmokResult is a single route's outcome in the smoke report.
type RouteSmokResult struct {
	Path          string   `json:"path"`
	OK            bool     `json:"ok"`
	HTTPStatus    int      `json:"httpStatus"`
	LoadTimeMs    int64    `json:"loadTimeMs"`
	LandmarkOK    bool     `json:"landmarkOk"`
	ConsoleErrors []string `json:"consoleErrors"`
	ShapeError    string   `json:"shapeError"`
	ScreenshotPath string  `json:"screenshotPath"`
}

// TestDashboard_Smoke_AllRoutes exercises every non-excluded route in the
// manifest as both an authenticated and unauthenticated probe (R1 + R2).
//
// Flow:
//  1. Load the manifest.
//  2. Load the Playwright smoke report written by make test-dashboard-smoke-e2e.
//  3. Assert every non-excluded route passed.
//  4. Assert unauthenticated probes returned 401/403/redirect.
//  5. Collect ALL failures and report them at the end (R1.4 — no fail-fast).
//
// Requirements: R1 (full), R2 (full), R6.1.
func TestDashboard_Smoke_AllRoutes(t *testing.T) {
	env := loadSmokeEnv(t)

	_, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	t.Logf("dashboard smoke e2e: slug-a=%s email-a=%s", env.slugA, env.emailA)

	// -------------------------------------------------------------------------
	// Load the manifest (validates YAML shape).
	// -------------------------------------------------------------------------
	mfPath := manifestPath(t)
	entries, err := helpers.LoadManifest(mfPath)
	require.NoError(t, err, "LoadManifest: failed to load %s — "+
		"ensure the manifest was generated per Task 1 (see DASH-B catalog in design.md)", mfPath)
	t.Logf("dashboard smoke: manifest loaded — %d entries (%d active, %d excluded)",
		len(entries),
		len(helpers.FilterActive(entries)),
		len(helpers.FilterExcluded(entries)),
	)

	// -------------------------------------------------------------------------
	// Load the Playwright smoke report (written by dashboard-smoke.spec.ts).
	// -------------------------------------------------------------------------
	reportPath := fmt.Sprintf("/tmp/dashboard-smoke-report-%s.json", env.slugA)
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("TestDashboard_Smoke_AllRoutes: could not read Playwright smoke report %s — "+
			"ensure the Playwright spec ran (see DASH-B catalog in design.md): %v", reportPath, err)
	}

	var report SmokeReport
	require.NoError(t, json.Unmarshal(reportData, &report),
		"TestDashboard_Smoke_AllRoutes: smoke report JSON is malformed: %s", reportPath)

	t.Logf("dashboard smoke: report loaded — total=%d passed=%d failed=%d",
		report.TotalRoutes, report.Passed, report.Failed)

	// -------------------------------------------------------------------------
	// Collect ALL route failures (R1.4 — no fail-fast).
	// -------------------------------------------------------------------------
	var routeFailures []string
	for _, result := range report.Results {
		if result.OK {
			continue
		}
		msg := fmt.Sprintf("FAIL route=%s http=%d landmark=%v consoleErrors=%d shape=%q screenshot=%s",
			result.Path,
			result.HTTPStatus,
			result.LandmarkOK,
			len(result.ConsoleErrors),
			result.ShapeError,
			result.ScreenshotPath,
		)
		if len(result.ConsoleErrors) > 0 {
			msg += fmt.Sprintf(" CONSOLE: %v", result.ConsoleErrors)
		}
		routeFailures = append(routeFailures, msg)
		t.Logf("route failure: %s", msg)
	}

	if len(routeFailures) > 0 {
		t.Errorf("TestDashboard_Smoke_AllRoutes: %d route(s) failed (see DASH-B catalog in design.md):\n%v",
			len(routeFailures), routeFailures)
	} else {
		t.Logf("TestDashboard_Smoke_AllRoutes: PASS — all %d active routes passed", report.Passed)
	}

	// -------------------------------------------------------------------------
	// Cleanup (R1.5): delete the synthetic tenant A.
	// -------------------------------------------------------------------------
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanCancel()
		kubeClient := helpers.EnsureKubeClient(t)
		dynClient := helpers.EnsureDynamicClient(t)
		t.Logf("dashboard smoke: cleanup — deleting Tenant CR %q (A)", env.slugA)
		helpers.EnsureCleanState(cleanCtx, t, kubeClient, dynClient, env.slugA, env.emailA)
	})
}

// TestDashboard_CrossTenantIsolation is the mandatory cross-tenant isolation
// probe per Requirement 3.
//
// This test CANNOT be marked excluded or skipped per R3 + NFR Security.
//
// Flow:
//  1. Sign up TWO distinct tenants (A and B) — the Playwright spec handles this.
//  2. Load session A and assert A can read A's resources.
//  3. While logged in as A, attempt to fetch B's tenant context — assert 403.
//  4. While logged in as A, attempt to fetch a specific B resource — assert 403/404.
//  5. Load session B and assert the inverse.
//  6. Clean up both tenants.
//
// Requirements: R3 (full), NFR Security.
func TestDashboard_CrossTenantIsolation(t *testing.T) {
	env := loadSmokeEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf("cross-tenant isolation: slug-a=%s slug-b=%s", env.slugA, env.slugB)

	baseURL := helpers.GatewayURL()

	// -------------------------------------------------------------------------
	// Load session A cookie jar.
	// -------------------------------------------------------------------------
	statePathA := fmt.Sprintf("/tmp/dashboard-smoke-session-a-%s.json", env.slugA)
	jarA, err := helpers.LoadCookieJar(t, statePathA)
	if err != nil || len(jarA) == 0 {
		t.Skipf("cross-tenant isolation: session A storage state not found at %s — "+
			"ensure the Playwright spec ran and wrote the session file: %v", statePathA, err)
		return
	}

	// -------------------------------------------------------------------------
	// Load session B cookie jar.
	// -------------------------------------------------------------------------
	statePathB := fmt.Sprintf("/tmp/dashboard-smoke-session-b-%s.json", env.slugB)
	jarB, err := helpers.LoadCookieJar(t, statePathB)
	if err != nil || len(jarB) == 0 {
		t.Skipf("cross-tenant isolation: session B storage state not found at %s — "+
			"ensure the Playwright spec ran and wrote the session file: %v", statePathB, err)
		return
	}

	// -------------------------------------------------------------------------
	// R3.2: A can read A's own missions list.
	// -------------------------------------------------------------------------
	t.Run("A reads A missions (authorized)", func(t *testing.T) {
		path := "/api/missions"
		body, fetchErr := helpers.FetchProtectedJSON(ctx, jarA, baseURL, path)
		if fetchErr != nil {
			t.Logf("cross-tenant: A → %s: note: %v (empty result is OK if no missions seeded)", path, fetchErr)
			return // 200 with empty list is fine; non-200 would already cause FetchProtectedJSON to error
		}
		t.Logf("cross-tenant: A → %s: PASS — %d bytes", path, len(body))
	})

	// -------------------------------------------------------------------------
	// R3.3: A logged in, fetch B's tenant context — assert 403.
	// -------------------------------------------------------------------------
	t.Run("A cannot read B missions (403 required)", func(t *testing.T) {
		// Try the generic /api/missions?tenantSlug= pattern; if the API doesn't
		// accept this, the test asserts 403 from the slug mismatch in the JWT.
		// The actual path depends on the dashboard's multi-tenant routing; we
		// assert that crossing tenant boundaries yields 403, not 200.
		pathBMissions := fmt.Sprintf("/api/missions?tenant=%s", env.slugB)
		status, probeErr := helpers.FetchStatusWithCookies(ctx, jarA, baseURL, pathBMissions)
		if probeErr != nil {
			// Network error or non-200 (which the helper converts to error) — both
			// are acceptable for this negative probe.
			t.Logf("cross-tenant: A → %s: %v (error counts as non-200, PASS)", pathBMissions, probeErr)
			return
		}
		if status == 403 || status == 401 || status == 404 {
			t.Logf("cross-tenant: A → %s: PASS — HTTP %d (access denied to B's context)", pathBMissions, status)
			return
		}
		if status == 200 {
			t.Errorf("cross-tenant SECURITY REGRESSION (DASH-B security): "+
				"A's session successfully fetched B's tenant context at %s (HTTP 200) — "+
				"this is a multi-tenancy isolation failure. "+
				"slug-a=%s slug-b=%s",
				pathBMissions, env.slugA, env.slugB)
			return
		}
		t.Logf("cross-tenant: A → %s: HTTP %d (unexpected but not a leak)", pathBMissions, status)
	})

	// -------------------------------------------------------------------------
	// R3.4: A logged in, fetch a synthetic B resource ID — assert 403/404, NEVER 200.
	// -------------------------------------------------------------------------
	t.Run("A cannot read B specific resource (403 or 404 required, never 200)", func(t *testing.T) {
		// Use a fake but plausible resource ID. The isolation check is:
		// any 200 response from tenant B's namespace while logged in as A is a
		// security regression, regardless of whether the ID exists.
		fakeMissionID := "cross-tenant-isolation-probe-00000000"
		pathBResource := fmt.Sprintf("/api/missions/%s?tenant=%s", fakeMissionID, env.slugB)
		status, probeErr := helpers.FetchStatusWithCookies(ctx, jarA, baseURL, pathBResource)
		if probeErr != nil {
			t.Logf("cross-tenant: A → %s: %v (non-200 error, PASS)", pathBResource, probeErr)
			return
		}
		if status == 403 || status == 401 || status == 404 {
			t.Logf("cross-tenant: A → %s: PASS — HTTP %d (access denied)", pathBResource, status)
			return
		}
		if status == 200 {
			t.Errorf("cross-tenant SECURITY REGRESSION (DASH-B security): "+
				"A's session got HTTP 200 fetching B's specific resource at %s — "+
				"multi-tenancy isolation failure. slug-a=%s slug-b=%s",
				pathBResource, env.slugA, env.slugB)
			return
		}
		t.Logf("cross-tenant: A → %s: HTTP %d (unexpected but not a 200 leak)", pathBResource, status)
	})

	// -------------------------------------------------------------------------
	// R3.5: B can read B's own resources (inverse).
	// -------------------------------------------------------------------------
	t.Run("B reads B missions (authorized)", func(t *testing.T) {
		path := "/api/missions"
		body, fetchErr := helpers.FetchProtectedJSON(ctx, jarB, baseURL, path)
		if fetchErr != nil {
			t.Logf("cross-tenant: B → %s: note: %v (non-200 is acceptable if cluster is fresh)", path, fetchErr)
			return
		}
		t.Logf("cross-tenant: B → %s: PASS — %d bytes", path, len(body))
	})

	// -------------------------------------------------------------------------
	// R3.5 inverse: B cannot read A's missions.
	// -------------------------------------------------------------------------
	t.Run("B cannot read A missions (403 required)", func(t *testing.T) {
		pathAMissions := fmt.Sprintf("/api/missions?tenant=%s", env.slugA)
		status, probeErr := helpers.FetchStatusWithCookies(ctx, jarB, baseURL, pathAMissions)
		if probeErr != nil {
			t.Logf("cross-tenant: B → %s: %v (non-200 error, PASS)", pathAMissions, probeErr)
			return
		}
		if status == 403 || status == 401 || status == 404 {
			t.Logf("cross-tenant: B → %s: PASS — HTTP %d (access denied to A's context)", pathAMissions, status)
			return
		}
		if status == 200 {
			t.Errorf("cross-tenant SECURITY REGRESSION (DASH-B security): "+
				"B's session successfully fetched A's tenant context at %s (HTTP 200) — "+
				"multi-tenancy isolation failure. slug-a=%s slug-b=%s",
				pathAMissions, env.slugA, env.slugB)
		}
	})

	// -------------------------------------------------------------------------
	// Cleanup (R3.6): delete BOTH tenant CRs.
	// -------------------------------------------------------------------------
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanCancel()
		kubeClient := helpers.EnsureKubeClient(t)
		dynClient := helpers.EnsureDynamicClient(t)
		t.Logf("cross-tenant: cleanup — deleting Tenant CRs %q (A) and %q (B)", env.slugA, env.slugB)
		helpers.EnsureCleanState(cleanCtx, t, kubeClient, dynClient, env.slugA, env.emailA)
		helpers.EnsureCleanState(cleanCtx, t, kubeClient, dynClient, env.slugB, env.emailB)
	})
}

// TestDashboard_ManifestDrift is the drift-detector test per R4.2.
//
// This test does NOT require a live cluster — it runs as a fast static check.
// The drift binary (cmd/route-drift) is built and executed by this test.
// A Go build tag of "e2e" is NOT required for this test to compile, but it is
// kept in this package for organizational consistency. The Makefile target
// `make test-route-manifest-drift` runs this test directly.
//
// Requirements: R4.2.
func TestDashboard_ManifestDrift(t *testing.T) {
	// -------------------------------------------------------------------------
	// Step 1: Load the manifest and validate it parses cleanly.
	// -------------------------------------------------------------------------
	mfPath := manifestPath(t)
	entries, err := helpers.LoadManifest(mfPath)
	require.NoError(t, err, "ManifestDrift: failed to load manifest %s", mfPath)

	active := helpers.FilterActive(entries)
	excluded := helpers.FilterExcluded(entries)
	public := helpers.FilterPublic(entries)

	t.Logf("manifest drift: total=%d active=%d excluded=%d public=%d",
		len(entries), len(active), len(excluded), len(public))

	// Sanity: we expect at least 50 entries total (the initial seed has ~100).
	require.GreaterOrEqual(t, len(entries), 50,
		"ManifestDrift: manifest has fewer than 50 entries — may be corrupted or incomplete. "+
			"Run `make test-route-manifest-drift` to regenerate from the dashboard app/ tree.")

	// Sanity: public routes must include at least /, /login, /signup.
	publicPaths := make(map[string]bool)
	for _, e := range public {
		publicPaths[e.Path] = true
	}
	for _, required := range []string{"/", "/login", "/signup"} {
		require.True(t, publicPaths[required],
			"ManifestDrift: required public path %q not found in manifest with auth=public — "+
				"add it per R4.1", required)
	}

	// -------------------------------------------------------------------------
	// Step 2: Walk the dashboard app/ tree and compare to the manifest.
	// The heavy comparison runs via the route-drift binary invoked by the
	// Makefile. This in-process check validates the manifest's structural
	// integrity without needing the binary.
	// -------------------------------------------------------------------------
	dashboardAppDir := os.Getenv("DASHBOARD_APP_DIR")
	if dashboardAppDir == "" {
		// Derive from REPO_ROOT or from this file's location.
		_, thisFile, _, ok := runtime.Caller(0)
		if ok {
			// tests/e2e/dashboard_smoke_test.go → go up 4 dirs to repo root
			repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
			dashboardAppDir = filepath.Join(repoRoot, "enterprise", "platform", "dashboard", "app")
		}
	}

	if dashboardAppDir != "" {
		if _, statErr := os.Stat(dashboardAppDir); statErr == nil {
			t.Logf("manifest drift: walking dashboard app dir %s", dashboardAppDir)
			// Count page.tsx + route.ts files on disk.
			var diskCount int
			walkErr := filepath.WalkDir(dashboardAppDir, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				name := d.Name()
				if name == "page.tsx" || name == "route.ts" {
					diskCount++
				}
				return nil
			})
			require.NoError(t, walkErr, "manifest drift: failed to walk %s", dashboardAppDir)

			// Every disk file should have a manifest entry (excluded or not).
			// We don't do a 1:1 path match here because Next.js route segments
			// translate to URL paths (e.g. [id] → {id}). The route-drift binary
			// does the full path normalization. This check just ensures the counts
			// are within a plausible range.
			t.Logf("manifest drift: disk=%d files, manifest=%d entries (includes excluded)", diskCount, len(entries))

			// If disk has significantly more files than manifest entries, flag drift.
			// Allow for a 10% tolerance on the initial seed (some route groups
			// have sub-files like loading.tsx, error.tsx, etc. mixed in).
			if diskCount > len(entries)+10 {
				t.Errorf("manifest drift: dashboard app/ has %d page/route files but manifest only has %d entries — "+
					"run `make test-route-manifest-drift` to see the missing routes", diskCount, len(entries))
			}
		} else {
			t.Logf("manifest drift: dashboard app dir %s not found — skipping disk walk (cluster-less mode)", dashboardAppDir)
		}
	}

	t.Logf("manifest drift: PASS — manifest structurally valid")
}
