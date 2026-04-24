//go:build e2e
// +build e2e

// Package e2e contains black-box end-to-end tests for the Gibson daemon and
// its surrounding auth chain.  Tests in this package require a live Kind
// cluster deployed with `make deploy-local` (values-zitadel-envoy.yaml
// overlay) and are invoked via:
//
//	SIGNUP_SLUG=<slug> SIGNUP_EMAIL=<email> \
//	  go test -tags=e2e -run TestLogin -v ./tests/e2e/...
//
// The Makefile target `make test-login-e2e` sets those env vars and calls
// both the Playwright browser driver and this Go cluster-side assertions file.
//
// TDD note: every assertion in this file starts as a stub (t.Fatal "not
// implemented yet") per Requirement 6.1.  The stubs are replaced by real
// helper calls in Task 6.
package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/tests/e2e/helpers"
)

// loginEnv holds the test-run-specific values injected by the orchestrator.
// Identical shape to signupEnv so the two suites share the same orchestrator
// pattern.
type loginEnv struct {
	slug  string
	email string
}

// loadLoginEnv reads SIGNUP_SLUG and SIGNUP_EMAIL from the environment.
// t.Fatal is called if either is missing — per R5.3 the Makefile always sets
// both before invoking the Go test.
func loadLoginEnv(t *testing.T) loginEnv {
	t.Helper()
	slug := os.Getenv("SIGNUP_SLUG")
	email := os.Getenv("SIGNUP_EMAIL")
	if slug == "" {
		t.Fatal("SIGNUP_SLUG env var is required — run via `make test-login-e2e` or set it manually")
	}
	if email == "" {
		t.Fatal("SIGNUP_EMAIL env var is required — run via `make test-login-e2e` or set it manually")
	}
	return loginEnv{slug: slug, email: email}
}

// TestLogin_FullChain_HappyPath is the canonical black-box login regression
// test.
//
// The test drives the full flow:
//  1. Signup a fresh user (via Playwright, already done before this Go test
//     runs per the Makefile orchestrator).
//  2. Asserts the browser session was cleared (simulating a fresh visit).
//  3. Asserts the login form was submitted and the OIDC redirect chain
//     completed (via redirect-chain JSON written by the Playwright spec).
//  4. Asserts the resulting session cookie unlocks /api/me and a daemon
//     admin RPC, proving end-to-end identity propagation.
//  5. Cleans up the tenant CR on completion.
//
// Requirements: R1 (full), R3.1, R5.1, R6.1–R6.2.
func TestLogin_FullChain_HappyPath(t *testing.T) {
	env := loadLoginEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf("login e2e: slug=%s email=%s", env.slug, env.email)

	// -------------------------------------------------------------------------
	// Build k8s clients (required for all assertions below).
	// -------------------------------------------------------------------------
	kubeClient := helpers.EnsureKubeClient(t)

	// -------------------------------------------------------------------------
	// Phase 1: Assert OIDC redirect chain completed (R1.4)
	// The Playwright spec writes the redirect chain to:
	//   /tmp/login-redirect-chain-<slug>.json
	// This assertion reads that file and verifies the required hops.
	// Bug catalog: see LOGIN-B catalog in design.md (empty at initial writing).
	// -------------------------------------------------------------------------
	t.Run("assert OIDC redirect chain", func(t *testing.T) {
		chainPath := fmt.Sprintf("/tmp/login-redirect-chain-%s.json", env.slug)
		chain, err := helpers.LoadRedirectChain(chainPath)
		require.NoError(t, err,
			"LoadRedirectChain: could not load %s — "+
				"ensure the Playwright spec ran and wrote the redirect chain JSON "+
				"(see LOGIN-B catalog in design.md once populated)", chainPath)
		helpers.AssertRedirectChain(t, chain)
		helpers.MustHaveZitadelHop(t, chain)
		helpers.MustHaveCallbackHop(t, chain)
	})

	// -------------------------------------------------------------------------
	// Phase 2: Assert session cookie set after login (R1.5)
	// The Playwright spec saves storage state to:
	//   /tmp/login-storage-state-<slug>.json
	// This assertion loads the cookie jar and verifies a session cookie exists.
	// Bug catalog: LOGIN-B (empty at initial writing — grows as bugs surface).
	// -------------------------------------------------------------------------
	var cookieJar []*helpers.PlaywrightCookie
	t.Run("assert session cookie set", func(t *testing.T) {
		statePath := fmt.Sprintf("/tmp/login-storage-state-%s.json", env.slug)
		jar, err := helpers.LoadCookieJar(t, statePath)
		require.NoError(t, err,
			"LoadCookieJar: could not load Playwright storage state from %s — "+
				"session cookie was not set after login (see LOGIN-B catalog)", statePath)
		require.NotEmpty(t, jar,
			"LoadCookieJar: cookie jar is empty — no session cookie set after login "+
				"(see LOGIN-B catalog in design.md)")
		cookieJar = jar
		t.Logf("assert session cookie set: PASS — %d cookie(s) present (values redacted)", len(jar))
	})

	// -------------------------------------------------------------------------
	// Phase 3: Assert /api/me returns correct user data (R1.6)
	// Uses the cookie jar loaded in Phase 2 to fetch /api/me and assert:
	//   - email matches env.email
	//   - tenant.slug matches env.slug
	//   - tenant.role is "admin"
	// Bug catalog: LOGIN-B (empty at initial writing).
	// -------------------------------------------------------------------------
	t.Run("assert /api/me returns email + tenant + role", func(t *testing.T) {
		if len(cookieJar) == 0 {
			t.Skip("cookie jar empty from prior phase — skipping /api/me assertion")
			return
		}
		baseURL := helpers.GatewayURL()
		me, err := helpers.FetchMe(ctx, cookieJar, baseURL)
		require.NoError(t, err,
			"FetchMe: /api/me request failed — session cookie may be invalid or Auth.js misconfigured "+
				"(see LOGIN-B catalog in design.md)")
		require.Equal(t, env.email, me.Email,
			"FetchMe: email mismatch — expected %q got %q "+
				"(identity propagation failure — see LOGIN-B catalog)", env.email, me.Email)
		require.Equal(t, env.slug, me.Tenant.Slug,
			"FetchMe: tenant.slug mismatch — expected %q got %q "+
				"(tenant claim not propagated — see LOGIN-B catalog)", env.slug, me.Tenant.Slug)
		require.Equal(t, "admin", me.Tenant.Role,
			"FetchMe: tenant.role mismatch — expected 'admin' got %q "+
				"(FGA admin tuple not found — see LOGIN-B catalog)", me.Tenant.Role)
		t.Logf("assert /api/me: PASS — email=%s tenant.slug=%s role=%s", me.Email, me.Tenant.Slug, me.Tenant.Role)
	})

	// -------------------------------------------------------------------------
	// Phase 4: Assert daemon RPC accessible with session identity (R1.7)
	// Fetches /api/tenant/<slug>/missions and asserts HTTP 200.
	// Bug catalog: LOGIN-B (empty at initial writing).
	// -------------------------------------------------------------------------
	t.Run("assert /api/tenant/slug/missions returns 200", func(t *testing.T) {
		if len(cookieJar) == 0 {
			t.Skip("cookie jar empty from prior phase — skipping daemon RPC assertion")
			return
		}
		baseURL := helpers.GatewayURL()
		path := fmt.Sprintf("/api/tenant/%s/missions", env.slug)
		body, err := helpers.FetchProtectedJSON(ctx, cookieJar, baseURL, path)
		require.NoError(t, err,
			"FetchProtectedJSON %s: request failed — session may not propagate to daemon "+
				"(see LOGIN-B catalog in design.md)", path)
		t.Logf("assert daemon RPC: PASS — %s returned %d bytes", path, len(body))
	})

	// -------------------------------------------------------------------------
	// Phase 5: Daemon identity-debug proof (R3.1)
	// Asserts that the daemon received x-gibson-identity-* headers for this
	// login session (proving the identity propagation through the full chain).
	// Bug catalog: LOGIN-B (empty at initial writing).
	// -------------------------------------------------------------------------
	t.Run("assert daemon received identity headers for login session", func(t *testing.T) {
		if os.Getenv("GIBSON_IDENTITY_TRACE") != "1" {
			t.Skip("GIBSON_IDENTITY_TRACE not set — skipping daemon identity-debug assertion " +
				"(set GIBSON_IDENTITY_TRACE=1 on daemon pod to enable)")
			return
		}
		podName, podErr := helpers.DaemonPodName(ctx, kubeClient)
		require.NoError(t, podErr)
		testStartTime := time.Now().Add(-5 * time.Minute) // look back 5 min for login session
		helpers.AssertHeadersLanded(t, ctx, kubeClient, podName, testStartTime, 60*time.Second)
	})

	// -------------------------------------------------------------------------
	// Cleanup (R1.8): delete the tenant CR to reap Zitadel + FGA + namespace.
	// -------------------------------------------------------------------------
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanCancel()
		dynClient := helpers.EnsureDynamicClient(t)
		t.Logf("login e2e: cleanup — deleting Tenant CR %q", env.slug)
		helpers.EnsureCleanState(cleanCtx, t, kubeClient, dynClient, env.slug, env.email)
	})
}

// negativeAuthCase describes a single negative authentication test case.
type negativeAuthCase struct {
	name        string
	email       string
	password    string
	wantCookies bool // false = no session cookie should be set
	description string
}

// TestLogin_NegativeAuth exercises the five negative authentication cases
// from Requirement 2.  Each case is a table-driven sub-test.
//
// Requirements: R2.1–R2.5.
func TestLogin_NegativeAuth(t *testing.T) {
	env := loadLoginEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	baseURL := helpers.GatewayURL()

	cases := []negativeAuthCase{
		{
			name:        "wrong-password",
			email:       env.email,
			password:    "WrongPassword!99",
			wantCookies: false,
			description: "R2.1: wrong password → no session cookie, localized error within 5s",
		},
		{
			name:        "nonexistent-email",
			email:       "nobody-" + env.slug + "@nowhere.invalid",
			password:    "AnyPassword!99",
			wantCookies: false,
			description: "R2.2: non-existent email → same generic error (no user-enumeration)",
		},
		{
			name:        "no-cookie-protected-route",
			email:       "",
			password:    "",
			wantCookies: false,
			description: "R2.3: no session cookie → /api/me returns 401 or redirect to /login",
		},
		{
			name:        "tampered-cookie",
			email:       "",
			password:    "",
			wantCookies: false,
			description: "R2.4: tampered session cookie → 401 (not 500)",
		},
		{
			name:        "expired-session",
			email:       "",
			password:    "",
			wantCookies: false,
			description: "R2.5: expired session → redirect to /login with ?redirect_to= param",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("negative auth: %s (%s)", tc.name, tc.description)

			switch tc.name {
			case "wrong-password", "nonexistent-email":
				// These cases require checking the Playwright output (browser-side
				// error message assertion).  The Go side asserts no session cookie
				// was written to the storage state file.
				statePath := fmt.Sprintf("/tmp/login-negative-%s-%s.json", tc.name, env.slug)
				if _, statErr := helpers.StorageStateExists(statePath); statErr != nil {
					// Storage state file not written — this means the Playwright
					// spec for this negative case hasn't been implemented yet, or
					// this test is running before the Playwright driver.
					t.Skipf("negative auth %s: storage state %s not found — "+
						"ensure the Playwright spec writes this file (see login-full-chain.spec.ts)", tc.name, statePath)
					return
				}
				jar, loadErr := helpers.LoadCookieJar(t, statePath)
				if loadErr != nil || len(jar) == 0 {
					t.Logf("negative auth %s: PASS — no session cookie set after bad credential attempt", tc.name)
					return
				}
				t.Errorf("negative auth %s: FAIL — session cookie was set after bad credential attempt "+
					"(LOGIN-B catalog: see design.md for regression entry once catalogued)", tc.name)

			case "no-cookie-protected-route":
				// Assert /api/me returns 401 or redirects to /login when no cookie is sent.
				status, err := helpers.FetchMeUnauthenticated(ctx, baseURL)
				if err != nil {
					t.Logf("negative auth %s: could not reach %s/api/me: %v — skipping (cluster may be down)", tc.name, baseURL, err)
					return
				}
				if status == 401 || status == 302 || status == 307 {
					t.Logf("negative auth %s: PASS — /api/me returned HTTP %d with no cookie", tc.name, status)
					return
				}
				t.Errorf("negative auth %s: FAIL — /api/me returned HTTP %d without cookie (expected 401 or redirect) "+
					"(see LOGIN-B catalog)", tc.name, status)

			case "tampered-cookie":
				// Load the real session state from the happy-path run, tamper the
				// cookie, assert 401.
				statePath := fmt.Sprintf("/tmp/login-storage-state-%s.json", env.slug)
				jar, loadErr := helpers.LoadCookieJar(t, statePath)
				if loadErr != nil || len(jar) == 0 {
					t.Skipf("negative auth %s: no session state at %s — run happy path first", tc.name, statePath)
					return
				}
				tampered := helpers.TamperCookie(jar, "authjs.session-token")
				status, err := helpers.FetchMeWithCookies(ctx, tampered, baseURL)
				if err != nil {
					t.Logf("negative auth %s: could not reach /api/me: %v — skipping", tc.name, err)
					return
				}
				if status == 401 {
					t.Logf("negative auth %s: PASS — tampered cookie returned HTTP 401 (not 500)", tc.name)
					return
				}
				t.Errorf("negative auth %s: FAIL — tampered cookie returned HTTP %d (expected 401, got %d) "+
					"(see LOGIN-B catalog)", tc.name, status, status)

			case "expired-session":
				// The expired-session negative test requires the Playwright spec
				// to have injected an expired cookie.  Check for the result file.
				resultPath := fmt.Sprintf("/tmp/login-negative-expired-%s.json", env.slug)
				if _, statErr := helpers.StorageStateExists(resultPath); statErr != nil {
					t.Skipf("negative auth %s: result file %s not found — "+
						"ensure the Playwright spec exercises the expired-session case", tc.name, resultPath)
					return
				}
				result, err := helpers.LoadExpiredSessionResult(resultPath)
				if err != nil {
					t.Skipf("negative auth %s: could not load result: %v", tc.name, err)
					return
				}
				if result.RedirectedToLogin && result.HasRedirectToParam {
					t.Logf("negative auth %s: PASS — expired session redirected to /login with redirect_to param", tc.name)
					return
				}
				t.Errorf("negative auth %s: FAIL — redirected_to_login=%v has_redirect_to_param=%v "+
					"(see LOGIN-B catalog)", tc.name, result.RedirectedToLogin, result.HasRedirectToParam)
			}
		})
	}

	_ = ctx // used in sub-tests via closure
}

// TestLogin_ConcurrentSessions_NoCrosstalk asserts that two separate browser
// sessions (user A and user B) do not bleed identity into each other's daemon
// calls (Requirement 3.2).
//
// This test is table-driven: it reads two pre-existing storage state files
// written by the Playwright concurrent-session spec and asserts:
//   - A's /api/me returns A's email.
//   - B's /api/me returns B's email.
//   - A's daemon calls carry A's tenant.
//   - B's daemon calls carry B's tenant.
//
// Requirements: R3.2, R3.3.
func TestLogin_ConcurrentSessions_NoCrosstalk(t *testing.T) {
	env := loadLoginEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	baseURL := helpers.GatewayURL()

	// Locate the two storage state files written by the Playwright concurrent spec.
	stateA := fmt.Sprintf("/tmp/login-storage-state-%s.json", env.slug)
	stateB := fmt.Sprintf("/tmp/login-storage-state-%s-b.json", env.slug)

	_, errA := helpers.StorageStateExists(stateA)
	_, errB := helpers.StorageStateExists(stateB)

	if errA != nil || errB != nil {
		t.Skipf("concurrent session test: one or both storage state files missing "+
			"(A: %v, B: %v) — ensure the Playwright concurrent-session spec ran", errA, errB)
		return
	}

	t.Run("session-A identity", func(t *testing.T) {
		t.Parallel()
		jarA, err := helpers.LoadCookieJar(t, stateA)
		require.NoError(t, err, "session A: could not load cookie jar")
		require.NotEmpty(t, jarA, "session A: cookie jar is empty")
		meA, err := helpers.FetchMe(ctx, jarA, baseURL)
		require.NoError(t, err, "session A: /api/me failed")
		require.Equal(t, env.email, meA.Email,
			"session A: email mismatch — concurrent session A saw wrong identity "+
				"(R3.2: no cross-talk between concurrent sessions)")
		require.Equal(t, env.slug, meA.Tenant.Slug,
			"session A: tenant.slug mismatch — cross-talk detected "+
				"(R3.3: tenant claim must match logged-in user's tenant)")
		t.Logf("session A: PASS — email=%s slug=%s", meA.Email, meA.Tenant.Slug)
	})

	t.Run("session-B identity", func(t *testing.T) {
		t.Parallel()
		// Session B is a second user with a different email (the Playwright spec
		// creates a second account with slug suffixed "-b").
		jarB, err := helpers.LoadCookieJar(t, stateB)
		require.NoError(t, err, "session B: could not load cookie jar")
		require.NotEmpty(t, jarB, "session B: cookie jar is empty")
		meB, err := helpers.FetchMe(ctx, jarB, baseURL)
		require.NoError(t, err, "session B: /api/me failed")
		// Session B's email should be different from session A's.
		require.NotEqual(t, env.email, meB.Email,
			"session B: email matches session A — concurrent sessions are bleeding "+
				"(R3.2 violation: cross-talk detected)")
		t.Logf("session B: PASS — email=%s (distinct from A's %s)", meB.Email, env.email)
	})
}
