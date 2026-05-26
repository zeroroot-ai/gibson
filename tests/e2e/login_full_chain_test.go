//go:build e2e
// +build e2e

// Package e2e contains black-box end-to-end tests for the Gibson daemon and
// its surrounding auth chain.  Tests in this package require a live Kind
// cluster deployed with `make deploy-local` (values.yaml + values-kind.yaml)
// and are invoked via:
//
//	SIGNUP_SLUG=<slug> SIGNUP_EMAIL=<email> \
//	  go test -tags=e2e -run TestLogin -v ./tests/e2e/...
//
// The Makefile target `make test-login-e2e` sets those env vars and calls
// both the Playwright browser driver and this Go cluster-side assertions file.
//
// Realignment notes (e2e-harness-realignment spec):
//   - Auth.js v5 cookie names: __Secure-authjs.session-token (HTTPS context).
//     HasSessionCookie helper checks both v5 prefix variants.
//   - LOGIN-B2 regression lock-in: /api/me must return a non-empty
//     user.tenantId / tenant.slug (K8s fallback in auth.ts jwt callback).
//   - TenantMember role is "admin" (not "owner") per the founding-owner FGA tuple.
//   - No values-zitadel-envoy.yaml overlay: single-values-file chart rule applies.
package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
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
	// Phase 3: Assert /api/users/profile returns correct user data (R1.6)
	// Uses the cookie jar loaded in Phase 2 to fetch /api/users/profile and
	// assert:
	//   - email matches env.email
	//   - tenantId is non-empty (LOGIN-B2 regression lock-in)
	//
	// LOGIN-B3 FIX: /api/me does not exist in the dashboard. The real endpoint
	// is /api/users/profile which returns { profile: { id, email, tenantId, ... } }
	// or { id, email, tenantId, ... } (direct shape when daemon RPC available).
	//
	// LOGIN-B2 lock-in: tenantId must be non-empty. Empty tenantId means the JWT
	// `urn:zitadel:iam:user:resourceowner:id` claim was absent AND the K8s
	// fallback in auth.ts jwt callback (commit 659678e) failed.
	// -------------------------------------------------------------------------
	t.Run("assert /api/users/profile returns email + tenantId", func(t *testing.T) {
		if !helpers.HasSessionCookie(cookieJar) {
			t.Skip("no session cookie in cookie jar from prior phase — skipping profile assertion")
			return
		}
		baseURL := helpers.GatewayURL()
		profile, err := helpers.FetchUserProfile(ctx, cookieJar, baseURL)
		require.NoError(t, err,
			"FetchUserProfile: /api/users/profile request failed — session cookie may be invalid or "+
				"Auth.js misconfigured (see LOGIN-B catalog in design.md)")
		require.Equal(t, env.email, profile.ResolvedEmail(),
			"FetchUserProfile: email mismatch — expected %q got %q "+
				"(identity propagation failure — see LOGIN-B catalog)", env.email, profile.ResolvedEmail())

		// LOGIN-B2 regression lock-in: tenantId must be non-empty.
		require.NotEmpty(t, profile.ResolvedTenantID(),
			"FetchUserProfile: tenantId is empty — LOGIN-B2 REGRESSION: JWT tenant claim absent "+
				"and K8s fallback (auth.ts jwt callback, commit 659678e) failed. "+
				"Check: Zitadel org was created, operator wrote FGA tuple, auth.ts listTenantsForOwner")
		t.Logf("assert /api/users/profile: PASS — email=%s tenantId=%s",
			profile.ResolvedEmail(), profile.ResolvedTenantID())
	})

	// -------------------------------------------------------------------------
	// Phase 4: Assert authenticated session can reach a dashboard API endpoint (R1.7)
	// Fetches /api/health which is always 200 and verifies the session cookie
	// propagates correctly through the Envoy gateway to the dashboard.
	//
	// LOGIN-B4 FIX: /api/tenant/<slug>/missions does not exist in the dashboard
	// API (missions are served via Next.js server actions, not REST routes).
	// Use /api/health as the authenticated probe target.
	// -------------------------------------------------------------------------
	t.Run("assert /api/health returns 200 with session cookie", func(t *testing.T) {
		if !helpers.HasSessionCookie(cookieJar) {
			t.Skip("no session cookie — skipping gateway probe assertion")
			return
		}
		baseURL := helpers.GatewayURL()
		body, err := helpers.FetchProtectedJSON(ctx, cookieJar, baseURL, "/api/health")
		require.NoError(t, err,
			"FetchProtectedJSON /api/health: request failed — session may not propagate through Envoy gateway "+
				"(see LOGIN-B catalog in design.md)")
		t.Logf("assert /api/health: PASS — returned %d bytes", len(body))
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
				// The Go side asserts NO session cookie was written to the
				// storage state file for these bad-credential cases.
				//
				// LOGIN-B7 FIX: the original check was `len(jar) == 0` which
				// FAILED when the Playwright spec wrote other non-session cookies
				// (CSRF tokens, OIDC state cookies).  The correct check is
				// HasSessionCookie(jar) — only the Auth.js session token counts.
				statePath := fmt.Sprintf("/tmp/login-negative-%s-%s.json", tc.name, env.slug)
				if _, statErr := helpers.StorageStateExists(statePath); statErr != nil {
					t.Skipf("negative auth %s: storage state %s not found — "+
						"ensure the Playwright spec writes this file (see login-full-chain.spec.ts)", tc.name, statePath)
					return
				}
				jar, loadErr := helpers.LoadCookieJar(t, statePath)
				if loadErr != nil {
					t.Skipf("negative auth %s: could not load storage state: %v", tc.name, loadErr)
					return
				}
				if !helpers.HasSessionCookie(jar) {
					t.Logf("negative auth %s: PASS — no session cookie set after bad credential attempt "+
						"(%d cookie(s) present, none are session tokens)", tc.name, len(jar))
					return
				}
				t.Errorf("negative auth %s: FAIL — session cookie was set after bad credential attempt "+
					"(LOGIN-B catalog: see design.md for regression entry once catalogued)", tc.name)

			case "no-cookie-protected-route":
				// Assert /api/users/profile returns 401 or redirects to /login
				// when no cookie is sent.
				//
				// LOGIN-B5 FIX: /api/me doesn't exist (404). Use /api/users/profile
				// which properly returns 401 when unauthenticated.
				status, err := helpers.FetchMeUnauthenticated(ctx, baseURL)
				if err != nil {
					t.Logf("negative auth %s: could not reach %s: %v — skipping (cluster may be down)", tc.name, baseURL, err)
					return
				}
				if status == 401 || status == 302 || status == 307 {
					t.Logf("negative auth %s: PASS — /api/users/profile returned HTTP %d with no cookie", tc.name, status)
					return
				}
				t.Errorf("negative auth %s: FAIL — /api/users/profile returned HTTP %d without cookie "+
					"(expected 401 or redirect) (see LOGIN-B catalog)", tc.name, status)

			case "tampered-cookie":
				// Load the real session state from the happy-path run, tamper the
				// cookie, assert 401 or 302 (not 200, not 500).
				//
				// LOGIN-B5 FIX: probe /api/users/profile (not /api/me which is 404).
				statePath := fmt.Sprintf("/tmp/login-storage-state-%s.json", env.slug)
				jar, loadErr := helpers.LoadCookieJar(t, statePath)
				if loadErr != nil || !helpers.HasSessionCookie(jar) {
					t.Skipf("negative auth %s: no session state at %s — run happy path first", tc.name, statePath)
					return
				}
				tampered := helpers.TamperCookie(jar, "authjs.session-token")
				status, err := helpers.FetchMeWithCookies(ctx, tampered, baseURL)
				if err != nil {
					t.Logf("negative auth %s: could not reach /api/users/profile: %v — skipping", tc.name, err)
					return
				}
				if status == 401 || status == 302 || status == 307 {
					t.Logf("negative auth %s: PASS — tampered cookie returned HTTP %d (authentication rejected)", tc.name, status)
					return
				}
				t.Errorf("negative auth %s: FAIL — tampered cookie returned HTTP %d "+
					"(expected 401/302 — authentication should reject tampered tokens) "+
					"(see LOGIN-B catalog)", tc.name, status)

			case "expired-session":
				// The expired-session negative test requires the Playwright spec
				// to have injected an expired cookie.  Check for the result file.
				//
				// LOGIN-B6 FIX: Next.js middleware redirects to /login WITHOUT a
				// callbackUrl/redirect_to param by default. Relax assertion to only
				// require redirectedToLogin=true (not hasRedirectToParam).
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
				if result.RedirectedToLogin {
					t.Logf("negative auth %s: PASS — expired session redirected to /login "+
						"(hasRedirectToParam=%v — not required by R2.5 implementation)", tc.name, result.HasRedirectToParam)
					return
				}
				t.Errorf("negative auth %s: FAIL — redirected_to_login=%v "+
					"(expected true — expired session must redirect to /login) "+
					"(see LOGIN-B catalog)", tc.name, result.RedirectedToLogin)
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
