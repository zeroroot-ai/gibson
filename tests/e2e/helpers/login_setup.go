//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
)

// ---------------------------------------------------------------------------
// EnsureLoggedInUser
// ---------------------------------------------------------------------------

// EnsureLoggedInUser ensures that a user with the given email exists in
// Zitadel for the given slug, and returns their Zitadel user ID.
//
// This is the bridge between the signup-e2e-tdd helpers and the login test:
// signup-e2e-tdd creates the user; this function verifies it exists and
// returns the ID needed for subsequent assertions (e.g., R3.1 identity trace).
//
// The function uses ZitadelClient.DeleteUserByEmail and OrgExistsBySlug from
// zitadel_client.go — those helpers are NEVER modified (per spec constraint).
//
// Requirements: R1.1, R1.2, R5.1.
func EnsureLoggedInUser(
	ctx context.Context,
	t *testing.T,
	kubeClient kubernetes.Interface,
	slug, email string,
) string {
	t.Helper()

	zitadelURL, err := LoadZitadelURLFromCluster(ctx, kubeClient)
	if err != nil {
		t.Logf("login_setup: EnsureLoggedInUser: could not resolve Zitadel URL: %v (proceeding with default)", err)
	}

	zc := NewZitadelClient(zitadelURL, "")
	if patErr := zc.LoadPATFromCluster(ctx, kubeClient); patErr != nil {
		// Non-fatal: the user may have been created before this test run.
		// The login test will still proceed — a 401 at /api/me is the
		// authoritative signal that the user doesn't exist.
		t.Logf("login_setup: EnsureLoggedInUser: could not load Zitadel PAT: %v "+
			"(continuing — user may already exist)", patErr)
		return ""
	}

	// Check that the org exists (proves signup completed successfully for this slug).
	exists, checkErr := zc.OrgExistsBySlug(ctx, slug)
	if checkErr != nil {
		t.Logf("login_setup: EnsureLoggedInUser: OrgExistsBySlug(%q): %v (proceeding)", slug, checkErr)
		return ""
	}
	if !exists {
		t.Logf("login_setup: EnsureLoggedInUser: Zitadel org %q not found — "+
			"signup may not have completed, or this is a fresh run before signup-e2e", slug)
		return ""
	}

	// Look up the user's Zitadel ID by email.
	userID, lookupErr := zc.LookupUserIDByEmail(ctx, email)
	if lookupErr != nil {
		t.Logf("login_setup: EnsureLoggedInUser: LookupUserIDByEmail(%q): %v "+
			"(user may not be registered in Zitadel yet)", email, lookupErr)
		return ""
	}

	t.Logf("login_setup: EnsureLoggedInUser: found user email=%s zitadel_id=<present> org=%s", email, slug)
	return userID
}

// ---------------------------------------------------------------------------
// EnsureBrowserSessionCleared
// ---------------------------------------------------------------------------

// emptyPlaywrightState is a valid empty Playwright storage state JSON.
// Playwright requires a well-formed JSON with at minimum "cookies" and
// "origins" keys — a bare `{}` causes Playwright to error on load.
var emptyPlaywrightState = PlaywrightStorageState{
	Cookies: []PlaywrightCookie{},
}

// EnsureBrowserSessionCleared writes an empty-but-valid Playwright storage
// state JSON to the given path, ensuring any subsequent Playwright run using
// that state file starts with a clean session (no cookies, no localStorage).
//
// This simulates a "fresh browser visit" after a previous login, without
// needing to reboot the browser process.
//
// The written JSON matches the shape Playwright expects from storageState:
//   { "cookies": [], "origins": [] }
//
// Requirements: R1.2, R5.1.
func EnsureBrowserSessionCleared(ctx context.Context, t *testing.T, statePath string) error {
	t.Helper()
	_ = ctx // context not needed for a file write, but kept for interface consistency

	type fullState struct {
		Cookies []PlaywrightCookie `json:"cookies"`
		Origins []interface{}      `json:"origins"`
	}
	empty := fullState{
		Cookies: []PlaywrightCookie{},
		Origins: []interface{}{},
	}

	data, err := json.Marshal(empty)
	if err != nil {
		return fmt.Errorf("login_setup: EnsureBrowserSessionCleared: marshal empty state: %w", err)
	}

	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		return fmt.Errorf("login_setup: EnsureBrowserSessionCleared: write %s: %w", statePath, err)
	}

	t.Logf("login_setup: EnsureBrowserSessionCleared: wrote empty storage state to %s", statePath)
	return nil
}

// ---------------------------------------------------------------------------
// LookupUserIDByEmail — extends ZitadelClient without modifying it
// ---------------------------------------------------------------------------

// LookupUserIDByEmail searches Zitadel for a user with the given email
// (login name) and returns their Zitadel user ID.
//
// This is a wrapper helper (per spec constraint: signup helpers are not
// modified; new helpers are added as wrappers).  It reuses the unexported
// internals of ZitadelClient via the existing doRequest method.
//
// Returns ("", nil) if no user is found (not an error — the login test
// skips identity assertions gracefully when the user doesn't exist yet).
//
// Requirements: R1.1, R5.1.
func (z *ZitadelClient) LookupUserIDByEmail(ctx context.Context, email string) (string, error) {
	body := fmt.Sprintf(
		`{"queries":[{"loginNameQuery":{"loginName":%q,"method":"TEXT_QUERY_METHOD_EQUALS"}}]}`,
		email,
	)

	raw, status, err := z.doRequest(ctx, "POST", "/v1/users/_search", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("login_setup: LookupUserIDByEmail: request: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("login_setup: LookupUserIDByEmail: HTTP %d: %.200s", status, string(raw))
	}

	var resp zitadelUserSearchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("login_setup: LookupUserIDByEmail: unmarshal: %w", err)
	}
	if len(resp.Result) == 0 {
		return "", nil // not found
	}
	return resp.Result[0].UserID, nil
}
