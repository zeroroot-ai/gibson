//go:build e2e
// +build e2e

package helpers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// RedirectStep — one hop in the OIDC redirect chain
// ---------------------------------------------------------------------------

// RedirectStep is a single hop in the OIDC authorization-code redirect chain
// captured by the Playwright spec via page.on('response').
//
// The Playwright spec writes an array of these to:
//   /tmp/login-redirect-chain-<slug>.json
//
// The fields mirror the Playwright spec's RedirectStep TypeScript interface.
type RedirectStep struct {
	// From is the URL that initiated this redirect (the previous page URL).
	// Empty string for the first hop if the page navigated directly.
	From string `json:"from"`
	// To is the URL the response redirected to (the Location header value).
	To string `json:"to"`
	// Status is the HTTP status code of the redirect response (e.g. 302, 307).
	Status int `json:"status"`
	// Method is the HTTP method of the redirect request (usually "GET").
	Method string `json:"method"`
}

// ---------------------------------------------------------------------------
// LoadRedirectChain
// ---------------------------------------------------------------------------

// LoadRedirectChain reads the JSON file written by the Playwright login spec
// and returns the parsed redirect chain.
//
// Security: OIDC `code` query parameter values are NOT logged — only the URL
// structure (scheme + host + path + presence of code param) appears in error
// messages.
//
// Requirements: R1.4.
func LoadRedirectChain(path string) ([]RedirectStep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oidc_redirect: LoadRedirectChain: read %s: %w", path, err)
	}
	var chain []RedirectStep
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("oidc_redirect: LoadRedirectChain: unmarshal %s: %w", path, err)
	}
	return chain, nil
}

// ---------------------------------------------------------------------------
// AssertRedirectChain
// ---------------------------------------------------------------------------

// AssertRedirectChain asserts that the redirect chain contains at least 3 hops.
//
// A healthy OIDC authorization-code flow produces at minimum:
//   1. Dashboard /login → Zitadel /oauth/v2/authorize (302)
//   2. Zitadel → dashboard /api/auth/callback/zitadel?code=... (302)
//   3. Dashboard callback → dashboard / (302 or 200)
//
// If the chain is shorter, the OIDC redirect chain did not complete.
//
// Requirements: R1.4.
func AssertRedirectChain(t interface{ Fatalf(string, ...interface{}) }, chain []RedirectStep) {
	if len(chain) < 3 {
		t.Fatalf(
			"AssertRedirectChain: expected at least 3 redirect hops in the OIDC chain, got %d.\n"+
				"Chain dump:\n%s\n"+
				"This means the login form either did not trigger an OIDC redirect or the\n"+
				"redirect chain was cut short before completing. See LOGIN-B catalog in design.md.",
			len(chain), formatChain(chain),
		)
	}
}

// ---------------------------------------------------------------------------
// MustHaveZitadelHop
// ---------------------------------------------------------------------------

// MustHaveZitadelHop asserts that at least one hop in the chain traverses
// the Zitadel authentication server (auth.zeroroot.local or the configured
// ZITADEL_DOMAIN).
//
// This proves the browser was redirected through the OIDC identity provider
// rather than bypassing it.
//
// Security: OIDC code parameter values are redacted in the error message
// (only the host and path are shown).
//
// Requirements: R1.4.
func MustHaveZitadelHop(t interface{ Fatalf(string, ...interface{}) }, chain []RedirectStep) {
	zitadelHosts := []string{
		"auth.zeroroot.local",
		"zitadel",
		"gibson-zitadel",
	}

	for _, step := range chain {
		// Check both the From and To URLs for a Zitadel host.
		for _, u := range []string{step.From, step.To} {
			if u == "" {
				continue
			}
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			for _, zHost := range zitadelHosts {
				if strings.Contains(host, zHost) {
					return // found — assertion passes
				}
			}
		}
	}

	t.Fatalf(
		"MustHaveZitadelHop: no hop in the OIDC redirect chain traversed a Zitadel host.\n"+
			"Checked hosts: %v\n"+
			"Chain dump (code params redacted):\n%s\n"+
			"Possible causes:\n"+
			"  - The login form is not configured to redirect to Zitadel (OIDC client missing).\n"+
			"  - Zitadel is unreachable from the browser (check Envoy proxy route).\n"+
			"  - The redirect chain JSON was captured BEFORE the Zitadel hop (timing issue).\n"+
			"See LOGIN-B catalog in design.md for known causes once populated.",
		zitadelHosts, formatChain(chain),
	)
}

// ---------------------------------------------------------------------------
// MustHaveCallbackHop
// ---------------------------------------------------------------------------

// MustHaveCallbackHop asserts that at least one hop in the chain is the
// Auth.js callback endpoint: /api/auth/callback/zitadel?code=...
//
// This proves that:
//   1. Zitadel issued an authorization code (the OIDC flow progressed).
//   2. Auth.js received the code and began the token exchange.
//
// Security: the `code` query parameter VALUE is redacted in any error
// message — only the presence of the `code` param is asserted.
//
// Requirements: R1.4.
func MustHaveCallbackHop(t interface{ Fatalf(string, ...interface{}) }, chain []RedirectStep) {
	for _, step := range chain {
		for _, u := range []string{step.From, step.To} {
			if u == "" {
				continue
			}
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			// Check for the Auth.js callback path.
			if strings.Contains(parsed.Path, "/api/auth/callback/zitadel") {
				// Assert the `code` query param is present (not that it's valid).
				if parsed.Query().Get("code") != "" {
					return // found — assertion passes
				}
				// Callback URL present but no code param — unusual.
				t.Fatalf(
					"MustHaveCallbackHop: found /api/auth/callback/zitadel hop but NO `code` query param.\n"+
						"URL (code redacted): %s\n"+
						"This means Zitadel redirected to the callback but did not include the authorization code.\n"+
						"Possible cause: Zitadel client config has wrong redirect_uri.\n"+
						"See LOGIN-B candidate A in design.md.",
					redactCodeParam(u),
				)
				return
			}
		}
	}

	t.Fatalf(
		"MustHaveCallbackHop: no /api/auth/callback/zitadel?code=... hop in the redirect chain.\n"+
			"Chain dump (code params redacted):\n%s\n"+
			"Possible causes:\n"+
			"  - Zitadel did not issue an authorization code (OIDC error response).\n"+
			"  - The dashboard's Auth.js callback URL is not registered in Zitadel.\n"+
			"  - The redirect chain was captured before the callback hop completed.\n"+
			"See LOGIN-B catalog in design.md for known causes once populated.",
		formatChain(chain),
	)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// redactCodeParam returns the URL string with the `code` query parameter
// value replaced by "<redacted>" for safe logging.
func redactCodeParam(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "<unparseable-url>"
	}
	q := parsed.Query()
	if q.Get("code") != "" {
		q.Set("code", "<redacted>")
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}

// formatChain returns a multi-line string representation of the redirect
// chain with code params redacted.
func formatChain(chain []RedirectStep) string {
	if len(chain) == 0 {
		return "  (empty chain)"
	}
	var sb strings.Builder
	for i, step := range chain {
		fmt.Fprintf(&sb, "  [%d] status=%d method=%s\n      from=%s\n      to=%s\n",
			i, step.Status, step.Method,
			redactCodeParam(step.From),
			redactCodeParam(step.To),
		)
	}
	return sb.String()
}
