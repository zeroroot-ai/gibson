// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"net/http"
	"os"
	"sync"
)

// The Anthropic client of anthropic-sdk-go reads defaults from the environment
// of the process and from a profile directory: an API key, an auth token, a base
// URL, a profile and a federation identity. The eino-ext Claude client builds
// that client and offers no option to turn the defaults off. A tenant request
// must never carry or follow a credential or an address that belongs to the
// platform, so the provider removes every one of these variables before it
// builds a client, and points the profile directory at an empty directory.
// The daemon has no use for them: its own environment is never a credential.
var ambientAnthropicEnv = []string{
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_AUTH_TOKEN",
	"ANTHROPIC_AWS_API_KEY",
	"ANTHROPIC_AWS_BASE_URL",
	"ANTHROPIC_AWS_WORKSPACE_ID",
	"ANTHROPIC_BASE_URL",
	"ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
	"ANTHROPIC_CREDENTIALS_FILE",
	"ANTHROPIC_CUSTOM_HEADERS",
	"ANTHROPIC_ENVIRONMENT_ID",
	"ANTHROPIC_ENVIRONMENT_KEY",
	"ANTHROPIC_FEDERATION_RULE_ID",
	"ANTHROPIC_IDENTITY_TOKEN",
	"ANTHROPIC_IDENTITY_TOKEN_FILE",
	"ANTHROPIC_ORGANIZATION_ID",
	"ANTHROPIC_PROFILE",
	"ANTHROPIC_SCOPE",
	"ANTHROPIC_SERVICE_ACCOUNT_ID",
	"ANTHROPIC_SESSION_ID",
	"ANTHROPIC_WORK_ID",
	"ANTHROPIC_WORKSPACE_ID",
}

var (
	emptyConfigDirOnce sync.Once
	emptyConfigDir     string
)

func init() { scrubAnthropicAmbient() }

// scrubAnthropicAmbient removes the ambient Anthropic defaults of the process.
// It is idempotent, and the daemon calls it before each client it builds.
func scrubAnthropicAmbient() {
	for _, name := range ambientAnthropicEnv {
		_ = os.Unsetenv(name)
	}
	emptyConfigDirOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gibson-anthropic-empty-")
		if err == nil {
			emptyConfigDir = dir
		}
	})
	if emptyConfigDir != "" {
		_ = os.Setenv("ANTHROPIC_CONFIG_DIR", emptyConfigDir)
	}
}

// stripAmbientAuth wraps a transport so that no request carries an API key
// header that an ambient default put there. A Vertex request authenticates with
// the Google token of the tenant and never with an Anthropic key.
type stripAmbientAuth struct{ inner http.RoundTripper }

func (t stripAmbientAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Del("X-Api-Key")
	return t.inner.RoundTrip(req) //nolint:wrapcheck // the transport error is the answer
}

// withoutAmbientAuth returns a copy of client that strips ambient API key headers.
// The client must have its own transport, as every guarded client has.
func withoutAmbientAuth(client *http.Client) *http.Client {
	c := *client
	c.Transport = stripAmbientAuth{inner: client.Transport}
	return &c
}
