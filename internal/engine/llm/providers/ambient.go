// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// The Anthropic client of anthropic-sdk-go reads defaults from the environment
// of the process and from a profile directory: an API key, an auth token, a base
// URL, a profile and a federation identity. The eino-ext Claude client builds
// that client and offers no option to turn the defaults off. A tenant request
// must never carry or follow a credential or an address that belongs to the
// platform. So the daemon refuses to start when any ANTHROPIC_ variable is set,
// and points the profile directory at an empty directory that it creates.
const anthropicEnvPrefix = "ANTHROPIC_"

// anthropicConfigDirVar names the profile directory of the SDK.
const anthropicConfigDirVar = "ANTHROPIC_CONFIG_DIR"

// SecureAnthropicEnvironment runs once at daemon start, before any client
// exists. It fails when any environment variable with the ANTHROPIC_ prefix,
// other than ANTHROPIC_CONFIG_DIR, is set. It then creates an empty directory
// and makes it the profile directory of the SDK. The SDK reads a default profile
// from that directory and fails a request when the file is missing, so an empty
// directory of the daemon also keeps a profile of the host out of reach. It
// fails when the directory holds any file.
func SecureAnthropicEnvironment() error {
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, anthropicEnvPrefix) && name != anthropicConfigDirVar {
			return fmt.Errorf("providers: the environment variable %s is set. "+
				"The daemon never uses an Anthropic default of its own environment as a credential. Remove it", name)
		}
	}
	dir, err := os.MkdirTemp("", "gibson-anthropic-empty-")
	if err != nil {
		return fmt.Errorf("providers: create the empty Anthropic profile directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("providers: read the Anthropic profile directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("providers: the Anthropic profile directory %s is not empty", dir)
	}
	if err := os.Setenv(anthropicConfigDirVar, dir); err != nil {
		return fmt.Errorf("providers: set %s: %w", anthropicConfigDirVar, err)
	}
	return nil
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
