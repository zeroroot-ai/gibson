// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill

// export_test.go holds the helper that only the tests use. It points the Puller
// at a test transport. No production code calls it.

import "net/http"

// WithTransportForTest replaces the transport, with no HTTPS check and no
// address limit. It exists only so a test can reach an in-process registry.
func WithTransportForTest(rt http.RoundTripper) PullerOption {
	return func(p *Puller) { p.transport = rt }
}
