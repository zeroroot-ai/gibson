// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
)

// capCheckCall records one ActiveGrantID call, so a test can assert what the
// capability gate asked.
type capCheckCall struct {
	tenant, principal, capability string
}

// mockCapabilityChecker implements CapabilityChecker.
type mockCapabilityChecker struct {
	granted map[string]bool
	// grantID overrides the id that ActiveGrantID reports for a granted
	// capability. When empty, the mock makes one. A granted capability must
	// never answer with an empty id, because an empty id is the denial.
	grantID string
	err     error
	calls   []capCheckCall
}

func (m *mockCapabilityChecker) ActiveGrantID(_ context.Context, tenant, principal, capability string) (string, error) {
	m.calls = append(m.calls, capCheckCall{tenant: tenant, principal: principal, capability: capability})
	if m.err != nil {
		return "", m.err
	}
	if !m.granted[capability] {
		return "", nil
	}
	if m.grantID != "" {
		return m.grantID, nil
	}
	return "grant-" + capability, nil
}

// countingRegistry wraps noopRegistry to count the Discover calls. A test uses
// it to show that a refusal happens before any discovery.
type countingRegistry struct {
	noopRegistry
	discoverCalls int
}

func (r *countingRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	r.discoverCalls++
	return nil, nil
}
