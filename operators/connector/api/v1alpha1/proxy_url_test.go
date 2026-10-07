// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"net/url"
	"testing"
)

// IsProxyHost matches the host of ProxyURL, so the two cannot disagree, and
// each short DNS form of it.
func TestIsProxyHost(t *testing.T) {
	u, err := url.Parse(ProxyURL("gitlab", "tenant-acme"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, h := range []string{u.Hostname(), "mcp-gitlab-proxy", "mcp-gitlab-proxy.tenant-acme", "mcp-gitlab-proxy.tenant-acme.svc", "MCP-GITLAB-PROXY.tenant-acme.svc.cluster.local.", "mcp-gitlab-proxy.tenant-acme.svc.example.internal"} {
		if !IsProxyHost(h) {
			t.Errorf("IsProxyHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"mcp.example.com", "gitlab.com", "mcp-gitlab-proxy.example.com", "proxy.tenant-acme.svc"} {
		if IsProxyHost(h) {
			t.Errorf("IsProxyHost(%q) = true, want false", h)
		}
	}
}
