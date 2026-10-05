// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import "testing"

func TestProxyURL(t *testing.T) {
	got := ProxyURL("github", "tenant-acme")
	want := "http://mcp-github-proxy.tenant-acme.svc.cluster.local:8080/mcp"
	if got != want {
		t.Fatalf("ProxyURL = %q; want %q", got, want)
	}
}
