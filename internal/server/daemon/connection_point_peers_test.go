// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"slices"
	"testing"
)

// Each configured connection point caller joins the TLS allowlist once. A
// caller that is not a SPIFFE ID, or that is in another trust domain, stops
// the start.
func TestWithConnectionPointPeers(t *testing.T) {
	allowed := []string{"spiffe://zeroroot.ai/platform/envoy"}
	got, err := withConnectionPointPeers(allowed, "zeroroot.ai",
		"spiffe://zeroroot.ai/component/billing", "", "spiffe://zeroroot.ai/platform/envoy")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"spiffe://zeroroot.ai/platform/envoy", "spiffe://zeroroot.ai/component/billing"}) {
		t.Fatalf("peers = %v", got)
	}
	if len(allowed) != 1 {
		t.Fatal("the input list changed")
	}
	if _, err := withConnectionPointPeers(nil, "zeroroot.ai", "not-an-id"); err == nil {
		t.Error("a caller that is not a SPIFFE ID passed")
	}
	if _, err := withConnectionPointPeers(nil, "zeroroot.ai", "spiffe://other.example/billing"); err == nil {
		t.Error("a caller of another trust domain passed")
	}
}
