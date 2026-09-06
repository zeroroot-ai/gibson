// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"
)

// The exit-test runner is a direct-dial SPIFFE peer, which is exactly the kind
// of thing that must not leak into a production binary. These pin that.
//
// This file is UNTAGGED on purpose: it compiles in both builds, so each
// assertion below is checked in whichever build the test run selects.

// TestE2EPeerPolicy_AbsentFromProductionBuilds is the important one. Without
// the test_fixtures tag the e2e identity must not exist, so a production daemon
// cannot be talked into accepting it — not by config, not by an operator
// mistake, because there is no policy for it in the binary.
func TestE2EPeerPolicy_AbsentFromProductionBuilds(t *testing.T) {
	policies := spiffePeerMethodPolicies()

	var e2e []string
	for id := range policies {
		if strings.Contains(id, "e2e") {
			e2e = append(e2e, id)
		}
	}

	if isTestFixturesBuild {
		if len(e2e) == 0 {
			t.Fatal("a test_fixtures build must carry the e2e runner policy, or the exit tests cannot dial the daemon")
		}
		return
	}
	if len(e2e) != 0 {
		t.Fatalf("a production build must NOT carry an e2e direct-dial identity, found: %v", e2e)
	}
}

// TestSpiffePeerMethodPolicies_KeepsTheShippedPeers: adding the e2e hook must
// not disturb the two real control-plane peers. Losing one would silently
// un-authorise the tenant-operator or connector-operator.
func TestSpiffePeerMethodPolicies_KeepsTheShippedPeers(t *testing.T) {
	policies := spiffePeerMethodPolicies()
	for _, want := range []string{tenantOperatorSVID, connectorOperatorSVID} {
		methods, ok := policies[want]
		if !ok {
			t.Errorf("%s lost its method policy; that peer would be denied at request time", want)
			continue
		}
		if len(methods) == 0 {
			t.Errorf("%s has an EMPTY method policy, which denies every call", want)
		}
	}
}

// TestValidateAllowedPeerPolicies_RefusesAnUnpolicedPeer is the fail-closed
// property the whole design leans on: if the e2e SVID is allow-listed by a
// deployment whose daemon has no policy for it (a production binary), the
// daemon must refuse at boot rather than grant unrestricted access.
func TestValidateAllowedPeerPolicies_RefusesAnUnpolicedPeer(t *testing.T) {
	const unpoliced = "spiffe://zeroroot.ai/platform/e2e-runner"
	err := validateAllowedPeerPolicies(
		[]string{tenantOperatorSVID, unpoliced},
		map[string]map[string]bool{tenantOperatorSVID: operatorAllowedMethods()},
	)
	if err == nil {
		t.Fatal("an allow-listed peer with no method policy must fail the daemon at boot")
	}
	if !strings.Contains(err.Error(), unpoliced) {
		t.Errorf("the error must name the unpoliced peer so an operator can fix it, got: %v", err)
	}
}

// TestMergePeerPolicies covers the fold in both builds. In a production build
// the e2e map is nil, so without this the merge would be untested precisely
// where a mistake is most costly: dropping or overwriting a real
// control-plane peer's method policy.
func TestMergePeerPolicies(t *testing.T) {
	base := map[string]map[string]bool{
		tenantOperatorSVID: {"/a": true},
	}

	// nil extra — the production shape — must leave base untouched.
	got := mergePeerPolicies(base, nil)
	if len(got) != 1 || !got[tenantOperatorSVID]["/a"] {
		t.Fatalf("a nil extra map must leave the shipped peers alone, got %v", got)
	}

	// a test-build extra is added alongside, not instead of.
	got = mergePeerPolicies(base, map[string]map[string]bool{"spiffe://x/e2e": {"/b": true}})
	if !got[tenantOperatorSVID]["/a"] {
		t.Error("merging an extra peer must not disturb an existing one")
	}
	if !got["spiffe://x/e2e"]["/b"] {
		t.Error("the extra peer must be present after the merge")
	}
	if len(got) != 2 {
		t.Errorf("expected exactly the two peers, got %d", len(got))
	}
}
