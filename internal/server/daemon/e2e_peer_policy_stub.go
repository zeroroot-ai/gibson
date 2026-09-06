// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

// e2e_peer_policy_stub.go — production build: the exit-test runner identity
// does not exist.
//
// Compiled whenever -tags=test_fixtures is absent, which is every production
// build. spiffePeerMethodPolicies merges an empty map, so no test identity is
// ever a direct-dial peer on a production daemon. A deployment that
// nonetheless lists the e2e SVID in allowedPeerIDs fails the daemon at boot
// (validateAllowedPeerPolicies), which is the correct outcome: an unpoliced
// peer must never reach the request path.

package daemon

// e2ePeerMethodPolicies returns nothing in a production build.
func e2ePeerMethodPolicies() map[string]map[string]bool { return nil }
