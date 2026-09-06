// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// TestDefaultIdentityPattern_MatchesTheReleaseWorkflow pins the identity this
// gate actually enforces. The SAN was read off a real signed image; if the
// release pipeline changes where it signs from, this test is the thing that
// says so, rather than every daemon silently refusing every component.
func TestDefaultIdentityPattern_MatchesTheReleaseWorkflow(t *testing.T) {
	re := regexp.MustCompile(DefaultIdentityPattern)

	const releaseIdentity = "https://github.com/zeroroot-ai/.github/.github/workflows/" +
		"reusable-image-build.yml@f0e11905166f5c53dd1a1b9f446e5ea8db643229"
	if !re.MatchString(releaseIdentity) {
		t.Errorf("the pattern does not match the real signing identity:\n  %s", releaseIdentity)
	}

	// The SAN is pinned to the reusable workflow's commit, so a different SHA
	// is a routine bump, not an attack — the pattern must still match.
	const bumped = "https://github.com/zeroroot-ai/.github/.github/workflows/" +
		"reusable-image-build.yml@0000000000000000000000000000000000000000"
	if !re.MatchString(bumped) {
		t.Error("a reusable-workflow SHA bump must not look like a supply-chain failure")
	}

	for _, bad := range []string{
		// Another org's workflow of the same name.
		"https://github.com/attacker/.github/.github/workflows/reusable-image-build.yml@" + strings.Repeat("a", 40),
		// Our org, but a workflow that is not the signing one.
		"https://github.com/zeroroot-ai/.github/.github/workflows/something-else.yml@" + strings.Repeat("a", 40),
		// A branch ref rather than a pinned commit.
		"https://github.com/zeroroot-ai/.github/.github/workflows/reusable-image-build.yml@refs/heads/main",
		"",
	} {
		if re.MatchString(bad) {
			t.Errorf("the pattern must not accept %q", bad)
		}
	}
}

// TestSigstoreVerifier_RejectsNonDigestReference: verification is anchored to a
// digest. A tag could be repointed after the check.
func TestSigstoreVerifier_RejectsNonDigestReference(t *testing.T) {
	v := NewSigstoreVerifier("")
	if err := v.Verify(context.Background(), FirstPartyRegistry+"gibson-executor:latest"); err == nil {
		t.Error("a tagged reference must be refused")
	}
}
