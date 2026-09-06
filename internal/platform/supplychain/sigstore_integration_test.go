// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package supplychain

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// The real-artifact proof. Everything else in this package tests the policy in
// isolation; this checks the part that can only be got wrong against a live
// registry — fetching the sigstore bundle from OCI referrers and verifying it
// end to end.
//
// It reaches ghcr.io and the sigstore TUF repository, so it self-skips unless
// GIBSON_VERIFY_IMAGE names an image to check:
//
//	GIBSON_VERIFY_IMAGE=ghcr.io/zeroroot-ai/gibson-executor@sha256:<digest> \
//	  go test -tags integration ./internal/platform/supplychain/ -run RealImage -v
//
// This caught the bug that unit tests could not: ghcr's referrers index
// advertises its descriptors as `application/vnd.oci.empty.v1+json` while the
// manifests they point at carry the real bundle artifactType. Filtering on the
// descriptor made the verifier report a correctly-signed image as unsigned —
// which, wired to a fail-closed gate, de-lists the entire catalog.

func TestRealImage_VerifiesAgainstTheReleaseIdentity(t *testing.T) {
	image := os.Getenv("GIBSON_VERIFY_IMAGE")
	if image == "" {
		t.Skip("GIBSON_VERIFY_IMAGE unset; skipping the live registry check")
	}
	v := NewSigstoreVerifier(os.Getenv("GIBSON_REGISTRY_CREDENTIAL_DIR"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := v.Verify(ctx, image); err != nil {
		if errors.Is(err, ErrUnsigned) {
			t.Fatalf("%s reports as unsigned. Either the release pipeline did not sign it, "+
				"or the verifier is looking in the wrong place (cosign v3 attaches the bundle "+
				"as an OCI referrer, not a `sha256-….sig` tag).", image)
		}
		t.Fatalf("verify %s: %v", image, err)
	}
}

// TestRealImage_RefusesAnUnsignedDigest: a digest that exists but was never
// signed must be refused. GIBSON_VERIFY_UNSIGNED_IMAGE names one.
func TestRealImage_RefusesAnUnsignedDigest(t *testing.T) {
	image := os.Getenv("GIBSON_VERIFY_UNSIGNED_IMAGE")
	if image == "" {
		t.Skip("GIBSON_VERIFY_UNSIGNED_IMAGE unset; skipping the negative live check")
	}
	v := NewSigstoreVerifier(os.Getenv("GIBSON_REGISTRY_CREDENTIAL_DIR"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := v.Verify(ctx, image); err == nil {
		t.Fatalf("%s verified, but it is supposed to be unsigned — the gate is not enforcing", image)
	}
}
