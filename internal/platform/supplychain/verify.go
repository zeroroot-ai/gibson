// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package supplychain verifies that a first-party image the platform is about
// to offer was actually built by the release pipeline (ADR-0015, ADR-0017).
//
// A digest pin answers "is everyone running the same bytes". It does not answer
// "did we build those bytes" — anyone who can push to the registry can produce
// a digest-shaped reference. The signature answers the second question, and
// only the second question makes the first one worth anything.
//
// What the release pipeline produces (reusable-image-build.yml, keyless OIDC):
// a sigstore bundle attached to the image manifest as an OCI 1.1 referrer, with
// a Fulcio certificate whose SAN is the signing workflow and whose issuer is
// GitHub Actions. Note it is a referrer, NOT the legacy cosign `sha256-….sig`
// tag — cosign v3 stopped writing those, and a verifier that looks for the tag
// finds nothing and concludes "unsigned" about a perfectly signed image.
package supplychain

import (
	"context"
	"errors"
	"strings"
)

// FirstPartyRegistry is the image prefix of components built from source and
// signed by the release pipeline. A third-party vendor image is a different
// trust seam — it carries no signature of ours and is not held to this rule.
const FirstPartyRegistry = "ghcr.io/zeroroot-ai/"

// DefaultIssuer is the OIDC issuer in the signing certificate: the images are
// signed by a GitHub Actions job, keylessly.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

// DefaultIdentityPattern matches the SAN of the org's reusable image-build
// workflow, which is what actually holds the signing identity — every component
// repo delegates its build to it.
//
// The SAN ends in `@<git-sha>` because callers pin the reusable workflow by SHA.
// That is why this is a pattern and not a literal: pinning the exact SAN would
// make every routine bump of the reusable workflow look like a supply-chain
// attack, and the safe-looking fix for that alarm is to stop verifying.
const DefaultIdentityPattern = `^https://github\.com/zeroroot-ai/\.github/\.github/workflows/reusable-image-build\.yml@[0-9a-f]{40}$`

// ErrUnsigned reports an image with no signature the verifier could find.
// Separated from a verification failure because the two mean different things:
// no signature is usually a pipeline that did not run, a bad signature is a
// reason to stop trusting the registry.
var ErrUnsigned = errors.New("image carries no sigstore signature")

// Verifier answers one question about one image: was it signed by our release
// pipeline. Implementations must fail closed — an error means "not verified",
// never "probably fine".
type Verifier interface {
	Verify(ctx context.Context, image string) error
}

// IsFirstParty reports whether an image is one the release pipeline signs.
func IsFirstParty(image string) bool {
	return strings.HasPrefix(image, FirstPartyRegistry)
}
