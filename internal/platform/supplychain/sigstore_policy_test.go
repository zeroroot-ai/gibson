// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// These exercise the half that decides trust, against a virtual sigstore — its
// own Fulcio, Rekor and CT log — so the policy is proven offline rather than by
// reaching the internet.
//
// The question they answer is the one that matters: a signature is only
// accepted when the RIGHT party made it. A verifier that accepts any valid
// signature is not a supply-chain control, it is a checksum.

// releaseIdentitySAN is the SAN the real pipeline signs with, verbatim from a
// signed image. The trailing 40-hex is the reusable workflow's pinned commit.
const releaseIdentitySAN = "https://github.com/zeroroot-ai/.github/.github/workflows/" +
	"reusable-image-build.yml@f0e11905166f5c53dd1a1b9f446e5ea8db643229"

// virtualVerifier builds a SigstoreVerifier whose trust root is the given
// virtual sigstore, so verifyEntities runs with no network.
func virtualVerifier(t *testing.T, sigstore *ca.VirtualSigstore) *SigstoreVerifier {
	t.Helper()
	v := NewSigstoreVerifier("")
	v.rootFn = func() (root.TrustedMaterial, error) { return sigstore, nil }
	// The in-memory CA issues certificates with no embedded SCT. Production
	// requires one — real Fulcio certs carry it, and the live integration test
	// verifies a real image with the production threshold intact. Dropping it
	// here isolates what these tests are for: the identity and digest policy.
	v.sctThreshold = 0
	return v
}

// signArtifact signs payload as identity/issuer and returns the entity plus the
// artifact digest the policy binds to.
func signArtifact(t *testing.T, sigstore *ca.VirtualSigstore, identity, issuer string, payload []byte) (entity verify.SignedEntity, artifactDigest []byte) {
	t.Helper()
	entity, err := sigstore.Sign(identity, issuer, payload)
	if err != nil {
		t.Fatalf("sign as %q/%q: %v", identity, issuer, err)
	}
	sum := sha256.Sum256(payload)
	return entity, sum[:]
}

// TestVerifyEntities_AcceptsTheReleaseIdentity: a signature from the release
// workflow, for this exact artifact, verifies.
func TestVerifyEntities_AcceptsTheReleaseIdentity(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, digest := signArtifact(t, sigstore, releaseIdentitySAN, DefaultIssuer, []byte("image-bytes"))

	if err := virtualVerifier(t, sigstore).verifyEntities([]verify.SignedEntity{entity}, digest); err != nil {
		t.Fatalf("a signature from the release workflow must verify: %v", err)
	}
}

// TestVerifyEntities_RejectsAnotherWorkflow is the assertion the whole gate
// rests on. The signature is cryptographically valid and chains to the same
// Fulcio — it is simply not ours. Accepting it would mean anyone who can run a
// GitHub Actions job could sign an image the platform then offers.
func TestVerifyEntities_RejectsAnotherWorkflow(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	for name, identity := range map[string]string{
		"another org, same workflow name": "https://github.com/attacker/.github/.github/workflows/" +
			"reusable-image-build.yml@" + strings.Repeat("a", 40),
		"our org, a different workflow": "https://github.com/zeroroot-ai/.github/.github/workflows/" +
			"release-please.yml@" + strings.Repeat("b", 40),
		"our workflow, from a branch rather than a pinned commit": "https://github.com/zeroroot-ai/.github/" +
			".github/workflows/reusable-image-build.yml@refs/heads/main",
	} {
		t.Run(name, func(t *testing.T) {
			entity, digest := signArtifact(t, sigstore, identity, DefaultIssuer, []byte("image-bytes"))
			err := virtualVerifier(t, sigstore).verifyEntities([]verify.SignedEntity{entity}, digest)
			if err == nil {
				t.Fatalf("a signature from %q must be refused", identity)
			}
			if !strings.Contains(err.Error(), "no attached signature verified") {
				t.Errorf("the refusal should name the identity policy, got: %v", err)
			}
		})
	}
}

// TestVerifyEntities_RejectsAnotherIssuer: the right workflow path asserted by
// the wrong OIDC provider is not the same claim.
func TestVerifyEntities_RejectsAnotherIssuer(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, digest := signArtifact(t, sigstore, releaseIdentitySAN, "https://gitlab.com", []byte("image-bytes"))

	if err := virtualVerifier(t, sigstore).verifyEntities([]verify.SignedEntity{entity}, digest); err == nil {
		t.Fatal("a signature from another OIDC issuer must be refused")
	}
}

// TestVerifyEntities_RejectsASignatureForAnotherArtifact: the signature is ours
// and valid, but it covers different bytes. Without the digest binding, a
// signature could be lifted from one image onto another.
func TestVerifyEntities_RejectsASignatureForAnotherArtifact(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, _ := signArtifact(t, sigstore, releaseIdentitySAN, DefaultIssuer, []byte("the image that was signed"))
	other := sha256.Sum256([]byte("a different image"))

	if err := virtualVerifier(t, sigstore).verifyEntities([]verify.SignedEntity{entity}, other[:]); err == nil {
		t.Fatal("a signature must not verify against an artifact it does not cover")
	}
}

// TestVerifyEntities_AcceptsWhenOneOfSeveralMatches: the pipeline attaches a
// signature AND an SBOM attestation. One entity verifying is the claim; the
// others are a different predicate, not a failure.
func TestVerifyEntities_AcceptsWhenOneOfSeveralMatches(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	payload := []byte("image-bytes")
	foreign, _ := signArtifact(t, sigstore, "https://github.com/someone/else/.github/workflows/x.yml@"+
		strings.Repeat("c", 40), DefaultIssuer, payload)
	ours, digest := signArtifact(t, sigstore, releaseIdentitySAN, DefaultIssuer, payload)

	if err := virtualVerifier(t, sigstore).verifyEntities([]verify.SignedEntity{foreign, ours}, digest); err != nil {
		t.Fatalf("one matching signature among several must verify: %v", err)
	}
}

// TestVerifyEntities_NoSignaturesIsRefusal: nothing to check is not a pass.
func TestVerifyEntities_NoSignaturesIsRefusal(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	sum := sha256.Sum256([]byte("image-bytes"))
	if err := virtualVerifier(t, sigstore).verifyEntities(nil, sum[:]); err == nil {
		t.Fatal("an empty signature set must be refused")
	}
}

// TestVerifyEntities_TrustedRootFailureIsRefusal: if the trust root cannot be
// loaded, nothing can be decided — and "cannot decide" is a deny.
func TestVerifyEntities_TrustedRootFailureIsRefusal(t *testing.T) {
	v := NewSigstoreVerifier("")
	v.rootFn = func() (root.TrustedMaterial, error) { return nil, errTrustRoot }
	sum := sha256.Sum256([]byte("image-bytes"))
	if err := v.verifyEntities(nil, sum[:]); err == nil {
		t.Fatal("a trust-root load failure must be refused, not passed")
	}
}

// TestIsBundleManifest covers the artifactType rules directly: the explicit form
// ghcr serves, and the OCI fallback to the config mediaType.
func TestIsBundleManifest(t *testing.T) {
	for name, tc := range map[string]struct {
		artifactType string
		configType   string
		want         bool
	}{
		"explicit artifactType":                   {bundleMediaType, "application/vnd.oci.empty.v1+json", true},
		"empty artifactType falls back to config": {"", bundleMediaType, true},
		"explicit artifactType wins over config":  {"application/vnd.example.sbom+json", bundleMediaType, false},
		"neither is a bundle":                     {"application/vnd.example.sbom+json", "application/vnd.oci.empty.v1+json", false},
		"both empty":                              {"", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isBundleManifest(manifestWith(tc.artifactType, tc.configType)); got != tc.want {
				t.Errorf("isBundleManifest(artifactType=%q, config=%q) = %v, want %v",
					tc.artifactType, tc.configType, got, tc.want)
			}
		})
	}
}

// TestNewSigstoreVerifier_DefaultsToTheReleaseIdentity: the constructor wires
// the production policy — the release SAN pattern, the GitHub Actions issuer,
// an SCT requirement, and a keychain. A verifier missing any of these would
// either accept the wrong signer or refuse every image.
func TestNewSigstoreVerifier_DefaultsToTheReleaseIdentity(t *testing.T) {
	v := NewSigstoreVerifier("")
	if v.issuer != DefaultIssuer {
		t.Errorf("issuer = %q, want %q", v.issuer, DefaultIssuer)
	}
	if v.identityPattern == nil || v.identityPattern.String() != DefaultIdentityPattern {
		t.Errorf("identity pattern = %v, want the release pattern", v.identityPattern)
	}
	if !v.identityPattern.MatchString(releaseIdentitySAN) {
		t.Error("the default pattern must match the real release identity")
	}
	if v.sctThreshold < 1 {
		t.Errorf("sctThreshold = %d; production must require an SCT, which is what ties "+
			"the certificate to a public CT log", v.sctThreshold)
	}
	if v.keychain == nil {
		t.Error("a verifier must carry a keychain, or it cannot read a private registry")
	}
}

// errTrustRoot stands in for a TUF fetch that failed.
var errTrustRoot = errors.New("tuf: cannot reach the sigstore trust root")

// manifestWith builds the minimal referrer manifest isBundleManifest reads.
func manifestWith(artifactType, configType string) *v1.Manifest {
	m := &v1.Manifest{ArtifactType: artifactType}
	m.Config.MediaType = types.MediaType(configType)
	return m
}
