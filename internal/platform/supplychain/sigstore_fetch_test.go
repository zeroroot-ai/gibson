// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// These cover how a signature is FOUND, against a real registry served in
// process. It is the half that unit-testing the policy cannot reach, and the
// half that was actually wrong twice:
//
//   - cosign v3 attaches the bundle as an OCI 1.1 referrer, not a
//     `sha256-….sig` tag; looking for the tag finds nothing and reports a
//     signed image as unsigned.
//   - ghcr's referrers index advertises its descriptors as
//     `application/vnd.oci.empty.v1+json` while the manifests they point at
//     carry the real bundle artifactType, so filtering on the descriptor skips
//     every signature.
//
// Wired to a fail-closed gate, either mistake de-lists the whole catalog.

// localRegistry starts an in-process OCI registry and returns its host.
func localRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	return u.Host
}

// pushSubject pushes an ordinary image and returns its digest reference — the
// thing a signature would be attached to.
func pushSubject(t *testing.T, host string) name.Digest {
	t.Helper()
	ref, err := name.NewTag(host + "/gibson-executor:v1")
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer([]byte("payload"), types.OCILayer),
	})
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push subject: %v", err)
	}
	dg, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return ref.Context().Digest(dg.String())
}

// attachReferrer attaches an artifact of the given artifactType to subject,
// carrying body as its only layer — the shape cosign uses for a bundle.
func attachReferrer(t *testing.T, subject name.Digest, artifactType string, body []byte) {
	t.Helper()
	subjDesc, err := remote.Head(subject)
	if err != nil {
		t.Fatalf("head subject: %v", err)
	}
	art, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(body, types.MediaType(artifactType)),
	})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	art = mutate.MediaType(art, types.OCIManifestSchema1)
	// go-containerregistry cannot set a manifest's artifactType directly. Per
	// the OCI spec an empty artifactType falls back to the config mediaType,
	// which is the form built here; the live ghcr form (an explicit
	// artifactType) is covered by the tagged integration test.
	art = mutate.ConfigMediaType(art, types.MediaType(artifactType))
	art = mutate.Subject(art, *subjDesc).(v1.Image)

	dg, err := art.Digest()
	if err != nil {
		t.Fatalf("artifact digest: %v", err)
	}
	if err := remote.Write(subject.Context().Digest(dg.String()), art); err != nil {
		t.Fatalf("push referrer: %v", err)
	}
}

// TestFetchBundles_NoReferrers_ReportsUnsigned: an image with nothing attached
// is unsigned, and Verify says exactly that rather than a parse error.
func TestFetchBundles_NoReferrers_ReportsUnsigned(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)

	v := NewSigstoreVerifier("")
	bundles, err := v.fetchBundles(context.Background(), subject)
	if err != nil {
		t.Fatalf("fetchBundles: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("an image with no referrers has no bundles, got %d", len(bundles))
	}

	if err := v.Verify(context.Background(), subject.String()); err == nil {
		t.Fatal("an unsigned image must be refused")
	} else if !strings.Contains(err.Error(), ErrUnsigned.Error()) {
		t.Errorf("want an unsigned report, got: %v", err)
	}
}

// TestFetchBundles_IgnoresNonBundleReferrers: an SBOM or provenance artifact
// attached to the same image is not a signature. It must be skipped without
// failing the fetch — other referrers are normal, not corruption.
func TestFetchBundles_IgnoresNonBundleReferrers(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)
	attachReferrer(t, subject, "application/vnd.example.sbom.v1+json", []byte(`{"sbom":true}`))

	v := NewSigstoreVerifier("")
	bundles, err := v.fetchBundles(context.Background(), subject)
	if err != nil {
		t.Fatalf("a non-bundle referrer must not fail the fetch: %v", err)
	}
	if len(bundles) != 0 {
		t.Errorf("an SBOM referrer is not a signature, got %d bundle(s)", len(bundles))
	}
}

// TestFetchBundles_FindsBundleByManifestArtifactType is the regression test for
// the bug that mattered: the bundle is found by the referrer MANIFEST's
// artifactType. A verifier that trusted the index descriptor instead would find
// nothing here and call a signed image unsigned.
func TestFetchBundles_FindsBundleByManifestArtifactType(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)

	// A syntactically valid, cryptographically meaningless bundle: this test is
	// about locating and parsing it, not about whether it verifies.
	const minimalBundle = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",` +
		`"verificationMaterial":{"publicKey":{"hint":"test"}},` +
		`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"YWJj"},"signature":"c2ln"}}`
	attachReferrer(t, subject, bundleMediaType, []byte(minimalBundle))

	v := NewSigstoreVerifier("")
	bundles, err := v.fetchBundles(context.Background(), subject)
	if err != nil {
		t.Fatalf("fetchBundles: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("the attached sigstore bundle must be found, got %d", len(bundles))
	}
}

// TestVerify_BundlePresentButUntrusted: a bundle that exists but does not chain
// to the release identity is refused — and NOT reported as unsigned, because
// "nobody signed it" and "the wrong party signed it" are different problems.
func TestVerify_BundlePresentButUntrusted(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)
	const minimalBundle = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",` +
		`"verificationMaterial":{"publicKey":{"hint":"test"}},` +
		`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"YWJj"},"signature":"c2ln"}}`
	attachReferrer(t, subject, bundleMediaType, []byte(minimalBundle))

	// Trusted material that trusts nothing: verification must fail on the
	// signature, having got far enough to try.
	v := NewSigstoreVerifier("")
	err := v.Verify(context.Background(), subject.String())
	if err == nil {
		t.Fatal("a bundle that does not chain to the release identity must be refused")
	}
	if strings.Contains(err.Error(), ErrUnsigned.Error()) {
		t.Errorf("a present-but-bad signature must not be reported as unsigned: %v", err)
	}
}

// TestVerify_UnreachableRegistryIsRefusal: a registry that is down is not a
// pass. "We could not check" and "it is signed" must never be the same outcome.
func TestVerify_UnreachableRegistryIsRefusal(t *testing.T) {
	v := NewSigstoreVerifier("")
	// Port 1 on loopback refuses connections immediately.
	const dead = "127.0.0.1:1/gibson-executor@sha256:" +
		"c2d7b916f610c3e3d6ec285cdaf9db95437e26cf111c152df71a27438ade2c16"
	if err := v.Verify(context.Background(), dead); err == nil {
		t.Fatal("an unreachable registry must be refused, not passed")
	}
}

// TestFetchBundle_RejectsAReferrerWithNoLayer: a bundle lives in the manifest's
// only layer. A referrer that claims the bundle artifactType but carries no
// layer is malformed, and saying so beats an index-out-of-range panic during
// daemon startup.
func TestFetchBundle_RejectsAReferrerWithNoLayer(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)

	subjDesc, err := remote.Head(subject)
	if err != nil {
		t.Fatalf("head subject: %v", err)
	}
	art := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	art = mutate.ConfigMediaType(art, types.MediaType(bundleMediaType))
	art = mutate.Subject(art, *subjDesc).(v1.Image)
	dg, err := art.Digest()
	if err != nil {
		t.Fatalf("artifact digest: %v", err)
	}
	if err := remote.Write(subject.Context().Digest(dg.String()), art); err != nil {
		t.Fatalf("push layerless referrer: %v", err)
	}

	v := NewSigstoreVerifier("")
	if _, err := v.fetchBundle(context.Background(), subject, dg, []remote.Option{}); err == nil {
		t.Fatal("a referrer with no bundle layer must be reported, not panic")
	}
}

// TestFetchBundles_SkipsAnUnparseableBundle: a referrer that claims to be a
// bundle but is not valid JSON is skipped, not fatal — one corrupt attachment
// must not stop a good signature beside it from being found.
func TestFetchBundles_SkipsAnUnparseableBundle(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host)
	attachReferrer(t, subject, bundleMediaType, []byte("this is not a bundle"))

	v := NewSigstoreVerifier("")
	bundles, err := v.fetchBundles(context.Background(), subject)
	if err != nil {
		t.Fatalf("an unparseable referrer must not fail the fetch: %v", err)
	}
	if len(bundles) != 0 {
		t.Errorf("garbage must not parse as a bundle, got %d", len(bundles))
	}
}

// TestReadAllLimited covers the cap: a bundle is a few KB, so an oversized or
// failing read is reported rather than streamed into memory unbounded.
func TestReadAllLimited(t *testing.T) {
	got, err := readAllLimited(strings.NewReader("hello"), 1024)
	if err != nil {
		t.Fatalf("a small body must read cleanly: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("body = %q, want hello", got)
	}

	if _, err := readAllLimited(strings.NewReader("way too long"), 4); err == nil {
		t.Error("a body over the cap must be an error, not silently truncated")
	}

	if _, err := readAllLimited(errReader{}, 1024); err == nil {
		t.Error("a read failure must propagate")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
