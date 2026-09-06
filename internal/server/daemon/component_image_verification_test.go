// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
)

// These cover the gate that makes a digest pin mean something: the platform
// offers a component only when its image can be shown to come from the release
// pipeline (ADR-0015 runtime verification, gibson#1639).

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// stubVerifier fails the images named in bad, passes everything else, and
// records what it was asked about.
type stubVerifier struct {
	bad    map[string]error
	asked  []string
	calls  int
	failed bool
}

func (s *stubVerifier) Verify(_ context.Context, image string) error {
	s.calls++
	s.asked = append(s.asked, image)
	if err, ok := s.bad[image]; ok {
		s.failed = true
		return err
	}
	return nil
}

// realToolImage is the executor image the generated kind:tool manifests pin.
func realToolImage(t *testing.T) string {
	t.Helper()
	entry, ok := componentcatalog.LookupTool("nmap")
	if !ok {
		t.Fatal("nmap must exist in the embedded catalog")
	}
	return entry.Image
}

// TestVerifyCatalogImages_AllSigned_KeepsEverything: the happy path. Every
// component survives, so the seeder writes the full catalog.
func TestVerifyCatalogImages_AllSigned_KeepsEverything(t *testing.T) {
	refs := componentcatalog.Refs()
	v := &stubVerifier{}
	kept, err := verifyCatalogImages(context.Background(), v, refs, quietLogger())
	if err != nil {
		t.Fatalf("a fully signed catalog must not error: %v", err)
	}
	if len(kept) != len(refs) {
		t.Errorf("kept %d of %d components; a signed catalog loses none", len(kept), len(refs))
	}
	if v.calls == 0 {
		t.Error("the verifier was never consulted")
	}
}

// TestVerifyCatalogImages_UnsignedImageRefused is the failing fixture the gate
// ships with: a digest-shaped but unverifiable image is refused, and the
// components it backs are left out of the seed set. Without this the check
// could be a no-op and nothing would notice.
func TestVerifyCatalogImages_UnsignedImageRefused(t *testing.T) {
	image := realToolImage(t)
	refs := componentcatalog.Refs()
	v := &stubVerifier{bad: map[string]error{image: supplychain.ErrUnsigned}}

	kept, err := verifyCatalogImages(context.Background(), v, refs, quietLogger())
	if err == nil {
		t.Fatal("an unverifiable image must be reported, not passed over in silence")
	}
	if !strings.Contains(err.Error(), "could not be shown to come from the release pipeline") {
		t.Errorf("the error should say what failed and why, got: %v", err)
	}

	// Every component backed by that image is gone; the rest survive.
	for _, r := range kept {
		if ir, ok := componentcatalog.LookupTool(r.ID); ok && ir.Image == image {
			t.Errorf("component %s/%s is backed by the refused image but was still seeded", r.Kind, r.ID)
		}
	}
	if len(kept) == len(refs) {
		t.Error("nothing was excluded; the gate is not enforcing")
	}
	if len(kept) == 0 {
		t.Error("one bad image de-listed the whole catalog; verified components must survive")
	}
}

// TestVerifyCatalogImages_NilVerifierFailsClosed: an unwired verifier cannot
// decide, and "cannot decide" is a deny. Seeding everything because the check
// is missing is the exact failure this gate exists to prevent.
func TestVerifyCatalogImages_NilVerifierFailsClosed(t *testing.T) {
	kept, err := verifyCatalogImages(context.Background(), nil, componentcatalog.Refs(), quietLogger())
	if err == nil {
		t.Fatal("a nil verifier must fail closed")
	}
	if len(kept) != 0 {
		t.Errorf("a nil verifier must seed nothing, got %d components", len(kept))
	}
}

// TestVerifyCatalogImages_RegistryErrorIsRefusal: a network failure is not a
// pass. "We could not check" and "it is signed" must never be the same outcome.
func TestVerifyCatalogImages_RegistryErrorIsRefusal(t *testing.T) {
	image := realToolImage(t)
	v := &stubVerifier{bad: map[string]error{image: errors.New("dial ghcr.io: connection refused")}}

	kept, err := verifyCatalogImages(context.Background(), v, componentcatalog.Refs(), quietLogger())
	if err == nil {
		t.Fatal("a registry error must refuse, not pass")
	}
	for _, r := range kept {
		if ir, ok := componentcatalog.LookupTool(r.ID); ok && ir.Image == image {
			t.Errorf("component %s/%s survived a failed verification", r.Kind, r.ID)
		}
	}
}

// TestVerifyCatalogImages_VerifiesEachImageOnce: every sandboxed tool shares one
// executor image. Verifying per component would turn one answer into seven
// network round trips on the startup path.
func TestVerifyCatalogImages_VerifiesEachImageOnce(t *testing.T) {
	v := &stubVerifier{}
	if _, err := verifyCatalogImages(context.Background(), v, componentcatalog.Refs(), quietLogger()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	seen := map[string]int{}
	for _, img := range v.asked {
		seen[img]++
	}
	for img, n := range seen {
		if n > 1 {
			t.Errorf("image %s was verified %d times; distinct images are verified once", img, n)
		}
	}

	// And the shared executor really is shared, or the test above proves nothing.
	tools := 0
	for _, ir := range componentcatalog.ImageRefs() {
		if ir.Kind == "tool" && ir.Image == realToolImage(t) {
			tools++
		}
	}
	if tools < 2 {
		t.Skipf("only %d tool(s) share the executor image; de-duplication is untested here", tools)
	}
}

// TestVerifyCatalogImages_ThirdPartyImageSkipped: a vendor image carries no
// signature of ours. It is a different trust seam, not a failure — holding it to
// our release identity would either block it forever or teach the verifier to
// accept unsigned images.
func TestVerifyCatalogImages_ThirdPartyImageSkipped(t *testing.T) {
	v := &stubVerifier{}
	if _, err := verifyCatalogImages(context.Background(), v, componentcatalog.Refs(), quietLogger()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, img := range v.asked {
		if !supplychain.IsFirstParty(img) {
			t.Errorf("third-party image %s was held to the release identity", img)
		}
	}
}

// TestComponentImageVerifier_BuildsAVerifier: the daemon's one construction
// point must produce a usable verifier. If it returned nil, verifyCatalogImages
// would fail closed and de-list the whole catalog at every startup.
func TestComponentImageVerifier_BuildsAVerifier(t *testing.T) {
	if componentImageVerifier() == nil {
		t.Fatal("a nil verifier fails closed and would de-list every component")
	}
}
