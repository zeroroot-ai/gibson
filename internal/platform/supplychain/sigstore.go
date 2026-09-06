// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// bundleMediaType is the artifactType the release pipeline attaches. Both the
// signature and the SBOM attestation use it; they are told apart by whether the
// bundle carries a DSSE envelope, and only the plain signature is checked here.
const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// defaultIdentityRE is DefaultIdentityPattern compiled once. A bad pattern here
// is a programming error, not a runtime condition.
var defaultIdentityRE = regexp.MustCompile(DefaultIdentityPattern)

// SigstoreVerifier verifies an image's sigstore bundle, fetched from the
// registry as an OCI 1.1 referrer of the image manifest.
type SigstoreVerifier struct {
	issuer          string
	identityPattern *regexp.Regexp
	keychain        authn.Keychain

	// trustedRoot is resolved once, lazily. Fetching it reaches the sigstore
	// TUF repository, so doing it per image would put a network round trip in
	// front of every verification for material that does not change per image.
	once        sync.Once
	trustedRoot root.TrustedMaterial
	rootErr     error

	// rootFn is the trusted-material source. Nil fetches the real sigstore TUF
	// root; it exists as a seam so the fetch is substitutable rather than
	// hard-wired into Verify.
	rootFn func() (root.TrustedMaterial, error)

	// sctThreshold is how many signed certificate timestamps a certificate must
	// carry. Production is 1: real Fulcio certs embed an SCT, and requiring it
	// is what ties the certificate to a public CT log. Only a test lowers this,
	// because the in-memory CA used to exercise the identity policy offline does
	// not embed SCTs — the live integration test covers the real form.
	sctThreshold int
}

// NewSigstoreVerifier builds a verifier for the release pipeline's identity.
//
// credentialDir is the directory holding the registry credential as a docker
// config. It is the ONLY thing a caller supplies. The identity policy is still
// a constant of this package: the release SAN pattern, the GitHub Actions
// issuer, and an SCT requirement. There is no way for a caller to weaken them,
// which is the point — an overridable identity is one an operator can widen to
// "any signer" while the gate still looks present. A credential is not an
// identity: it decides which registry answers, never which signer is trusted.
//
// An empty credentialDir leaves the ambient keychain alone. A private registry
// answers an unauthenticated referrers request with 401, so the verifier
// refuses every first-party image and the platform offers no component. That
// is the failure this argument exists to end.
func NewSigstoreVerifier(credentialDir string) *SigstoreVerifier {
	keychain := authn.Keychain(authn.DefaultKeychain)
	if path := DockerConfigPath(credentialDir); path != "" {
		keychain = authn.NewMultiKeychain(dockerConfigKeychain{path: path}, authn.DefaultKeychain)
	}
	return &SigstoreVerifier{
		issuer:          DefaultIssuer,
		identityPattern: defaultIdentityRE,
		keychain:        keychain,
		sctThreshold:    1,
	}
}

// fetchTrustedRoot loads the sigstore trusted root with the local TUF cache
// DISABLED.
//
// The default writes a cache under $HOME/.sigstore. The daemon runs with a
// read-only root filesystem, so that mkdir fails — and because verification is
// fail-closed, a failure to load the trust root de-lists EVERY component. On a
// kind cluster this took the whole catalog down at startup:
//
//	load sigstore trusted root: ... mkdir /var/lib/gibson/.sigstore: read-only file system
//	9 component(s) not offered: agent/claude, agent/zerocool, tool/nmap, ...
//
// DisableLocalCache is sigstore-go's supported mode for exactly this. The
// trust root is fetched fresh instead of cached, which costs one request at
// startup and nothing afterwards: material() resolves once per process.
//
// Writing a cache elsewhere (an emptyDir, /tmp) was the alternative. It trades
// a read-only filesystem — a hardening property worth keeping — for a startup
// optimisation the daemon does not need.
func fetchTrustedRoot() (root.TrustedMaterial, error) {
	tr, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		return nil, fmt.Errorf("fetch sigstore trusted root: %w", err)
	}
	return tr, nil
}

func (v *SigstoreVerifier) material() (root.TrustedMaterial, error) {
	v.once.Do(func() {
		fn := v.rootFn
		if fn == nil {
			fn = fetchTrustedRoot
		}
		v.trustedRoot, v.rootErr = fn()
	})
	return v.trustedRoot, v.rootErr
}

// Verify fetches the image's sigstore bundle and checks it against the release
// identity. It returns nil only when a signature verifies; every other outcome,
// including "could not reach the registry", is an error. A verifier that
// answers "probably fine" when it could not check is worse than none, because
// it makes the gate look present while it enforces nothing.
func (v *SigstoreVerifier) Verify(ctx context.Context, image string) error {
	digestRef, err := name.NewDigest(image)
	if err != nil {
		return fmt.Errorf("parse image digest: %w", err)
	}
	hexDigest := strings.TrimPrefix(digestRef.DigestStr(), "sha256:")
	artifactDigest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return fmt.Errorf("decode image digest %q: %w", digestRef.DigestStr(), err)
	}

	bundles, err := v.fetchBundles(ctx, digestRef)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		return ErrUnsigned
	}

	entities := make([]verify.SignedEntity, 0, len(bundles))
	for _, b := range bundles {
		entities = append(entities, b)
	}
	return v.verifyEntities(entities, artifactDigest)
}

// verifyEntities applies the release-identity policy to the signatures attached
// to one image. Split from Verify so the policy can be exercised against a
// virtual sigstore, with no registry and no network: this is the half that
// decides trust, and it should not be testable only by reaching the internet.
func (v *SigstoreVerifier) verifyEntities(entities []verify.SignedEntity, artifactDigest []byte) error {
	trusted, err := v.material()
	if err != nil {
		return fmt.Errorf("load sigstore trusted root: %w", err)
	}
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if v.sctThreshold > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(v.sctThreshold))
	}
	sev, err := verify.NewVerifier(trusted, opts...)
	if err != nil {
		return fmt.Errorf("build sigstore verifier: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(v.issuer, "", "", v.identityPattern.String())
	if err != nil {
		return fmt.Errorf("build certificate identity policy: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", artifactDigest),
		verify.WithCertificateIdentity(identity),
	)

	// The pipeline attaches more than one bundle (signature, SBOM attestation).
	// One verifying against the release identity is the claim being made; the
	// others are a different predicate, not a failure.
	var lastErr error
	for _, e := range entities {
		_, vErr := sev.Verify(e, policy)
		if vErr == nil {
			return nil
		}
		lastErr = vErr
	}
	return fmt.Errorf("no attached signature verified against %s issued by %s: %w",
		v.identityPattern.String(), v.issuer, lastErr)
}

// isBundleManifest reports whether a referrer manifest is a sigstore bundle.
//
// The OCI spec says an empty artifactType falls back to the config mediaType,
// and both forms appear in the wild, so both are accepted. What is NOT consulted
// is the referrers-index descriptor: ghcr advertises those as
// `application/vnd.oci.empty.v1+json` regardless of what they point at.
func isBundleManifest(mf *v1.Manifest) bool {
	if mf.ArtifactType != "" {
		return mf.ArtifactType == bundleMediaType
	}
	return string(mf.Config.MediaType) == bundleMediaType
}

// fetchBundles pulls every sigstore bundle attached to the image as an OCI
// referrer.
func (v *SigstoreVerifier) fetchBundles(ctx context.Context, ref name.Digest) ([]*bundle.Bundle, error) {
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(v.keychain),
	}
	idx, err := remote.Referrers(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("list signature referrers: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read referrers index: %w", err)
	}

	// Filter on each referrer MANIFEST's artifactType, not the index
	// descriptor's. ghcr's referrers index advertises the descriptors as
	// `application/vnd.oci.empty.v1+json` while the manifests they point at
	// carry the real `…sigstore.bundle.v0.3+json` — trusting the descriptor
	// skips every signature and reports a signed image as unsigned.
	out := make([]*bundle.Bundle, 0, len(manifest.Manifests))
	for _, desc := range manifest.Manifests {
		b, err := v.fetchBundle(ctx, ref, desc.Digest, opts)
		if err != nil {
			// A referrer that is not a bundle (an SBOM blob, a provenance
			// attestation in another format) is not an error — it is simply
			// not the thing being looked for.
			continue
		}
		if b != nil {
			out = append(out, b)
		}
	}
	return out, nil
}

func (v *SigstoreVerifier) fetchBundle(_ context.Context, ref name.Digest, digest v1.Hash, opts []remote.Option) (*bundle.Bundle, error) {
	referrerRef := ref.Context().Digest(digest.String())
	img, err := remote.Image(referrerRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch signature manifest %s: %w", digest, err)
	}
	mf, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read referrer manifest %s: %w", digest, err)
	}
	if !isBundleManifest(mf) {
		return nil, fmt.Errorf("referrer %s is not a sigstore bundle (artifactType %q, config %q)",
			digest, mf.ArtifactType, mf.Config.MediaType)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read signature layers %s: %w", digest, err)
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("signature manifest %s carries no bundle layer", digest)
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("open bundle layer %s: %w", digest, err)
	}
	defer func() { _ = rc.Close() }()

	raw, err := readAllLimited(rc, maxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("read bundle %s: %w", digest, err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("parse bundle %s: %w", digest, err)
	}
	return &b, nil
}

// maxBundleBytes bounds a bundle read. A sigstore bundle is a few KB; the cap
// is there so a hostile or corrupt registry response cannot be streamed into
// memory unbounded during startup.
const maxBundleBytes = 8 << 20 // 8 MiB

// readAllLimited reads at most limit bytes, and reports an error rather than
// silently truncating — a truncated bundle would fail verification with a
// confusing parse error instead of naming the real problem.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle body: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("bundle exceeds %d bytes", limit)
	}
	return data, nil
}
