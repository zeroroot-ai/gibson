// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// tarOverhead is the room that tar headers and padding need on top of the
// largest folder.
const tarOverhead = MaxFiles * 2048

// Pulled is an Agent Skill that the daemon pulled by digest and validated.
type Pulled struct {
	Manifest *Manifest
	// Digest is the digest of the image manifest, in the form sha256:<hex>.
	Digest string
	Files  []File
}

// Puller pulls Agent Skill images from a registry by digest.
//
// The reference comes from a tenant, so the Puller limits where it can connect.
// It speaks HTTPS only, and its dialer refuses loopback, private, link-local,
// carrier-grade NAT, multicast and unspecified addresses after name
// resolution, for each connection and each redirect (internal/infra/netguard).
type Puller struct {
	transport http.RoundTripper
}

// PullerOption changes a Puller.
type PullerOption func(*Puller)

// AllowPrivateAddresses removes the address limit and keeps HTTPS only. Only the
// operator path uses it, because the operator config names the registry and a
// tenant does not.
func AllowPrivateAddresses() PullerOption {
	return func(p *Puller) { p.transport = httpsOnly{inner: netguard.Transport(true)} }
}

// addressHint is the hint of a refusal of a registry address. The setting
// security.allow_private_llm_endpoints does not apply to an Agent Skill pull.
const addressHint = "the registry of an Agent Skill must resolve to a public address"

// NewPuller returns a Puller with the HTTPS check and the address limit.
func NewPuller(opts ...PullerOption) *Puller {
	p := &Puller{transport: httpsOnly{inner: netguard.TransportWithHint(false, addressHint)}}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// httpsOnly refuses a request that is not HTTPS, whatever the reference says.
// The registry client picks http for a name such as localhost, so the check
// must be in the transport.
type httpsOnly struct{ inner http.RoundTripper }

func (h httpsOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("agentskill: refusing a %q request to %s: HTTPS only", req.URL.Scheme, req.URL.Host)
	}
	return h.inner.RoundTrip(req)
}

// Pull reads the image that reference names, and validates the folder in it.
//
// The reference must hold a digest. A tag is refused. Pull checks that the
// registry returns the manifest with that digest, checks the media types, and
// reads one layer with a size limit. The registry client checks the digest of
// each blob. Pull then unpacks the tar archive and calls Validate with
// folderName. Pull never keeps a file that is over a limit. keychain gives the
// credential for the registry of the reference.
func (p *Puller) Pull(
	ctx context.Context, reference, folderName string, keychain authn.Keychain,
) (*Pulled, error) {
	ref, err := name.NewDigest(reference, name.StrictValidation)
	if err != nil {
		return nil, invalidf("the reference %q is not a digest reference: %v", reference, err)
	}
	all := []remote.Option{
		remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain), remote.WithTransport(p.transport),
	}
	desc, err := remote.Get(ref, all...)
	if err != nil {
		return nil, fmt.Errorf("agentskill: pull %s: %w", ref.Name(), err)
	}
	if desc.Digest.String() != ref.DigestStr() {
		return nil, invalidf("the registry returned the digest %s for %s", desc.Digest, ref.DigestStr())
	}
	if desc.MediaType != types.OCIManifestSchema1 {
		return nil, invalidf("the manifest media type is %q, want %q", desc.MediaType, types.OCIManifestSchema1)
	}
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("agentskill: read the image %s: %w", ref.Name(), err)
	}
	mf, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("agentskill: read the manifest of %s: %w", ref.Name(), err)
	}
	if mf.Config.MediaType != ConfigMediaType {
		return nil, invalidf("the config media type is %q, want %q", mf.Config.MediaType, ConfigMediaType)
	}
	if len(mf.Layers) != 1 || mf.Layers[0].MediaType != LayerMediaType {
		return nil, invalidf("the image must have one layer of the media type %q", LayerMediaType)
	}
	if mf.Layers[0].Size > MaxFolderBytes+tarOverhead {
		return nil, overf("the layer has %d bytes, the limit is %d", mf.Layers[0].Size, MaxFolderBytes+tarOverhead)
	}
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		return nil, fmt.Errorf("agentskill: read the layers of %s: %w", ref.Name(), err)
	}
	// The layer is a plain tar archive, so the compressed stream is the tar.
	rc, err := layers[0].Compressed()
	if err != nil {
		return nil, fmt.Errorf("agentskill: open the layer of %s: %w", ref.Name(), err)
	}
	defer func() { _ = rc.Close() }()
	files, err := unpack(io.LimitReader(rc, MaxFolderBytes+tarOverhead+1))
	if err != nil {
		return nil, err
	}
	m, err := Validate(folderName, files)
	if err != nil {
		return nil, err
	}
	return &Pulled{Manifest: m, Digest: ref.DigestStr(), Files: files}, nil
}

// unpack reads the regular files of a tar archive. It refuses any other entry
// type and any file or folder over a limit.
func unpack(r io.Reader) ([]File, error) {
	tr := tar.NewReader(r)
	var files []File
	var total int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, invalidf("the layer is not a valid tar archive: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, invalidf("the layer entry %q is not a regular file", hdr.Name)
		}
		if len(files) >= MaxFiles {
			return nil, overf("the folder has more than %d files", MaxFiles)
		}
		if hdr.Size > MaxFileBytes {
			return nil, overf("the file %q has %d bytes, the limit is %d", hdr.Name, hdr.Size, MaxFileBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileBytes+1))
		if err != nil {
			return nil, invalidf("read the layer entry %q: %v", hdr.Name, err)
		}
		if len(data) > MaxFileBytes {
			return nil, overf("the file %q is over %d bytes", hdr.Name, MaxFileBytes)
		}
		total += len(data)
		if total > MaxFolderBytes {
			return nil, overf("the folder is over %d bytes", MaxFolderBytes)
		}
		files = append(files, File{Path: hdr.Name, Content: data})
	}
}
