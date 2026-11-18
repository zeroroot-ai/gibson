// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill

// package.go packs a folder as an OCI image. The tool
// tests/fixtures/agentskills/pack calls Package for the exit test of the Agent
// Skills epic, and the tests of this package call it too.

import (
	"archive/tar"
	"bytes"
	"fmt"
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Package validates the folder and writes it as an OCI image with one layer.
// The same folder always gives the same digest.
func Package(folderName string, files []File) (*Artifact, error) {
	m, err := Validate(folderName, files)
	if err != nil {
		return nil, err
	}
	layer, err := tarLayer(files)
	if err != nil {
		return nil, err
	}
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer})
	if err != nil {
		return nil, fmt.Errorf("agentskill: append the layer: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, ConfigMediaType)
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("agentskill: digest of the image: %w", err)
	}
	return &Artifact{Manifest: m, Image: img, Digest: digest}, nil
}

// tarLayer writes the files, sorted by path, into one tar archive with no time
// and no owner, so the bytes depend on the content only.
func tarLayer(files []File) (v1.Layer, error) {
	sorted := make([]File, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range sorted {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Path,
			Mode:     0o644,
			Size:     int64(len(f.Content)),
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("agentskill: tar header for %q: %w", f.Path, err)
		}
		if _, err := tw.Write(f.Content); err != nil {
			return nil, fmt.Errorf("agentskill: tar content of %q: %w", f.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("agentskill: close the tar archive: %w", err)
	}
	return static.NewLayer(buf.Bytes(), LayerMediaType), nil
}
