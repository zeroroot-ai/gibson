// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

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

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
)

// packFolder validates the folder with the rules of the daemon and writes it as an
// OCI image with one layer. The same folder always gives the same digest. The
// tests of the agentskill package hold a copy of this code in export_test.go.
// The daemon never builds an image, so the production package has no such
// function, and the dead code gate would refuse one.
func packFolder(folderName string, files []agentskill.File) (v1.Image, v1.Hash, error) {
	if _, err := agentskill.Validate(folderName, files); err != nil {
		return nil, v1.Hash{}, fmt.Errorf("validate the folder: %w", err)
	}
	layer, err := tarLayer(files)
	if err != nil {
		return nil, v1.Hash{}, err
	}
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer})
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("append the layer: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, agentskill.ConfigMediaType)
	digest, err := img.Digest()
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("digest of the image: %w", err)
	}
	return img, digest, nil
}

// tarLayer writes the files, sorted by path, into one tar archive with no time
// and no owner, so the bytes depend on the content only.
func tarLayer(files []agentskill.File) (v1.Layer, error) {
	sorted := make([]agentskill.File, len(files))
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
			return nil, fmt.Errorf("tar header for %q: %w", f.Path, err)
		}
		if _, err := tw.Write(f.Content); err != nil {
			return nil, fmt.Errorf("tar content of %q: %w", f.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close the tar archive: %w", err)
	}
	return static.NewLayer(buf.Bytes(), agentskill.LayerMediaType), nil
}
