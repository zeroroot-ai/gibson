// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
)

// push writes img to a new in-process registry and returns the digest
// reference.
func push(t *testing.T, img v1.Image) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	tagged, err := name.NewTag(host + "/acme/web-recon:v1")
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	if err := remote.Write(tagged, img); err != nil {
		t.Fatalf("push: %v", err)
	}
	return host + "/acme/web-recon@" + digest.String()
}

func pull(t *testing.T, ref string) (*agentskill.Pulled, error) {
	t.Helper()
	return agentskill.Pull(context.Background(), ref, "web-recon", authn.DefaultKeychain)
}

func rawImage(t *testing.T, cfg, layer types.MediaType, tarBytes []byte, layers int) v1.Image {
	t.Helper()
	img := v1.Image(empty.Image)
	for i := 0; i < layers; i++ {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(tarBytes, layer)})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	return mutate.ConfigMediaType(img, cfg)
}

func tarOf(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		body := []byte(validSkill)
		h.Size = int64(len(body))
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
			body = nil
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func TestPull_RoundTripKeepsTheDigest(t *testing.T) {
	art, err := agentskill.Package("web-recon", folder(file{Path: "references/a.md", Content: []byte("a")}))
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	got, err := pull(t, push(t, art.Image))
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if got.Digest != art.Digest.String() {
		t.Errorf("Digest = %s, want %s", got.Digest, art.Digest)
	}
	if got.Manifest.Name != "web-recon" || len(got.Files) != 2 {
		t.Errorf("pulled = %+v", got)
	}
}

func TestPull_Refusals(t *testing.T) {
	art, err := agentskill.Package("web-recon", folder())
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	good := push(t, art.Image)
	reg, _, _ := strings.Cut(good, "/")
	skillTar := tarOf(t, tar.Header{Typeflag: tar.TypeReg, Name: "SKILL.md", Mode: 0o644})

	cases := []struct {
		name string
		ref  string
		want error
	}{
		{"a tag", reg + "/acme/web-recon:v1", agentskill.ErrInvalidFolder},
		{"no digest", reg + "/acme/web-recon", agentskill.ErrInvalidFolder},
		{
			"wrong config media type",
			push(t, rawImage(t, "application/vnd.oci.image.config.v1+json", agentskill.LayerMediaType, skillTar, 1)),
			agentskill.ErrInvalidFolder,
		},
		{
			"wrong layer media type",
			push(t, rawImage(t, agentskill.ConfigMediaType, types.OCILayer, skillTar, 1)),
			agentskill.ErrInvalidFolder,
		},
		{
			"a symlink entry",
			push(t, rawImage(t, agentskill.ConfigMediaType, agentskill.LayerMediaType,
				tarOf(t, tar.Header{Typeflag: tar.TypeSymlink, Name: "SKILL.md", Linkname: "/etc/passwd"}), 1)),
			agentskill.ErrInvalidFolder,
		},
		{
			"a path that leaves the folder",
			push(t, rawImage(t, agentskill.ConfigMediaType, agentskill.LayerMediaType,
				tarOf(t, tar.Header{Typeflag: tar.TypeReg, Name: "../SKILL.md", Mode: 0o644}), 1)),
			agentskill.ErrInvalidFolder,
		},
		{
			"a layer over the limit",
			push(t, rawImage(t, agentskill.ConfigMediaType, agentskill.LayerMediaType,
				bytes.Repeat([]byte("x"), agentskill.MaxFolderBytes+agentskill.MaxFiles*2048+1), 1)),
			agentskill.ErrOverLimit,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pull(t, tc.ref)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Pull error = %v, want %v", err, tc.want)
			}
		})
	}
	// Two layers.
	two := push(t, rawImage(t, agentskill.ConfigMediaType, agentskill.LayerMediaType, skillTar, 2))
	if _, err := pull(t, two); !errors.Is(err, agentskill.ErrInvalidFolder) {
		t.Errorf("two layers: error = %v, want ErrInvalidFolder", err)
	}
	// The folder name in the request must match the name in the file.
	_, err = agentskill.Pull(context.Background(), good, "other-name", authn.DefaultKeychain)
	if !errors.Is(err, agentskill.ErrInvalidFolder) {
		t.Errorf("name mismatch: error = %v, want ErrInvalidFolder", err)
	}
}
