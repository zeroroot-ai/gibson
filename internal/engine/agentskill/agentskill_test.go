// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill_test

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
)

var (
	errInvalid = agentskill.ErrInvalidFolder
	errOver    = agentskill.ErrOverLimit
)

type file = agentskill.File

const validSkill = "---\nname: web-recon\ndescription: Map a web target before a scan.\n" +
	"license: Apache-2.0\ncompatibility: Needs httpx.\nmetadata:\n  author: acme\n" +
	"allowed-tools: native:httpx native:nmap\n---\n# Steps\nRun httpx first.\n"

func folder(extra ...file) []file {
	return append([]file{{Path: "SKILL.md", Content: []byte(validSkill)}}, extra...)
}

func TestValidate_AcceptsAValidFolder(t *testing.T) {
	m, err := agentskill.Validate("web-recon", folder(
		file{Path: "references/guide.md", Content: []byte("guide")},
		file{Path: "scripts/run.sh", Content: []byte("echo")},
	))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if m.Name != "web-recon" || m.License != "Apache-2.0" || m.Metadata["author"] != "acme" {
		t.Errorf("manifest = %+v", m)
	}
	if got := strings.Join(m.AllowedTools, ","); got != "native:httpx,native:nmap" {
		t.Errorf("AllowedTools = %q", got)
	}
	if m.Body != "# Steps\nRun httpx first.\n" {
		t.Errorf("Body = %q", m.Body)
	}
}

func skillWith(front string) []file {
	return []file{{Path: "SKILL.md", Content: []byte("---\n" + front + "---\nbody\n")}}
}

func TestValidate_Refusals(t *testing.T) {
	tooLong := strings.Repeat("d", agentskill.MaxDescriptionLen+1)
	cases := []struct {
		name   string
		folder string
		files  []file
		want   error
	}{
		{"no SKILL.md", "web-recon", []file{{Path: "a.md", Content: []byte("x")}}, errInvalid},
		{"lowercase skill.md", "web-recon", []file{{Path: "skill.md", Content: []byte(validSkill)}}, errInvalid},
		{"no frontmatter", "web-recon", []file{{Path: "SKILL.md", Content: []byte("body")}}, errInvalid},
		{"no closing line", "web-recon", []file{{Path: "SKILL.md", Content: []byte("---\nname: a\n")}}, errInvalid},
		{"no name", "web-recon", skillWith("description: d\n"), errInvalid},
		{"no description", "web-recon", skillWith("name: web-recon\n"), errInvalid},
		{"blank description", "web-recon", skillWith("name: web-recon\ndescription: '  '\n"), errInvalid},
		{"name mismatch", "web-recon", skillWith("name: other\ndescription: d\n"), errInvalid},
		{"uppercase name", "Web-Recon", skillWith("name: Web-Recon\ndescription: d\n"), errInvalid},
		{"double hyphen", "a--b", skillWith("name: a--b\ndescription: d\n"), errInvalid},
		{"duplicate field", "web-recon", skillWith("name: web-recon\nname: web-recon\ndescription: d\n"), errInvalid},
		{"description over 1024", "web-recon", skillWith("name: web-recon\ndescription: " + tooLong + "\n"), errInvalid},
		{
			"compatibility over 500", "web-recon",
			skillWith("name: web-recon\ndescription: d\ncompatibility: " + strings.Repeat("c", 501) + "\n"),
			errInvalid,
		},
		{"metadata not a map", "web-recon", skillWith("name: web-recon\ndescription: d\nmetadata: x\n"), errInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := agentskill.Validate(tc.folder, tc.files)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// The Agent Skills specification does not say that a reader refuses an unknown
// field, so Validate ignores it.
func TestValidate_IgnoresAnUnknownField(t *testing.T) {
	m, err := agentskill.Validate("web-recon", skillWith("name: web-recon\ndescription: d\nowner: x\n"))
	if err != nil || m.Name != "web-recon" {
		t.Fatalf("Validate = %+v, %v, want the manifest", m, err)
	}
}

func TestValidate_PathsThatLeaveTheFolder(t *testing.T) {
	for _, p := range []string{
		"../x", "a/../../x", "/etc/passwd", "a//b", "./a", "a/./b", "a/", "a\\b", "a\x00b", "", "a/..",
	} {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			_, err := agentskill.Validate("web-recon", folder(file{Path: p, Content: []byte("x")}))
			if !errors.Is(err, errInvalid) {
				t.Fatalf("path %q: error = %v, want ErrInvalidFolder", p, err)
			}
		})
	}
	_, err := agentskill.Validate("web-recon", folder(
		file{Path: "a.md"}, file{Path: "a.md"}))
	if !errors.Is(err, errInvalid) {
		t.Errorf("a duplicate path: error = %v, want ErrInvalidFolder", err)
	}
}

func TestValidate_SizeLimits(t *testing.T) {
	withBody := func(n int) []file {
		body := strings.Repeat("b", n)
		return []file{{
			Path:    "SKILL.md",
			Content: []byte("---\nname: web-recon\ndescription: d\n---\n" + body),
		}}
	}
	if _, err := agentskill.Validate("web-recon", withBody(agentskill.MaxBodyBytes)); err != nil {
		t.Errorf("a body at the limit: %v", err)
	}
	if _, err := agentskill.Validate("web-recon", withBody(agentskill.MaxBodyBytes+1)); !errors.Is(err, errOver) {
		t.Errorf("a body over the limit: error = %v, want ErrOverLimit", err)
	}

	big := make([]byte, agentskill.MaxFileBytes)
	if _, err := agentskill.Validate("web-recon", folder(file{Path: "a.bin", Content: big})); err != nil {
		t.Errorf("a file at the limit: %v", err)
	}
	over := make([]byte, agentskill.MaxFileBytes+1)
	_, err := agentskill.Validate("web-recon", folder(file{Path: "a.bin", Content: over}))
	if !errors.Is(err, errOver) {
		t.Errorf("a file over the limit: error = %v, want ErrOverLimit", err)
	}

	// Nine files of 1 MiB are 9 MiB, over the 8 MiB folder limit.
	many := make([]file, 0, 9)
	for i := range 9 {
		many = append(many, file{Path: fmt.Sprintf("f%d.bin", i), Content: big})
	}
	if _, err := agentskill.Validate("web-recon", folder(many...)); !errors.Is(err, errOver) {
		t.Errorf("a folder over the limit: error = %v, want ErrOverLimit", err)
	}

	files := make([]file, 0, agentskill.MaxFiles)
	for i := range agentskill.MaxFiles {
		files = append(files, file{Path: fmt.Sprintf("f%d.md", i), Content: []byte("x")})
	}
	if _, err := agentskill.Validate("web-recon", folder(files[:agentskill.MaxFiles-1]...)); err != nil {
		t.Errorf("200 files: %v", err)
	}
	if _, err := agentskill.Validate("web-recon", folder(files...)); !errors.Is(err, errOver) {
		t.Errorf("201 files: error = %v, want ErrOverLimit", err)
	}
}

func TestPackage_DigestDependsOnContentOnly(t *testing.T) {
	a := folder(
		file{Path: "references/a.md", Content: []byte("a")},
		file{Path: "scripts/b.sh", Content: []byte("b")},
	)
	b := folder(
		file{Path: "scripts/b.sh", Content: []byte("b")},
		file{Path: "references/a.md", Content: []byte("a")},
	)
	one, err := agentskill.Package("web-recon", a)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	two, err := agentskill.Package("web-recon", b)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	if one.Digest != two.Digest {
		t.Errorf("digest differs with file order: %s and %s", one.Digest, two.Digest)
	}
	changed := folder(
		file{Path: "references/a.md", Content: []byte("changed")},
		file{Path: "scripts/b.sh", Content: []byte("b")},
	)
	three, err := agentskill.Package("web-recon", changed)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	if three.Digest == one.Digest {
		t.Error("a changed file gave the same digest")
	}
}

func TestPackage_LayerHoldsTheFolder(t *testing.T) {
	art, err := agentskill.Package("web-recon", folder(file{Path: "references/a.md", Content: []byte("a")}))
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	layers, err := art.Image.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("Layers = %d, %v, want 1", len(layers), err)
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatalf("Uncompressed: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got := map[string]string{}
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		got[hdr.Name] = string(data)
	}
	if len(got) != 2 || got["references/a.md"] != "a" || got["SKILL.md"] != validSkill {
		t.Errorf("layer files = %v", got)
	}
}

func TestPackage_RefusesAnInvalidFolder(t *testing.T) {
	if _, err := agentskill.Package("web-recon", nil); !errors.Is(err, errInvalid) {
		t.Errorf("Package of no files: error = %v, want ErrInvalidFolder", err)
	}
}

// TestPackage_GoldenDigest pins the digest of one fixed folder. The adk CLI
// pins the same digest. If this digest changes, change both repos together.
func TestPackage_GoldenDigest(t *testing.T) {
	skill := "---\nname: web-recon\ndescription: Map a web target before a scan.\n" +
		"license: Apache-2.0\ncompatibility: Needs httpx.\nmetadata:\n  author: acme\n" +
		"allowed-tools: native:httpx native:nmap\n---\n# Steps\nRun httpx first.\n"
	files := []agentskill.File{
		{Path: "scripts/run.sh", Content: []byte("#!/bin/sh\necho recon\n")},
		{Path: "SKILL.md", Content: []byte(skill)},
		{Path: "references/guide.md", Content: []byte("# Guide\nUse the flags in the order shown.\n")},
	}
	a, err := agentskill.Package("web-recon", files)
	if err != nil {
		t.Fatalf("package the golden folder: %v", err)
	}
	const want = "sha256:d585fe5073f5a1078419e2ab03f1ee00ca8e9256063459a47ee205d054a61e97"
	if a.Digest.String() != want {
		t.Fatalf("digest = %s, want %s", a.Digest, want)
	}
}
