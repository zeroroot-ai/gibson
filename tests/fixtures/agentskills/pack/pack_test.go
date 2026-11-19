// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"archive/tar"
	"errors"
	"flag"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
)

const skillText = "---\nname: web-recon\ndescription: Find web hosts.\n---\nUse @TOOL@ first.\n"

// writeSkill writes a valid Agent Skill folder and returns its path.
func writeSkill(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "web-recon")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "references"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillText), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "references", "guide.md"), []byte("guide @TOOL@"), 0o600))
	return dir
}

func TestSetFlags(t *testing.T) {
	var s setFlags
	require.NoError(t, s.Set("A=1"))
	require.NoError(t, s.Set("B=2"))
	assert.Equal(t, "A=1,B=2", s.String())
}

func TestReadFolder_ReplacesKeysAndUsesSlashPaths(t *testing.T) {
	files, err := readFolder(writeSkill(t), map[string]string{"@TOOL@": "nmap"})

	require.NoError(t, err)
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = string(f.Content)
	}
	assert.Equal(t, "guide nmap", got["references/guide.md"])
	assert.Contains(t, got["SKILL.md"], "Use nmap first.")
	assert.Len(t, got, 2)
}

func TestReadFolder_MissingFolder(t *testing.T) {
	files, err := readFolder(filepath.Join(t.TempDir(), "absent"), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "read the folder")
	assert.Nil(t, files)
}

func TestReadFolder_UnreadableFile(t *testing.T) {
	dir := writeSkill(t)
	require.NoError(t, os.Symlink(filepath.Join(dir, "absent"), filepath.Join(dir, "broken")))

	_, err := readFolder(dir, nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "read ")
}

func TestPackFolder_SameFolderSameDigest(t *testing.T) {
	files, err := readFolder(writeSkill(t), nil)
	require.NoError(t, err)
	reversed := []agentskill.File{files[len(files)-1], files[0]}

	_, a, err := packFolder("web-recon", files)
	require.NoError(t, err)
	_, b, err := packFolder("web-recon", reversed)
	require.NoError(t, err)

	assert.Equal(t, a, b, "the digest does not depend on the order of the files")
	assert.True(t, strings.HasPrefix(a.String(), "sha256:"))
}

func TestPackFolder_RefusesAFolderThatDoesNotValidate(t *testing.T) {
	files, err := readFolder(writeSkill(t), nil)
	require.NoError(t, err)

	img, digest, err := packFolder("other-name", files)

	require.Error(t, err)
	assert.ErrorContains(t, err, "validate the folder")
	assert.Nil(t, img)
	assert.Empty(t, digest.Hex)
}

func TestTarLayer_SortsEntriesAndClearsTimeAndOwner(t *testing.T) {
	layer, err := tarLayer([]agentskill.File{
		{Path: "b.md", Content: []byte("two")},
		{Path: "a.md", Content: []byte("one")},
	})
	require.NoError(t, err)
	rc, err := layer.Uncompressed()
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
		assert.True(t, hdr.ModTime.IsZero() || hdr.ModTime.Unix() == 0, "no time in the header")
		assert.Empty(t, hdr.Uname)
		assert.Equal(t, int64(0o644), hdr.Mode)
	}
	assert.Equal(t, []string{"a.md", "b.md"}, names)
}

// runWith runs the command with the arguments and a clean flag set.
func runWith(t *testing.T, args ...string) error {
	t.Helper()
	saved, savedArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("pack", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"pack"}, args...)
	t.Cleanup(func() { flag.CommandLine, os.Args = saved, savedArgs })
	return run()
}

func TestRun_RejectsBadArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no flags", nil, "both -dir and -repo are required"},
		{"no repo", []string{"-dir", "x"}, "both -dir and -repo are required"},
		{"set without a value", []string{"-dir", "x", "-repo", "r", "-set", "novalue"}, "is not KEY=value"},
		{"set without a key", []string{"-dir", "x", "-repo", "r", "-set", "=v"}, "is not KEY=value"},
		{"missing folder", []string{"-dir", filepath.Join(t.TempDir(), "absent"), "-repo", "r"}, "read the folder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runWith(t, tt.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestRun_RefusesAFolderThatDoesNotValidate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wrong-name")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillText), 0o600))

	err := runWith(t, "-dir", dir, "-repo", "127.0.0.1:1/skills/x")

	require.Error(t, err)
	assert.ErrorContains(t, err, "package the folder")
}

func TestRun_RefusesABadRepository(t *testing.T) {
	err := runWith(t, "-dir", writeSkill(t), "-repo", "NOT A REPO")

	require.Error(t, err)
	assert.ErrorContains(t, err, "build the digest reference")
}

func TestRun_PushesTheImageAndPrintsTheReference(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("REGISTRY_USERNAME", "ci")
	t.Setenv("REGISTRY_PASSWORD", "secret")

	out := captureStdout(t, func() {
		require.NoError(t, runWith(t, "-dir", writeSkill(t), "-repo", host+"/skills/web-recon",
			"-set", "@TOOL@=nmap"))
	})

	ref := strings.TrimSpace(out)
	assert.True(t, strings.HasPrefix(ref, host+"/skills/web-recon@sha256:"), "got %q", ref)
}

func TestRun_PushFailureNamesTheReference(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()

	err := runWith(t, "-dir", writeSkill(t), "-repo", host+"/skills/web-recon")

	require.Error(t, err)
	assert.ErrorContains(t, err, "push "+host+"/skills/web-recon@sha256:")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}
