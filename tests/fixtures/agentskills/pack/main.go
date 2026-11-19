// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command pack packs one Agent Skill folder as an OCI image and pushes it to a
// registry by digest. The exit test of the Agent Skills epic runs it in the
// workflow, on the runner, before the test starts. It prints the digest
// reference of the image on one line. The test publishes that reference.
//
// Usage:
//
//	pack -dir <folder> -repo <registry>/<repository> [-set @KEY@=value]...
//
// The name of the folder is the name of the Agent Skill. A -set flag replaces
// each occurrence of its key in each file of the folder before the pack. The
// registry credential comes from REGISTRY_USERNAME and REGISTRY_PASSWORD. With
// neither set, the push is anonymous.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
)

// setFlags collects the repeated -set flag.
type setFlags []string

func (s *setFlags) String() string     { return strings.Join(*s, ",") }
func (s *setFlags) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pack:", err)
		os.Exit(1)
	}
}

func run() error {
	dir := flag.String("dir", "", "the Agent Skill folder")
	repo := flag.String("repo", "", "the repository to push to, without a tag or a digest")
	var sets setFlags
	flag.Var(&sets, "set", "a replacement in the form KEY=value. Repeat the flag for more.")
	flag.Parse()
	if *dir == "" || *repo == "" {
		return errors.New("both -dir and -repo are required")
	}
	replacements := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return fmt.Errorf("the -set value %q is not KEY=value", s)
		}
		replacements[k] = v
	}
	files, err := readFolder(*dir, replacements)
	if err != nil {
		return err
	}
	img, digest, err := packFolder(filepath.Base(filepath.Clean(*dir)), files)
	if err != nil {
		return fmt.Errorf("package the folder: %w", err)
	}
	ref, err := name.NewDigest(fmt.Sprintf("%s@%s", *repo, digest.String()), name.StrictValidation)
	if err != nil {
		return fmt.Errorf("build the digest reference: %w", err)
	}
	auth := authn.Anonymous
	if user := os.Getenv("REGISTRY_USERNAME"); user != "" {
		auth = &authn.Basic{Username: user, Password: os.Getenv("REGISTRY_PASSWORD")}
	}
	if err := remote.Write(ref, img, remote.WithAuth(auth)); err != nil {
		return fmt.Errorf("push %s: %w", ref.Name(), err)
	}
	fmt.Println(ref.Name())
	return nil
}

// readFolder reads each regular file of the folder. The path of a file is
// relative to the folder and uses "/".
func readFolder(dir string, replacements map[string]string) ([]agentskill.File, error) {
	var files []agentskill.File
	fsys := os.DirFS(dir)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		raw, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", p, rerr)
		}
		for k, v := range replacements {
			raw = bytes.ReplaceAll(raw, []byte(k), []byte(v))
		}
		files = append(files, agentskill.File{Path: p, Content: raw})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the folder %s: %w", dir, err)
	}
	return files, nil
}
