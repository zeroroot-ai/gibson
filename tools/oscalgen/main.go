// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command oscalgen writes the control list of the catalog Domain Pack
// nist-800-53-r5 from the OSCAL catalog that NIST publishes (ADR-0113,
// gibson#766).
//
// The input is a pinned copy of the catalog in this directory, gzip
// compressed. The tool checks its SHA-256 before it reads it, and it never
// downloads. The output is internal/engine/ontology/packs/nist-800-53-r5.json.
// The tool writes no mapping rule: a person writes the rules in
// nist-800-53-r5.rules.json next to it.
//
// The text of the catalog is a work of the United States government and is
// in the public domain. README.md in this directory records the source.
//
// Usage:
//
//	oscalgen -write   refresh the pack file
//	oscalgen -check   exit 1 when the pack file differs from the output
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

const (
	// CatalogFile is the pinned copy of the catalog, relative to the repo root.
	CatalogFile = "tools/oscalgen/NIST_SP-800-53_rev5_catalog.json.gz"
	// CatalogSHA256 is the SHA-256 of the uncompressed catalog: release
	// v1.5.0 of usnistgov/oscal-content, SP 800-53 Rev 5.2.0.
	CatalogSHA256 = "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
	// PackFile is the generated pack file, relative to the repo root.
	PackFile = "internal/engine/ontology/packs/nist-800-53-r5.json"
	// PackName is the catalog name of the pack.
	PackName = "nist-800-53-r5"
	// PackVersion is bumped when the pinned catalog changes.
	PackVersion = 1
)

// oscalCatalog is the part of the OSCAL catalog that the tool reads.
type oscalCatalog struct {
	Catalog struct {
		Groups []struct {
			ID       string         `json:"id"`
			Title    string         `json:"title"`
			Controls []oscalControl `json:"controls"`
		} `json:"groups"`
	} `json:"catalog"`
}

type oscalControl struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Props []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"props"`
}

func (c oscalControl) withdrawn() bool {
	for _, p := range c.Props {
		if p.Name == "status" && p.Value == "withdrawn" {
			return true
		}
	}
	return false
}

// ReadCatalog decompresses gz, checks the SHA-256 of the result against
// want, and decodes it.
func ReadCatalog(gz io.Reader, want string) (*oscalCatalog, error) {
	zr, err := gzip.NewReader(gz)
	if err != nil {
		return nil, fmt.Errorf("oscalgen: open gzip: %w", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("oscalgen: read gzip: %w", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("oscalgen: catalog SHA-256 is %s, want %s", got, want)
	}
	var cat oscalCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("oscalgen: decode catalog: %w", err)
	}
	return &cat, nil
}

// BuildPack returns the pack of the catalog: one control for each base
// control that is not withdrawn, in catalog order. Control enhancements are
// not in the list.
func BuildPack(cat *oscalCatalog) (ontology.DomainPack, error) {
	pack := ontology.DomainPack{
		Name:       PackName,
		Version:    PackVersion,
		Author:     "zeroroot",
		Visibility: ontology.PackVisibilityPublic,
	}
	for _, g := range cat.Catalog.Groups {
		for _, c := range g.Controls {
			if c.withdrawn() {
				continue
			}
			pack.Controls = append(pack.Controls, ontology.Control{
				ID:          c.ID,
				Title:       strings.TrimSpace(c.Title),
				Family:      g.ID,
				FamilyTitle: strings.TrimSpace(g.Title),
			})
		}
	}
	if len(pack.Controls) == 0 {
		return ontology.DomainPack{}, errors.New("oscalgen: the catalog has no control")
	}
	if err := pack.Validate(); err != nil {
		return ontology.DomainPack{}, fmt.Errorf("oscalgen: %w", err)
	}
	return pack, nil
}

// Render returns the bytes of the pack file.
func Render(pack ontology.DomainPack) ([]byte, error) {
	out, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("oscalgen: encode pack: %w", err)
	}
	return append(out, '\n'), nil
}

// Generate reads the catalog in root and returns the bytes of the pack file.
func Generate(root string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(filepath.Join(root, CatalogFile)))
	if err != nil {
		return nil, fmt.Errorf("oscalgen: %w", err)
	}
	defer func() { _ = f.Close() }()
	cat, err := ReadCatalog(f, CatalogSHA256)
	if err != nil {
		return nil, err
	}
	pack, err := BuildPack(cat)
	if err != nil {
		return nil, err
	}
	return Render(pack)
}

// Check returns an error when committed differs from generated.
func Check(committed, generated []byte) error {
	if !bytes.Equal(committed, generated) {
		return fmt.Errorf("oscalgen: %s differs from the output of the generator; run make nist-pack", PackFile)
	}
	return nil
}

func main() {
	dir := flag.String("dir", ".", "repository root")
	write := flag.Bool("write", false, "write the pack file")
	check := flag.Bool("check", false, "fail when the pack file is stale")
	flag.Parse()
	if *write == *check {
		fmt.Fprintln(os.Stderr, "oscalgen: pass exactly one of -write or -check")
		os.Exit(2)
	}
	out, err := Generate(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	target := filepath.Join(*dir, PackFile)
	if *write {
		if err := os.WriteFile(target, out, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	committed, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := Check(committed, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
