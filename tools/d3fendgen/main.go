// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command d3fendgen writes the catalog Domain Pack mitre-d3fend from one
// pinned release of MITRE D3FEND (gibson#1484).
//
// The input is the extract of the release, in this directory, gzip
// compressed. fetch.py writes the extract from the official D3FEND data. The
// tool checks the SHA-256 of the extract before it reads it, and it never
// downloads. The output is internal/engine/ontology/packs/mitre-d3fend.json.
// README.md in this directory records the source and the license.
//
// Usage:
//
//	d3fendgen -write   refresh the pack file
//	d3fendgen -check   exit 1 when the pack file differs from the output
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
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

const (
	// ExtractFile is the pinned extract, relative to the repo root.
	ExtractFile = "tools/d3fendgen/d3fend-extract.json.gz"
	// ExtractSHA256 is the SHA-256 of the uncompressed extract.
	ExtractSHA256 = "16f9050c4d28fdf8b8f87e884fbe1bd0e364cb0330d997346c1425f35b619258"
	// PackFile is the generated pack file, relative to the repo root.
	PackFile = "internal/engine/ontology/packs/mitre-d3fend.json"
	// PackName is the catalog name of the pack.
	PackName = "mitre-d3fend"
	// PackVersion is bumped when the pinned extract changes.
	PackVersion = 1
)

// extract is the content of the extract file.
type extract struct {
	Release        string `json:"release"`
	ReleaseDate    string `json:"release_date"`
	License        string `json:"license"`
	OntologyURL    string `json:"ontology_url"`
	OntologySHA256 string `json:"ontology_sha256"`
	Countermeasure []struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Tactic   string   `json:"tactic"`
		Parent   string   `json:"parent"`
		Counters []string `json:"counters"`
		// NISTControls are the labels that D3FEND uses, for example "AC-17(8)".
		NISTControls []string `json:"nist_controls"`
	} `json:"countermeasures"`
}

// ReadExtract decompresses gz, checks the SHA-256 of the result against want,
// and decodes it.
func ReadExtract(gz io.Reader, want string) (*extract, error) {
	zr, err := gzip.NewReader(gz)
	if err != nil {
		return nil, fmt.Errorf("d3fendgen: open gzip: %w", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("d3fendgen: read gzip: %w", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("d3fendgen: extract SHA-256 is %s, want %s", got, want)
	}
	var ex extract
	if err := json.Unmarshal(raw, &ex); err != nil {
		return nil, fmt.Errorf("d3fendgen: decode extract: %w", err)
	}
	return &ex, nil
}

// BuildPack returns the pack of the extract.
func BuildPack(ex *extract) (ontology.DomainPack, error) {
	if len(ex.Countermeasure) == 0 {
		return ontology.DomainPack{}, errors.New("d3fendgen: the extract has no countermeasure")
	}
	pack := ontology.DomainPack{
		Name:                      PackName,
		Version:                   PackVersion,
		Author:                    "zeroroot",
		Visibility:                ontology.PackVisibilityPublic,
		TaxonomyNodeLabels:        []string{ontology.CountermeasureLabel},
		TaxonomyRelationshipTypes: []string{ontology.AppliesCountermeasureRelationshipType, ontology.CountersRelationshipType},
		TaxonomyNodeIdentity:      map[string]string{ontology.CountermeasureLabel: ontology.CountermeasureIdentityProperty},
		Source: &ontology.PackSource{
			Name:    "MITRE D3FEND",
			Release: ex.Release,
			URL:     ex.OntologyURL,
			License: ex.License,
			SHA256:  ex.OntologySHA256,
		},
	}
	tactics := map[string]struct{}{}
	for _, c := range ex.Countermeasure {
		tactics[c.Tactic] = struct{}{}
		pack.Countermeasures = append(pack.Countermeasures, ontology.Countermeasure{
			ID: c.ID, Name: c.Name, Tactic: c.Tactic, Parent: c.Parent, Counters: c.Counters,
			NISTControls: controlIDs(c.NISTControls),
		})
	}
	for t := range tactics {
		pack.CountermeasureTactics = append(pack.CountermeasureTactics, t)
	}
	sort.Strings(pack.CountermeasureTactics)
	if err := pack.Validate(); err != nil {
		return ontology.DomainPack{}, fmt.Errorf("d3fendgen: %w", err)
	}
	return pack, nil
}

// controlIDs turns the control labels of D3FEND into the control ids of the
// pack nist-800-53-r5: "AC-17(8)" becomes "ac-17.8".
func controlIDs(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		id := strings.ToLower(strings.TrimSpace(l))
		id = strings.ReplaceAll(id, "(", ".")
		id = strings.ReplaceAll(id, ")", "")
		out = append(out, id)
	}
	return out
}

// Render returns the bytes of the pack file.
func Render(pack ontology.DomainPack) ([]byte, error) {
	out, err := json.MarshalIndent(pack, "", " ")
	if err != nil {
		return nil, fmt.Errorf("d3fendgen: encode pack: %w", err)
	}
	return append(out, '\n'), nil
}

// Generate reads the extract in root and returns the bytes of the pack file.
func Generate(root string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(filepath.Join(root, ExtractFile)))
	if err != nil {
		return nil, fmt.Errorf("d3fendgen: %w", err)
	}
	defer func() { _ = f.Close() }()
	ex, err := ReadExtract(f, ExtractSHA256)
	if err != nil {
		return nil, err
	}
	pack, err := BuildPack(ex)
	if err != nil {
		return nil, err
	}
	return Render(pack)
}

// Check returns an error when committed differs from generated.
func Check(committed, generated []byte) error {
	if !bytes.Equal(committed, generated) {
		return fmt.Errorf("d3fendgen: %s differs from the output of the generator; run make d3fend-pack", PackFile)
	}
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

// run is the command: it parses args, writes or checks the pack file, and
// returns the exit code. Errors go to stderr.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("d3fendgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "repository root")
	write := fs.Bool("write", false, "write the pack file")
	check := fs.Bool("check", false, "fail when the pack file is stale")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *write == *check {
		_, _ = fmt.Fprintln(stderr, "d3fendgen: pass exactly one of -write or -check")
		return 2
	}
	out, err := Generate(*dir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	target := filepath.Join(*dir, PackFile)
	if *write {
		if err := os.WriteFile(target, out, 0o600); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	committed, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if err := Check(committed, out); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
