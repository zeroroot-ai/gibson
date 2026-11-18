// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentskill validates an Agent Skill folder and packs it as an OCI
// image.
//
// An Agent Skill is a folder in the Agent Skills format. It has one SKILL.md
// with a YAML frontmatter and a body. It can also have script, reference and
// asset files. Validate applies the rules of the format and the size limits in
// limits.go. Package writes the folder as one OCI image with one layer. The
// digest of the image is a function of the content only, so the same folder
// always gives the same digest.
//
// This package does not store the image. The caller pushes it.
package agentskill

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"gopkg.in/yaml.v3"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// SkillFile is the name of the file that every Agent Skill folder holds at its
// root.
const SkillFile = "SKILL.md"

// Media types of the OCI image of an Agent Skill.
const (
	// ConfigMediaType is the media type of the config blob.
	ConfigMediaType types.MediaType = "application/vnd.zeroroot.agent-skill.config.v1+json"
	// LayerMediaType is the media type of the one layer. The layer is a tar
	// archive of the folder.
	LayerMediaType types.MediaType = "application/vnd.zeroroot.agent-skill.layer.v1.tar"
)

var (
	// ErrInvalidFolder marks a folder that breaks a rule of the Agent Skills
	// format.
	ErrInvalidFolder = errors.New("invalid Agent Skill folder")
	// ErrOverLimit marks a folder that is over a size limit.
	ErrOverLimit = errors.New("Agent Skill folder is over a size limit")
)

// File is one file of the folder. Path is relative to the root of the folder
// and uses "/" as the separator.
type File struct {
	Path    string
	Content []byte
}

// Manifest is the validated frontmatter of SKILL.md.
type Manifest struct {
	Name          string
	Description   string
	License       string
	Compatibility string
	Metadata      map[string]string
	// AllowedTools holds the names in the allowed-tools field. The field can
	// only narrow what an agent uses.
	AllowedTools []string
	// Body is the text of SKILL.md after the frontmatter.
	Body string
}

// frontmatter is the YAML schema of SKILL.md. The specification does not say
// that a reader refuses an unknown field, so the decoder ignores it.
type frontmatter struct {
	Name          string            `yaml:"name"`
	Description   string            `yaml:"description"`
	License       string            `yaml:"license"`
	Compatibility string            `yaml:"compatibility"`
	Metadata      map[string]string `yaml:"metadata"`
	AllowedTools  string            `yaml:"allowed-tools"`
}

// Validate checks the folder against the Agent Skills format and the size
// limits. folderName is the name of the folder. The name in the frontmatter
// must equal it. Validate returns an error that wraps ErrInvalidFolder or
// ErrOverLimit. It never truncates.
func Validate(folderName string, files []File) (*Manifest, error) {
	if !toolid.ValidSkillName(folderName) {
		return nil, invalidf("folder name %q is not a valid Agent Skill name", folderName)
	}
	if err := checkFiles(files); err != nil {
		return nil, err
	}
	var skill []byte
	for _, f := range files {
		if f.Path == SkillFile {
			skill = f.Content
		}
	}
	if skill == nil {
		return nil, invalidf("the folder has no %s at its root", SkillFile)
	}
	m, err := ParseSkillFile(skill)
	if err != nil {
		return nil, err
	}
	if m.Name != folderName {
		return nil, invalidf("name %q in the frontmatter does not match the folder name %q", m.Name, folderName)
	}
	return m, nil
}

// checkFiles applies the path rules and the size limits to the file list.
func checkFiles(files []File) error {
	if len(files) > MaxFiles {
		return overf("the folder has %d files, the limit is %d", len(files), MaxFiles)
	}
	seen := make(map[string]struct{}, len(files))
	var total int
	for _, f := range files {
		if err := checkPath(f.Path); err != nil {
			return err
		}
		if _, dup := seen[f.Path]; dup {
			return invalidf("the path %q appears twice", f.Path)
		}
		seen[f.Path] = struct{}{}
		if len(f.Content) > MaxFileBytes {
			return overf("the file %q has %d bytes, the limit is %d", f.Path, len(f.Content), MaxFileBytes)
		}
		total += len(f.Content)
		if total > MaxFolderBytes {
			return overf("the folder is over %d bytes", MaxFolderBytes)
		}
	}
	return nil
}

// checkPath refuses a path that is not a clean relative path inside the
// folder. It also refuses a path that a reader could resolve in a different way.
func checkPath(p string) error {
	switch {
	case p == "":
		return invalidf("a file has an empty path")
	case !utf8.ValidString(p):
		return invalidf("the path %q is not valid UTF-8", p)
	case strings.ContainsAny(p, "\\\x00"):
		return invalidf("the path %q has a backslash or a NUL byte", p)
	case strings.HasPrefix(p, "/"):
		return invalidf("the path %q is absolute", p)
	case path.Clean(p) != p:
		return invalidf("the path %q is not in clean form", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return invalidf("the path %q leaves the folder or has an empty segment", p)
		}
	}
	return nil
}

// ParseSkillFile splits SKILL.md into the frontmatter and the body, and
// validates the fields.
func ParseSkillFile(raw []byte) (*Manifest, error) {
	if !utf8.Valid(raw) {
		return nil, invalidf("%s is not valid UTF-8", SkillFile)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return nil, invalidf("%s does not start with a frontmatter", SkillFile)
	}
	var head, body string
	switch {
	case strings.HasPrefix(rest, "---\n"):
		body = strings.TrimPrefix(rest, "---\n")
	case rest == "---":
	default:
		end := strings.Index(rest, "\n---\n")
		switch {
		case end >= 0:
			head, body = rest[:end], rest[end+len("\n---\n"):]
		case strings.HasSuffix(rest, "\n---"):
			head = strings.TrimSuffix(rest, "\n---")
		default:
			return nil, invalidf("the frontmatter of %s has no closing line", SkillFile)
		}
	}
	var fm frontmatter
	dec := yaml.NewDecoder(strings.NewReader(head))
	if err := dec.Decode(&fm); err != nil && !errors.Is(err, io.EOF) {
		return nil, invalidf("the frontmatter of %s is not valid: %v", SkillFile, err)
	}
	if len(body) > MaxBodyBytes {
		return nil, overf("the body of %s has %d bytes, the limit is %d", SkillFile, len(body), MaxBodyBytes)
	}
	if !toolid.ValidSkillName(fm.Name) {
		return nil, invalidf("name %q is not a valid Agent Skill name", fm.Name)
	}
	if strings.TrimSpace(fm.Description) == "" {
		return nil, invalidf("the description is required")
	}
	if n := utf8.RuneCountInString(fm.Description); n > MaxDescriptionLen {
		return nil, invalidf("the description has %d characters, the limit is %d", n, MaxDescriptionLen)
	}
	if n := utf8.RuneCountInString(fm.Compatibility); n > MaxCompatibilityLen {
		return nil, invalidf("compatibility has %d characters, the limit is %d", n, MaxCompatibilityLen)
	}
	return &Manifest{
		Name:          fm.Name,
		Description:   fm.Description,
		License:       fm.License,
		Compatibility: fm.Compatibility,
		Metadata:      fm.Metadata,
		AllowedTools:  strings.Fields(fm.AllowedTools),
		Body:          body,
	}, nil
}

// Artifact is a validated Agent Skill as an OCI image.
type Artifact struct {
	Manifest *Manifest
	Image    v1.Image
	// Digest is the digest of the image manifest. An agent loads by this digest.
	Digest v1.Hash
}

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

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidFolder, fmt.Sprintf(format, args...))
}

func overf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrOverLimit, fmt.Sprintf(format, args...))
}
