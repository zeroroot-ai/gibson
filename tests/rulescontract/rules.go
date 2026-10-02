// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package rulescontract checks that every docs/rules.yaml conforms to the
// shared per-repo rules schema, and that each rule's enforced_by names a guard
// that exists.
//
// Each repo in the polyrepo ships a docs/rules.yaml enumerating the
// architectural invariants an editor must not violate. The shared schema lives
// in the SDK at docs/rules-schema.yaml, which says each rules.yaml MUST
// validate against it, and that each rule's enforced_by "points at the concrete
// check that catches violations today".
//
// Neither half was checked. operators/tenant/docs/rules.yaml never validated —
// six rules carried a pre-schema shape its own header admitted was pending
// migration — and gibson-auth-001 named `ci:gibson-make-check`, a job that
// exists in no workflow. An enforced_by naming a guard that does not exist is
// the same defect as a comment claiming one: it reads as coverage (gibson#557,
// gibson#559).
//
// What this does NOT do: evaluate pattern.target against the source. The schema
// stages that as a future `gibsoncheck doc-driven` runner, deliberately, and
// says so. Pre-empting it here would be a second implementation of something
// the polyrepo has already decided where to put. This checks the contract: the
// shape is valid, and every enforcement point named is real.
//
// It lives as a Go test rather than a script for the same reason
// tests/criticalpath does: it runs in the normal unit lane, so it cannot be
// forgotten, and it uses the module's own yaml dependency instead of asking
// whether a CI runner happens to ship PyYAML.
package rulescontract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Floors, so a wrong working directory or a moved file cannot report success
// having read nothing. gibson ships two rules files and 26 rules between them.
const (
	MinRulesFiles = 2
	MinRules      = 10
	// MinTreePaths floors the file walk the scope check matches against. An
	// empty or tiny list would make every glob look dead, or — worse, since
	// the check is skipped on an empty list — make every glob look alive.
	MinTreePaths = 500
)

// PatternKinds are the pattern.kind values the shared schema enumerates.
var PatternKinds = map[string]bool{
	"forbidden_import":    true,
	"forbidden_call":      true,
	"forbidden_string":    true,
	"required_call":       true,
	"required_annotation": true,
}

// Severities are the severity values the schema enumerates.
var Severities = map[string]bool{"error": true, "warning": true, "info": true}

// idRe is the schema's id format: <repo-slug>-<area>-<NNN>.
//
// The SLUG half is not enforced. The schema says it is the GitHub repo short
// name, but the legacy dp-op-* rules predate that and renaming them would break
// every reference. The schema has `replaces` for that migration; doing it is its
// own change, not a side effect of this guard. What is enforced is the shape.
var idRe = regexp.MustCompile(`^[a-z\d-]+-[a-z]{2,8}-\d{3}$`)

// Rule is one entry in a rules.yaml `rules` array.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Pattern     *Pattern `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	Message     string   `yaml:"message"`
	EnforcedBy  []string `yaml:"enforced_by"`
	Scope       []string `yaml:"scope"`
	Exempt      []string `yaml:"exempt"`
	Replaces    []string `yaml:"replaces"`
}

// Pattern is the schema's pattern object: a kind plus a target.
type Pattern struct {
	Kind   string    `yaml:"kind"`
	Target yaml.Node `yaml:"target"`
}

// File is one parsed rules.yaml.
type File struct {
	Path    string
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

var versionRe = regexp.MustCompile(`^\d+(\.\d+){0,2}$`)

// globToRegexp translates a rules.yaml scope glob into a regexp anchored at
// both ends. `**/` matches any number of leading directories (including none),
// a bare `**` matches anything, `*` and `?` stop at a separator.
//
// A translator rather than filepath.Match, because filepath.Match has no `**`
// and would quietly fail to match every pattern that uses one — which is most
// of them, and would make the scope check pass by never matching anything.
//
// MustCompile, with no error return, because every piece written here is either
// regexp.QuoteMeta of one byte or one of four fixed character classes. There is
// no input that makes the result uncompilable, so an error return would be a
// branch no test could reach and no caller could act on.
func globToRegexp(pat string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); {
		switch {
		case strings.HasPrefix(pat[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(pat[i:], "**"):
			b.WriteString(".*")
			i += 2
		case pat[i] == '*':
			b.WriteString("[^/]*")
			i++
		case pat[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// matchesAny reports whether pat matches at least one of paths.
func matchesAny(pat string, paths []string) bool {
	re := globToRegexp(pat)
	for _, p := range paths {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// Enforcement is what a repo can point enforced_by at.
type Enforcement struct {
	// Analyzers are the registered gibsoncheck analyzer names.
	Analyzers map[string]bool
	// Jobs are every workflow job key, job display name and workflow name.
	Jobs map[string]bool
	// Anchors are the directories a script: path may be relative to.
	Anchors []string
	// Paths are the repo-relative tracked files a scope or exempt glob may
	// match, plus the same paths relative to the rules file's own subtree. A
	// glob matching none of them covers nothing, so the rule is inert however
	// well its enforced_by resolves. Empty disables the check, so a harness
	// that failed to list files does not fail every rule.
	Paths []string
}

// Check returns every problem with one rule. Empty means it conforms and every
// enforcement point it names resolves.
func Check(r Rule, env Enforcement) []string {
	var out []string

	switch {
	case r.ID == "":
		out = append(out, "has no id")
	case !idRe.MatchString(r.ID):
		out = append(out, fmt.Sprintf("id %q is not <repo-slug>-<area>-<NNN>", r.ID))
	}

	if r.Pattern == nil {
		out = append(out,
			"pattern is missing or is not an object; the schema requires an object with kind and target")
	} else {
		if !PatternKinds[r.Pattern.Kind] {
			out = append(out, fmt.Sprintf(
				"pattern.kind %q is not one of forbidden_import, forbidden_call, "+
					"forbidden_string, required_call, required_annotation", r.Pattern.Kind))
		}
		if r.Pattern.Target.IsZero() {
			out = append(out, "pattern has no target")
		}
	}

	if !Severities[r.Severity] {
		out = append(out, fmt.Sprintf("severity %q is not one of error, warning, info", r.Severity))
	}

	if strings.TrimSpace(r.Message) == "" {
		out = append(out, "has no message, so a violation cannot say what to do instead")
	}

	// A scope or exempt glob that matches nothing is dead weight: it reads as
	// coverage and provides none. Ten of gibson's 88 entries named paths that
	// had been moved or deleted, including two whole rules that covered no file
	// at all, and gibson#550 was written against one of them.
	if len(env.Paths) > 0 {
		for _, field := range []struct {
			name string
			pats []string
		}{{"scope", r.Scope}, {"exempt", r.Exempt}} {
			for _, pat := range field.pats {
				if !matchesAny(pat, env.Paths) {
					out = append(out, fmt.Sprintf(
						"%s %q matches no tracked file; the path was moved or deleted, "+
							"so this entry claims coverage it does not have", field.name, pat))
				}
			}
		}
	}

	if len(r.EnforcedBy) == 0 {
		out = append(out, "enforced_by is empty; the schema requires a non-empty list")
		return out
	}

	for _, raw := range r.EnforcedBy {
		e := strings.TrimSpace(raw)
		if e == "manual" {
			continue
		}
		if strings.HasPrefix(e, "manual ") {
			out = append(out, fmt.Sprintf(
				"enforced_by %q is free text; the schema enumerates bare \"manual\" — "+
					"put the prose in description", e))
			continue
		}
		prefix, value, found := strings.Cut(e, ":")
		if !found {
			out = append(out, fmt.Sprintf(
				"enforced_by %q has no prefix; want one of gibsoncheck:, script:, "+
					"helm:, ci: or bare manual", e))
			continue
		}
		switch prefix {
		case "gibsoncheck":
			if !env.Analyzers[value] {
				out = append(out, fmt.Sprintf(
					"enforced_by %q names no registered analyzer (tools/gibsoncheck/checks has %d)",
					e, len(env.Analyzers)))
			}
		case "script":
			if !existsUnder(env.Anchors, value) {
				out = append(out, fmt.Sprintf("enforced_by %q names a script that does not exist", e))
			}
		case "ci":
			if !env.Jobs[value] {
				out = append(out, fmt.Sprintf(
					"enforced_by %q names no job or workflow in .github/workflows", e))
			}
		case "helm":
			// A chart validator lives in zeroroot-ai/charts. Out of reach from
			// here, and inventing a cross-repo check is how a guard starts lying.
		default:
			out = append(out, fmt.Sprintf("enforced_by %q has an unrecognised prefix %q", e, prefix))
		}
	}

	return out
}

func existsUnder(anchors []string, rel string) bool {
	for _, a := range anchors {
		if _, err := os.Stat(filepath.Join(a, rel)); err == nil {
			return true
		}
	}
	return false
}

// CheckFile returns every problem in one file, including the file-level ones.
func CheckFile(f File, env Enforcement) []string {
	var out []string
	if !versionRe.MatchString(f.Version) {
		out = append(out, fmt.Sprintf(
			"%s: version %q does not match the schema's ^[0-9]+(\\.[0-9]+){0,2}$",
			f.Path, f.Version))
	}
	if len(f.Rules) == 0 {
		return append(out, f.Path+": has no rules")
	}
	seen := map[string]bool{}
	for _, r := range f.Rules {
		if r.ID != "" && seen[r.ID] {
			out = append(out, fmt.Sprintf("%s: duplicate rule id %q", f.Path, r.ID))
		}
		seen[r.ID] = true
		for _, p := range Check(r, env) {
			out = append(out, fmt.Sprintf("%s: %s %s", f.Path, orUnnamed(r.ID), p))
		}
	}
	return out
}

func orUnnamed(id string) string {
	if id == "" {
		return "<no id>"
	}
	return id
}

// Load parses one rules.yaml.
//
// A pre-schema `pattern: forbidden-call` (a bare string where the schema wants
// an object) must be reported as that rule's shape problem, not as a YAML type
// error over the whole document — so the decode is two-stage.
func Load(path string) (File, error) {
	// #nosec G304 -- path comes from a walk of the repo's own tracked tree, not
	// from a caller or a request.
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read %s: %w", path, err)
	}

	var loose struct {
		Version yaml.Node   `yaml:"version"`
		Rules   []yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(b, &loose); err != nil {
		return File{}, fmt.Errorf("parse %s: %w", path, err)
	}

	f := File{Path: path}
	if !loose.Version.IsZero() {
		// Decoded as a string so `version: 1` and `version: "1.0.0"` are both
		// compared against the schema's pattern rather than one of them failing
		// to decode.
		_ = loose.Version.Decode(&f.Version)
		if f.Version == "" {
			f.Version = loose.Version.Value
		}
	}

	for _, node := range loose.Rules {
		// `pattern` is decoded as a Node and only then shaped, so a pre-schema
		// bare string leaves Rule.Pattern nil and Check reports it as that
		// rule's shape problem. Decoding straight into *Pattern would fail the
		// whole document with a YAML type error naming neither the rule nor the
		// fix.
		var raw struct {
			ID          string    `yaml:"id"`
			Description string    `yaml:"description"`
			Pattern     yaml.Node `yaml:"pattern"`
			Severity    string    `yaml:"severity"`
			Message     string    `yaml:"message"`
			EnforcedBy  []string  `yaml:"enforced_by"`
			Scope       []string  `yaml:"scope"`
			Exempt      []string  `yaml:"exempt"`
			Replaces    []string  `yaml:"replaces"`
		}
		if err := node.Decode(&raw); err != nil {
			return File{}, fmt.Errorf("parse %s: a rule did not decode: %w", path, err)
		}
		r := Rule{
			ID:          raw.ID,
			Description: raw.Description,
			Severity:    raw.Severity,
			Message:     raw.Message,
			EnforcedBy:  raw.EnforcedBy,
			Scope:       raw.Scope,
			Exempt:      raw.Exempt,
			Replaces:    raw.Replaces,
		}
		if raw.Pattern.Kind == yaml.MappingNode {
			var p Pattern
			if err := raw.Pattern.Decode(&p); err != nil {
				return File{}, fmt.Errorf("parse %s: rule %s pattern: %w", path, r.ID, err)
			}
			r.Pattern = &p
		}
		f.Rules = append(f.Rules, r)
	}
	return f, nil
}
