// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package rulescontract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot walks up to the module root, so the test runs the same from the
// package directory and from the repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory; cannot locate the repo root")
		}
		dir = parent
	}
}

// rulesFiles finds every docs/rules.yaml in the tree.
func rulesFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".tmp", "node_modules", "bin", "attic":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "rules.yaml" {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) == "docs" {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// analyzerNames reads the gibsoncheck analyzer names from their own Analyzer
// values. Parsed from the source rather than listed here, so a renamed analyzer
// is caught by this guard instead of silently making a rule's enforced_by stale.
func analyzerNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	dir := filepath.Join(root, "tools", "gibsoncheck", "checks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	re := regexp.MustCompile(`Name:\s*"([a-z0-9_]+)"`)
	out := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// workflowJobs collects every job key, job display name and workflow name.
// Both kinds of name, because enforced_by may reasonably use either.
func workflowJobs(t *testing.T, root string) map[string]bool {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		var doc struct {
			Name string `yaml:"name"`
			Jobs map[string]struct {
				Name string `yaml:"name"`
			} `yaml:"jobs"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			continue
		}
		if doc.Name != "" {
			out[doc.Name] = true
		}
		for key, job := range doc.Jobs {
			out[key] = true
			if job.Name != "" {
				out[job.Name] = true
			}
		}
	}
	return out
}

// The contract: every rules.yaml conforms, and every enforced_by resolves.
//
// This is the whole point. A rule whose enforced_by names a guard that does not
// exist reads as coverage and is not — the same defect as a comment claiming
// one. gibson-auth-001 named `ci:gibson-make-check`, a job in no workflow, and
// six dp-op-* rules carried a shape the schema does not admit.
func TestRulesFilesConformAndEveryEnforcementPointResolves(t *testing.T) {
	root := repoRoot(t)
	files := rulesFiles(t, root)

	if len(files) < MinRulesFiles {
		t.Fatalf("found %d docs/rules.yaml, below the floor of %d — refusing to pass "+
			"on a scan that read almost nothing", len(files), MinRulesFiles)
	}

	analyzers := analyzerNames(t, root)
	if len(analyzers) == 0 {
		t.Fatal("found no gibsoncheck analyzers; every gibsoncheck: entry would fail, " +
			"so this is a broken scan rather than a repo full of broken rules")
	}
	jobs := workflowJobs(t, root)

	total := 0
	for _, path := range files {
		f, err := Load(path)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		rel, _ := filepath.Rel(root, path)
		f.Path = rel
		total += len(f.Rules)

		// A rules file inside a subtree may name scripts relative to that
		// subtree, so both anchors are tried.
		anchors := []string{root}
		if sub := filepath.Dir(filepath.Dir(path)); sub != root {
			anchors = append(anchors, sub)
		}

		for _, p := range CheckFile(f, Enforcement{
			Analyzers: analyzers,
			Jobs:      jobs,
			Anchors:   anchors,
		}) {
			t.Errorf("%s", p)
		}
	}

	if total < MinRules {
		t.Fatalf("read %d rule(s) across %d file(s), below the floor of %d",
			total, len(files), MinRules)
	}
	t.Logf("%d rule(s) in %d file(s); %d analyzers and %d job names known",
		total, len(files), len(analyzers), len(jobs))
}

// conformant is the baseline a fixture mutates one field of.
func conformant() Rule {
	var target yaml.Node
	_ = target.Encode("example.com/x")
	return Rule{
		ID:         "gibson-auth-001",
		Pattern:    &Pattern{Kind: "forbidden_import", Target: target},
		Severity:   "error",
		Message:    "use the other thing",
		EnforcedBy: []string{"gibsoncheck:tenantfromcontext"},
	}
}

// One fixture per rule, each asserting the REASON surfaces. A guard that cannot
// fail is worse than no guard, and a guard whose failure does not say why sends
// the next reader to read its source.
func TestCheck_Fixtures(t *testing.T) {
	env := Enforcement{
		Analyzers: map[string]bool{"tenantfromcontext": true},
		Jobs:      map[string]bool{"analyze": true},
		Anchors:   []string{"."},
	}

	cases := []struct {
		name   string
		mutate func(*Rule)
		want   string // "" means it must pass
	}{
		{"a conformant rule passes", func(*Rule) {}, ""},
		{
			"a pre-schema string pattern fails, naming the shape",
			func(r *Rule) { r.Pattern = nil },
			"requires an object with kind and target",
		},
		{
			"an unknown pattern.kind fails",
			func(r *Rule) { r.Pattern.Kind = "forbidden-call" },
			"pattern.kind",
		},
		{
			"a missing target fails",
			func(r *Rule) { r.Pattern.Target = yaml.Node{} },
			"no target",
		},
		{"a bad severity fails", func(r *Rule) { r.Severity = "fatal" }, "severity"},
		{"an empty message fails", func(r *Rule) { r.Message = "   " }, "no message"},
		{
			"an empty enforced_by fails",
			func(r *Rule) { r.EnforcedBy = nil },
			"enforced_by is empty",
		},
		{
			"an unregistered analyzer fails, naming it",
			func(r *Rule) { r.EnforcedBy = []string{"gibsoncheck:nosuchanalyzer"} },
			"names no registered analyzer",
		},
		{
			"a missing script fails",
			func(r *Rule) { r.EnforcedBy = []string{"script:scripts/does-not-exist.sh"} },
			"script that does not exist",
		},
		{
			"a CI job that does not exist fails",
			func(r *Rule) { r.EnforcedBy = []string{"ci:gibson-make-check"} },
			"names no job or workflow",
		},
		{"a bare manual passes", func(r *Rule) { r.EnforcedBy = []string{"manual"} }, ""},
		{
			"free-text manual fails, pointing at description",
			func(r *Rule) { r.EnforcedBy = []string{"manual review (see the test)"} },
			"free text",
		},
		{
			"an unprefixed enforcement point fails",
			func(r *Rule) { r.EnforcedBy = []string{"someguard"} },
			"has no prefix",
		},
		{"a malformed id fails", func(r *Rule) { r.ID = "GibsonAuth1" }, "is not <repo-slug>"},
		{
			"a legacy slug still passes the shape check",
			func(r *Rule) { r.ID = "dp-op-001" },
			"",
		},
		{
			"a helm validator is accepted without a cross-repo check",
			func(r *Rule) { r.EnforcedBy = []string{"helm:someValidator"} },
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := conformant()
			tc.mutate(&r)
			got := Check(r, env)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no problem, got %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatal("want a problem, got none")
			}
			for _, g := range got {
				if strings.Contains(g, tc.want) {
					return
				}
			}
			t.Errorf("the refusal does not say %q: %v", tc.want, got)
		})
	}
}

// A bare-string pattern is reported as that rule's shape problem rather than as
// a YAML type error over the whole document. The pre-schema files looked exactly
// like this, and a document-level error names neither the rule nor the fix.
func TestLoad_PreSchemaPatternIsARuleProblemNotAParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
rules:
  - id: dp-op-001
    pattern: manual-review
    target:
      requires: "something"
    severity: error
    message: "do the thing"
    enforced_by:
      - "manual review (prose)"
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load must not fail on a pre-schema file; it must report the rule: %v", err)
	}
	if len(f.Rules) != 1 {
		t.Fatalf("parsed %d rule(s), want 1", len(f.Rules))
	}
	problems := CheckFile(f, Enforcement{
		Analyzers: map[string]bool{"x": true},
		Jobs:      map[string]bool{},
		Anchors:   []string{"."},
	})
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"dp-op-001", "kind and target", "free text"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not mention %q:\n%s", want, joined)
		}
	}
	// `version: 1` matches the schema's pattern, so it must NOT be reported.
	if strings.Contains(joined, "version") {
		t.Errorf("version 1 matches ^[0-9]+(\\.[0-9]+){0,2}$ and must not be flagged:\n%s", joined)
	}
}

// A version the schema's pattern rejects IS reported.
func TestCheckFile_BadVersionIsReported(t *testing.T) {
	f := File{Path: "fixture.yaml", Version: "v1", Rules: []Rule{conformant()}}
	problems := CheckFile(f, Enforcement{
		Analyzers: map[string]bool{"tenantfromcontext": true},
		Jobs:      map[string]bool{},
		Anchors:   []string{"."},
	})
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "version") {
		t.Errorf("want the version flagged, got %v", problems)
	}
}

// Two rules with the same id is reported. The schema requires the sequence to be
// unique within a (repo, area) pair, and a duplicate means one of them is
// invisible to anything that looks a rule up by id.
func TestCheckFile_DuplicateIDIsReported(t *testing.T) {
	f := File{Path: "fixture.yaml", Version: "1.0.0", Rules: []Rule{conformant(), conformant()}}
	problems := CheckFile(f, Enforcement{
		Analyzers: map[string]bool{"tenantfromcontext": true},
		Jobs:      map[string]bool{},
		Anchors:   []string{"."},
	})
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "duplicate rule id") {
		t.Errorf("want the duplicate flagged, got %v", problems)
	}
}
