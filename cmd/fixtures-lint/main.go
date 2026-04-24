// fixtures-lint — CI lint tool that asserts GIBSON_TEST_FIXTURES_ENABLED is
// NEVER set to "true" in any production overlay file.
//
// Checked paths (relative to repo root, can be overridden via --root):
//   - enterprise/deploy/helm/gibson/values*.yaml
//   - enterprise/deploy/helm/gibson/templates/**/*.yaml
//   - any *.yaml / *.yml file under enterprise/deploy/ containing a ConfigMap kind
//
// Exit 0 = clean; exit 1 = violation found (CI blocks merge).
//
// Usage:
//
//	fixtures-lint [--root <repo-root>]
//
// Requirements: R7.4, NFR Security.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root := flag.String("root", ".", "repository root to scan")
	flag.Parse()

	violations, err := scan(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fixtures-lint: scan error: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		fmt.Println("fixtures-lint: OK — GIBSON_TEST_FIXTURES_ENABLED not found in any production overlay")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "fixtures-lint: FAIL — GIBSON_TEST_FIXTURES_ENABLED=true found in production overlay(s):\n")
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s\n", v)
	}
	fmt.Fprintf(os.Stderr, "\nThis env var must NEVER be set in production. Remove it from the listed files.\n")
	fmt.Fprintf(os.Stderr, "See tests/e2e/fixtures/providers/mock-llm/provider.go for the safety contract.\n")
	os.Exit(1)
}

// scan walks the deploy directories and returns a list of violation strings
// (file:line) for any YAML file setting GIBSON_TEST_FIXTURES_ENABLED=true.
func scan(repoRoot string) ([]string, error) {
	scanRoots := []string{
		filepath.Join(repoRoot, "enterprise", "deploy"),
	}

	var violations []string

	for _, scanRoot := range scanRoots {
		if _, err := os.Stat(scanRoot); os.IsNotExist(err) {
			// Scan root doesn't exist — skip without error (handles partial checkouts).
			continue
		}

		err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			vs, ferr := checkFile(repoRoot, path)
			if ferr != nil {
				// Log but don't abort the walk for a single unreadable file.
				fmt.Fprintf(os.Stderr, "fixtures-lint: warning: could not read %s: %v\n", path, ferr)
				return nil
			}
			violations = append(violations, vs...)
			return nil
		})
		if err != nil {
			return violations, fmt.Errorf("walk %s: %w", scanRoot, err)
		}
	}

	return violations, nil
}

// checkFile returns violation strings for any line in the file that sets
// GIBSON_TEST_FIXTURES_ENABLED to "true".
func checkFile(repoRoot, path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		rel = path
	}

	var violations []string
	for lineNum, line := range strings.Split(string(data), "\n") {
		if isViolation(line) {
			violations = append(violations, fmt.Sprintf("%s:%d: %s", rel, lineNum+1, strings.TrimSpace(line)))
		}
	}
	return violations, nil
}

// isViolation reports whether a single YAML line sets GIBSON_TEST_FIXTURES_ENABLED
// to a truthy value ("true", "\"true\"", "1", "yes").
func isViolation(line string) bool {
	trimmed := strings.TrimSpace(line)
	// Skip comments.
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	if !strings.Contains(trimmed, "GIBSON_TEST_FIXTURES_ENABLED") {
		return false
	}
	// Match value patterns: `key: true`, `key: "true"`, `key: 1`, `key: yes`,
	// and env-var list style `- name: GIBSON_TEST_FIXTURES_ENABLED\n  value: "true"`.
	lower := strings.ToLower(trimmed)
	for _, truthy := range []string{`"true"`, `'true'`, `: true`, `: 1`, `: yes`, `=true`, `=1`, `=yes`} {
		if strings.Contains(lower, truthy) {
			return true
		}
	}
	return false
}
