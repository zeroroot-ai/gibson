// Command diff-coverage enforces the 85% diff-coverage gate (gibson#794, E3 /
// QUALITY-BARS §4): of the statement lines a PR adds or changes, at least 85%
// must be exercised by the test suite.
//
// Unlike an absolute floor, diff coverage is incremental by construction — it
// only looks at changed lines — so it can be blocking from day one without a
// repo-wide backfill. It is the primary "new code is tested" gate; the absolute
// total-coverage ratchet (scripts/check-coverage-floor.sh) guards against
// overall regression.
//
// Usage:
//
//	diff-coverage -profile coverage.out -base origin/main -threshold 85
//
// Inputs:
//   - a Go coverage profile (go test -coverprofile=...; -covermode=atomic)
//   - the git diff between the merge-base of -base and HEAD
//
// A changed line "counts" only if the profile places it inside a statement
// block. Blank lines, comments, imports, and bare declarations are ignored.
// Generated and test files are excluded from the diff. If the change adds no
// measurable statements, the gate passes (nothing to cover).
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the testable entry point. It returns the process exit code: 0 pass,
// 1 gate failure, 2 operational error.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff-coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profilePath := fs.String("profile", "coverage.out", "path to the Go coverage profile")
	base := fs.String("base", "origin/main", "base git ref to diff against (uses merge-base with HEAD)")
	threshold := fs.Float64("threshold", 85.0, "minimum percent of changed statement lines that must be covered")
	modulePath := fs.String("module", "", "module path prefix to strip from profile paths (default: read from go.mod)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	profile, err := os.ReadFile(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "diff-coverage: reading profile: %v\n", err)
		return 2
	}

	mod := *modulePath
	if mod == "" {
		mod = moduleFromGoMod("go.mod")
	}

	diff, err := gitDiff(*base)
	if err != nil {
		fmt.Fprintf(stderr, "diff-coverage: computing diff: %v\n", err)
		return 2
	}

	report := evaluate(profile, diff, mod, *threshold)
	fmt.Fprint(stdout, report.String())
	if !report.Pass {
		return 1
	}
	return 0
}

// block is a covered/uncovered statement range from the coverage profile.
type block struct {
	start, end int
	covered    bool
}

// evaluate is the pure core: it takes the profile bytes, the git-diff bytes,
// the module prefix, and the threshold, and returns the result. Kept free of
// git/FS access so it is unit-testable.
func evaluate(profile, diff []byte, module string, threshold float64) *Report {
	blocks := parseProfile(profile, module)
	added := parseAddedLines(diff)

	r := &Report{Threshold: threshold}
	for _, file := range sortedKeys(added) {
		if isExcludedFile(file) {
			continue
		}
		fileBlocks, ok := blocks[file]
		if !ok {
			// No profile data for this file's package (tests did not run for
			// it, or it has no statements). Cannot attribute coverage; skip.
			continue
		}
		for _, line := range added[file] {
			covered, isStmt := classify(fileBlocks, line)
			if !isStmt {
				continue
			}
			r.Total++
			if covered {
				r.Covered++
			} else {
				r.Missed = append(r.Missed, fmt.Sprintf("%s:%d", file, line))
			}
		}
	}

	r.Pass = r.Total == 0 || r.Percent() >= threshold
	sort.Strings(r.Missed)
	return r
}

// Report is the diff-coverage outcome.
type Report struct {
	Threshold float64
	Total     int      // changed statement lines considered
	Covered   int      // of those, lines the tests exercised
	Missed    []string // "file:line" of changed-but-uncovered statement lines
	Pass      bool
}

func (r *Report) Percent() float64 {
	if r.Total == 0 {
		return 100.0
	}
	return 100.0 * float64(r.Covered) / float64(r.Total)
}

func (r *Report) String() string {
	var b strings.Builder
	if r.Total == 0 {
		fmt.Fprintf(&b, "diff-coverage: no changed statement lines to cover — PASS\n")
		return b.String()
	}
	fmt.Fprintf(&b, "diff-coverage: %d/%d changed statement lines covered (%.1f%%), threshold %.0f%%\n",
		r.Covered, r.Total, r.Percent(), r.Threshold)
	if !r.Pass {
		fmt.Fprintf(&b, "FAIL: %d changed statement line(s) not covered by tests:\n", len(r.Missed))
		for _, m := range r.Missed {
			fmt.Fprintf(&b, "  %s\n", m)
		}
	} else {
		fmt.Fprintf(&b, "PASS\n")
	}
	return b.String()
}

// profileLineRe matches a coverage profile entry:
//
//	github.com/org/mod/pkg/file.go:12.34,15.2 3 1
var profileLineRe = regexp.MustCompile(`^(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$`)

// parseProfile parses a coverage profile into per-file blocks, with the module
// prefix stripped so keys are repo-relative paths matching git-diff paths.
func parseProfile(profile []byte, module string) map[string][]block {
	out := map[string][]block{}
	prefix := strings.TrimSuffix(module, "/") + "/"
	sc := bufio.NewScanner(bytes.NewReader(profile))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || strings.TrimSpace(line) == "" {
			continue
		}
		m := profileLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		file := m[1]
		if module != "" && strings.HasPrefix(file, prefix) {
			file = strings.TrimPrefix(file, prefix)
		}
		start, _ := strconv.Atoi(m[2])
		end, _ := strconv.Atoi(m[3])
		count, _ := strconv.Atoi(m[4])
		out[file] = append(out[file], block{start: start, end: end, covered: count > 0})
	}
	return out
}

// classify reports, for a line, whether it sits inside any statement block and
// whether that block was covered. A line may fall in multiple blocks (rare,
// nested); covered wins so we never over-penalize.
func classify(blocks []block, line int) (covered, isStmt bool) {
	for _, b := range blocks {
		if line >= b.start && line <= b.end {
			isStmt = true
			if b.covered {
				return true, true
			}
		}
	}
	return false, isStmt
}

var (
	hunkRe    = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)
	newFileRe = regexp.MustCompile(`^\+\+\+ b/(.+)$`)
)

// parseAddedLines parses unified diff (git diff --unified=0) into a map of
// file -> added line numbers (new-side). Only '+' content lines count.
func parseAddedLines(diff []byte) map[string][]int {
	out := map[string][]int{}
	var curFile string
	var newLine int
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			if m := newFileRe.FindStringSubmatch(line); m != nil {
				curFile = m[1]
			} else {
				curFile = "" // /dev/null (deletion) — ignore
			}
		case strings.HasPrefix(line, "@@"):
			if m := hunkRe.FindStringSubmatch(line); m != nil {
				newLine, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if curFile != "" {
				out[curFile] = append(out[curFile], newLine)
				newLine++
			}
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			// deleted line — does not advance the new-side counter
		default:
			// context line — with --unified=0 there are none, but be safe
			if !strings.HasPrefix(line, "\\") {
				newLine++
			}
		}
	}
	return out
}

// isExcludedFile drops files that should not be held to diff coverage: tests,
// generated bindings, generated registry artifacts, and mocks.
func isExcludedFile(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return true
	}
	base := path[strings.LastIndex(path, "/")+1:]
	switch {
	case strings.HasSuffix(path, "_test.go"),
		strings.HasSuffix(path, ".pb.go"),
		strings.HasSuffix(path, "_grpc.pb.go"),
		strings.HasSuffix(path, ".gen.go"),
		strings.HasPrefix(base, "zz_generated"),
		strings.HasPrefix(base, "mock_"),
		strings.HasSuffix(path, "_mock.go"):
		return true
	}
	// Generated authz-registry Go artifact.
	if strings.HasSuffix(path, "internal/platform/authz/registry/registry.go") {
		return true
	}
	return false
}

func sortedKeys(m map[string][]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- git / go.mod helpers (not exercised by unit tests) ---

func gitDiff(base string) ([]byte, error) {
	mergeBase := base
	if out, err := exec.Command("git", "merge-base", base, "HEAD").Output(); err == nil {
		mergeBase = strings.TrimSpace(string(out))
	}
	cmd := exec.Command("git", "diff", "--unified=0", "--no-color", mergeBase+"...HEAD", "--", "*.go")
	return cmd.Output()
}

func moduleFromGoMod(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}
