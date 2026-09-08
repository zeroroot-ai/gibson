// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package packaging guards the contract between the daemon image and the
// operational Jobs that run out of it (gibson#1302).
//
// A one-shot tool under cmd/ that a chart invokes has to be present in the
// image, and "present" is two independent lines in the Dockerfile: a build in
// the builder stage and a copy into the runtime stage. Missing either one is
// invisible in Go — the package compiles, its tests pass, `go build ./...`
// is green — and only shows up when the Job's container fails to start. For a
// pre-upgrade hook that means the whole `helm upgrade` aborts, which is worse
// than not having the Job at all.
//
// Pure unit: reads the Dockerfile and the cmd/ tree, no Docker.
package packaging

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// shippedTools lists the one-shot binaries the daemon image must carry
// alongside the daemon itself, each invoked by an explicit command override
// from a Job, DaemonSet, or Helm hook. Adding a tool here without adding it to
// the Dockerfile fails this test; shipping it in the Dockerfile without listing
// it here also fails, so the list cannot silently drift out of date.
var shippedTools = []string{
	"active-session-backfill",
	// bootstrap-tenant-owner (gibson#1103): a one-time, operator-credentialed
	// one-shot that creates the owner human identity for a tenant on a
	// closed-registration self-hosted install. No Helm hook — invoked ad hoc
	// via `kubectl exec` / a one-off Job, never wired into the standard
	// rollout.
	"bootstrap-tenant-owner",
	"gibson-migrate",
	"lowercase-tenant-owner",
	"sandbox-eviction-handler",
	"tenant-owner-backfill",
}

// repoRoot resolves the module root from this file: tests/packaging/ ⇒ two up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// readDockerfile returns the daemon image's Dockerfile as a string.
func readDockerfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "Dockerfile")
	b, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path, not user input
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// dockerfileScript returns the Dockerfile as shell text: comment lines removed
// and line continuations joined, so a command split across lines reads as one.
func dockerfileScript(dockerfile string) string {
	raw := strings.Split(dockerfile, "\n")
	lines := make([]string, 0, len(raw))
	cur := ""
	for _, line := range raw {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		s := strings.TrimRight(line, " \t")
		if strings.HasSuffix(s, "\\") {
			cur += strings.TrimSuffix(s, "\\") + " "
			continue
		}
		lines = append(lines, cur+s)
		cur = ""
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n")
}

// goBuildArgs returns the argument tokens of every `go build` in the Dockerfile.
// One RUN may hold several — the daemon build picks its flags with an if/else —
// so each invocation is read separately, up to the next shell separator.
func goBuildArgs(dockerfile string) [][]string {
	const marker = "go build "
	var out [][]string
	for _, line := range strings.Split(dockerfileScript(dockerfile), "\n") {
		rest := line
		for {
			i := strings.Index(rest, marker)
			if i < 0 {
				break
			}
			rest = rest[i+len(marker):]
			fields := strings.Fields(rest)
			args := make([]string, 0, len(fields))
			for _, tok := range fields {
				if tok == "then" || tok == "else" || tok == "fi" {
					break
				}
				if end := strings.IndexAny(tok, ";&|"); end >= 0 {
					if end > 0 {
						args = append(args, tok[:end])
					}
					break
				}
				args = append(args, tok)
			}
			out = append(out, args)
		}
	}
	return out
}

// builderOutputs maps every path the builder stage writes a binary to, to the
// command package that produced it. It reads both shapes `go build` accepts:
// `-o <file> <pkg>` names one binary, and `-o <dir>/ <pkg>...` names each binary
// after its package directory. The guard therefore asks what the image contains,
// not how the Dockerfile happens to spell the build.
func builderOutputs(dockerfile string) map[string]string {
	out := map[string]string{}
	for _, args := range goBuildArgs(dockerfile) {
		dest := ""
		pkgs := make([]string, 0, len(args))
		for i, a := range args {
			switch {
			case a == "-o" && i+1 < len(args):
				dest = args[i+1]
			case strings.HasPrefix(a, "-o="):
				dest = strings.TrimPrefix(a, "-o=")
			case strings.HasPrefix(a, "./"):
				pkgs = append(pkgs, a)
			}
		}
		if dest == "" || len(pkgs) == 0 {
			continue
		}
		if strings.HasSuffix(dest, "/") {
			for _, pkg := range pkgs {
				out[dest+path.Base(pkg)] = pkg
			}
			continue
		}
		if len(pkgs) == 1 {
			out[dest] = pkgs[0]
		}
	}
	return out
}

// missingBuilds returns the tools the builder stage never writes to /out, in the
// order given. It is the assertion itself, so a fixture can exercise it.
func missingBuilds(dockerfile string, tools []string) []string {
	outputs := builderOutputs(dockerfile)
	missing := make([]string, 0, len(tools))
	for _, tool := range tools {
		if pkg, ok := outputs["/out/"+tool]; !ok || pkg != "./cmd/"+tool {
			missing = append(missing, tool)
		}
	}
	return missing
}

func TestDaemonImageBuildsEveryShippedTool(t *testing.T) {
	dockerfile := readDockerfile(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			if got := missingBuilds(dockerfile, []string{tool}); len(got) != 0 {
				t.Fatalf("the builder stage never writes /out/%s from ./cmd/%s; "+
					"a Job invoking it would fail to start", tool, tool)
			}
		})
	}
}

// TestBuilderOutputs_ReadsEveryBuildShape pins what the reader understands, so
// the guard keeps asserting the image contents rather than one spelling.
func TestBuilderOutputs_ReadsEveryBuildShape(t *testing.T) {
	tests := []struct {
		name       string
		dockerfile string
		want       map[string]string
	}{
		{
			name:       "one build names one binary",
			dockerfile: `RUN go build -ldflags="-s -w" -o /out/alpha ./cmd/alpha`,
			want:       map[string]string{"/out/alpha": "./cmd/alpha"},
		},
		{
			name: "one build with a directory destination names several",
			dockerfile: "RUN go build -ldflags=\"-s -w\" -o /out/ \\\n" +
				"        ./cmd/alpha \\\n" +
				"        ./cmd/beta",
			want: map[string]string{"/out/alpha": "./cmd/alpha", "/out/beta": "./cmd/beta"},
		},
		{
			name: "an if/else picks flags for the same binary",
			dockerfile: "RUN if [ -n \"$TAGS\" ]; then \\\n" +
				"        go build -tags=\"$TAGS\" -o /out/alpha ./cmd/alpha; \\\n" +
				"    else \\\n" +
				"        go build -o /out/alpha ./cmd/alpha; \\\n" +
				"    fi",
			want: map[string]string{"/out/alpha": "./cmd/alpha"},
		},
		{
			name: "a cache mount does not hide the build",
			dockerfile: "RUN --mount=type=cache,target=/root/.cache/go-build \\\n" +
				"    --mount=type=cache,target=/go/pkg/mod \\\n" +
				"    go build -o /out/alpha ./cmd/alpha",
			want: map[string]string{"/out/alpha": "./cmd/alpha"},
		},
		{
			name:       "a comment naming a package is not a build",
			dockerfile: "# go build -o /out/alpha ./cmd/alpha\nRUN echo hello",
			want:       map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := builderOutputs(tc.dockerfile); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("outputs:\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}

// TestMissingBuilds_CatchesAToolTheImageDropped is the guard's failing fixture:
// a Dockerfile that builds every tool but one must name exactly that one.
func TestMissingBuilds_CatchesAToolTheImageDropped(t *testing.T) {
	const dropped = "beta"
	fixture := "RUN go build -o /out/ ./cmd/alpha ./cmd/gamma"

	got := missingBuilds(fixture, []string{"alpha", dropped, "gamma"})
	if want := []string{dropped}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
}

func TestDaemonImageCopiesEveryShippedToolIntoTheRuntimeStage(t *testing.T) {
	dockerfile := readDockerfile(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			want := "COPY --from=builder /out/" + tool + " /usr/local/bin/" + tool
			if !strings.Contains(dockerfile, want) {
				t.Fatalf("Dockerfile builds %s but never copies it into the runtime stage "+
					"(looked for %q); the binary exists only in the discarded builder layer", tool, want)
			}
		})
	}
}

func TestEveryShippedToolHasACommandPackage(t *testing.T) {
	root := repoRoot(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			dir := filepath.Join(root, "cmd", tool)
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("shipped tool %s has no cmd package at %s: %v", tool, dir, err)
			}
			if !info.IsDir() {
				t.Fatalf("%s is not a directory", dir)
			}
		})
	}
}

func TestShippedToolsListMatchesTheDockerfile(t *testing.T) {
	// The reverse direction: anything the Dockerfile copies into
	// /usr/local/bin must be declared above, so the list stays the readable
	// answer to "what is in this image, and why".
	dockerfile := readDockerfile(t)
	declared := make(map[string]bool, len(shippedTools))
	for _, tool := range shippedTools {
		declared[tool] = true
	}
	// The daemon itself is the image's ENTRYPOINT, not a one-shot tool.
	declared["gibson"] = true

	const prefix = "COPY --from=builder /out/"
	for _, line := range strings.Split(dockerfile, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		name := filepath.Base(fields[len(fields)-1])
		if !declared[name] {
			t.Errorf("Dockerfile ships %q but it is not in shippedTools; add it (with a note "+
				"on what invokes it) so the image contents stay documented", name)
		}
	}
}
