// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package harness — the tool dispatch path guard (gibson#755, ADR-0110).
//
// A tool has two dispatch paths: the sandbox and the work queue. This guard
// fails when a third one appears in the harness. It reads the AST of each
// hand-written Go file of this package and refuses the three ways that a
// third path was built before:
//
//  1. A read of the `grpc_endpoint` metadata key. The daemon dials no address
//     that a component reports.
//  2. A call of `ExecuteProto`, the method that runs a tool object in this
//     process or over a direct connection.
//  3. A call of `StreamExecute` or `NewToolServiceClient`, the direct stream
//     to a tool.
//
// The guard is keyed by content. It also proves that it looked: the two
// permitted dispatch calls must be in the scanned code.
package harness

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// toolDispatchForbiddenCalls names each call that is a third dispatch path.
var toolDispatchForbiddenCalls = map[string]string{
	"ExecuteProto":         "runs a tool object outside the sandbox and the work queue",
	"StreamExecute":        "opens a direct stream to a tool",
	"NewToolServiceClient": "builds a direct client of a tool",
}

// toolDispatchForbiddenKey is the metadata key that selected the direct gRPC
// path.
const toolDispatchForbiddenKey = "grpc_endpoint"

// toolDispatchPermittedCalls are the two dispatch calls of CallToolProto.
var toolDispatchPermittedCalls = []string{"ExecuteWithSpec", "callToolViaWorkQueue"}

// scanToolDispatchPaths returns one line for each third dispatch path in src,
// and the names of the permitted dispatch calls that src holds.
func scanToolDispatchPaths(filename string, src []byte) (violations []string, permitted map[string]bool, err error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", filename, err)
	}
	permitted = map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			name := toolCallSinkCalleeName(node)
			if why, bad := toolDispatchForbiddenCalls[name]; bad {
				violations = append(violations, fmt.Sprintf("%s: call of %s %s", fset.Position(node.Pos()), name, why))
			}
			for _, ok := range toolDispatchPermittedCalls {
				if name == ok {
					permitted[ok] = true
				}
			}
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			if value, uerr := strconv.Unquote(node.Value); uerr == nil && value == toolDispatchForbiddenKey {
				violations = append(violations, fmt.Sprintf("%s: the code reads the %q metadata key", fset.Position(node.Pos()), toolDispatchForbiddenKey))
			}
		}
		return true
	})
	return violations, permitted, nil
}

// TestToolDispatchHasTwoPaths scans the hand-written code of this package.
func TestToolDispatchHasTwoPaths(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	scanned := 0
	found := map[string]bool{}
	var all []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(f) //nolint:gosec // G304: f comes from a glob of this package directory
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		violations, permitted, serr := scanToolDispatchPaths(f, src)
		if serr != nil {
			t.Fatal(serr)
		}
		scanned++
		all = append(all, violations...)
		for name := range permitted {
			found[name] = true
		}
	}
	// The guard must prove that it looked at the dispatch code.
	if scanned < 20 {
		t.Fatalf("scanned %d files; the harness package has many more, so the guard looked at the wrong place", scanned)
	}
	for _, name := range toolDispatchPermittedCalls {
		if !found[name] {
			t.Errorf("the scan found no call of %s; a permitted dispatch path moved, and the guard must move with it", name)
		}
	}
	if len(all) > 0 {
		t.Fatalf("a tool has the sandbox path and the work queue path only (ADR-0110). A third path appeared:\n  %s",
			strings.Join(all, "\n  "))
	}
}

// toolDispatchThirdPathFixture holds each of the three forms of a third path.
const toolDispatchThirdPathFixture = `package harness

func (h *DefaultAgentHarness) thirdPath(ctx context.Context, info component.ComponentInfo) error {
	if endpoint := info.Metadata["grpc_endpoint"]; endpoint != "" {
		t, _ := h.registryAdapter.DiscoverTool(ctx, "x")
		_, err := t.ExecuteProto(ctx, nil)
		return err
	}
	client := toolpb.NewToolServiceClient(conn)
	_, err := client.StreamExecute(ctx)
	return err
}
`

// TestToolDispatchHasTwoPaths_CatchesAThirdPath is the failing fixture.
func TestToolDispatchHasTwoPaths_CatchesAThirdPath(t *testing.T) {
	violations, _, err := scanToolDispatchPaths("third_path_fixture.go", []byte(toolDispatchThirdPathFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 4 {
		t.Fatalf("the guard must name the key read and the three calls; got %d: %v", len(violations), violations)
	}
}

// TestToolDispatchHasTwoPaths_AllowsTheTwoPaths proves that the two permitted
// calls pass, and that a comment that names the key is not a read.
func TestToolDispatchHasTwoPaths_AllowsTheTwoPaths(t *testing.T) {
	const clean = `package harness

// A component cannot set grpc_endpoint.
func (h *DefaultAgentHarness) twoPaths() error {
	if sandbox {
		return h.sandboxedExecutor.ExecuteWithSpec(ctx, name, spec, in, out)
	}
	return h.callToolViaWorkQueue(ctx, tenant, name, in, out, info)
}
`
	violations, permitted, err := scanToolDispatchPaths("clean_fixture.go", []byte(clean))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 0 || len(permitted) != 2 {
		t.Fatalf("violations = %v, permitted = %v; want none and both", violations, permitted)
	}
}
