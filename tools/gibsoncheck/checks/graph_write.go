// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// GraphWriteAnalyzer enforces ADR-0012: the per-tenant Neo4j knowledge graph
// has exactly ONE writer — the graph projector — and no other code may open a
// Neo4j write transaction.
//
// ADR-0007 established the graph as a projection of the ECS World rather than a
// store, but that was a convention no build step checked, and the code drifted:
// by the time ADR-0012 was written four separate paths could write. The inline
// `MERGE (m:Mission …)` in the CreateMission RPC handler is the illustrative
// case — it was added for a dashboard feature, reviewed, and merged, because
// nothing said no. This analyzer is what says no.
//
// # What is flagged
//
// A call to a write-transaction entry point on the Neo4j driver:
//
//	session.ExecuteWrite(ctx, fn)     // neo4j.SessionWithContext
//	session.BeginTransaction(ctx)     // an explicit transaction can write
//
// Detection is type-based, not name-based: the receiver's type must resolve
// into github.com/neo4j/neo4j-go-driver, so an unrelated ExecuteWrite on some
// other type is not flagged and an alias or a renamed import cannot evade it.
//
// # What is NOT flagged, and why
//
// Reads (ExecuteRead) are unrestricted — the graph is a read model and reading
// it is the point. Cypher text is not inspected: the projector's own writes are
// constant Cypher with `$params`, and a rule about query strings would be a
// lint on spelling rather than on who holds the write transaction.
//
// # Allowed locations
//
// Each entry below is an architectural role, not a grandfathered violation.
// This analyzer ships with NO baseline file and should never acquire one: a
// baseline is a list of exceptions that only ever grows, and the invariant it
// protects is small enough not to need one.
//
//   - The projector itself (internal/server/daemon/graph_projector*.go). It is
//     the sole writer, so it is the sole holder of a write transaction.
//
//   - cmd/gibson-migrate — schema DDL (constraints and indexes), run as its own
//     Job. Schema and data have different lifecycles, and folding schema
//     authority into the daemon would put more privilege in the request path,
//     not less (ADR-0012).
//
//   - operators/tenant/cmd/gibson-backup — APOC export. Operational tooling,
//     outside the data plane.
//
//   - internal/engine/graphrag/graph, but only its specific driver-holding
//     files (neo4j.go, session_client.go) — NOT the whole package (gibson#1300).
//     Holding the driver is those files' purpose; Query in each selects a write
//     transaction from the statement text, which schema DDL migrations and the
//     being-retired ingest loader still rely on. A new write-capable method
//     added in any OTHER file of the package is flagged, so the exemption can no
//     longer silently absorb a fresh write path. (The former whole-package
//     exemption justified itself by "the GraphClient interface no longer
//     re-exports a write transaction" — which had gone stale: Query is
//     write-capable, and the dormant CreateNode/CreateRelationship/DeleteNode
//     methods were removed rather than left to prove the claim false.)
//
// Test files are exempt: a test that seeds a fixture graph is not the data
// plane, and the invariant this protects is about production write paths. The
// analyzer's own testdata fixtures are exempt for the same reason.
//
// Spec: ADR-0012 (single-writer graph ingress), ADR-0007 (world-sourced graph
// projection), gibson#1254.
var GraphWriteAnalyzer = &analysis.Analyzer{
	Name: "graphwrite",
	Doc:  "fail on any Neo4j write transaction opened outside the graph projector (ADR-0012)",
	Run:  runGraphWrite,
}

// neo4jDriverModulePath identifies the Neo4j Go driver by module path. The
// receiver type of a flagged call must live under it.
const neo4jDriverModulePath = "github.com/neo4j/neo4j-go-driver"

// neo4jWriteMethods are the driver methods that hand the caller the ability to
// write. ExecuteRead is deliberately absent.
var neo4jWriteMethods = map[string]string{
	"ExecuteWrite":     "opens a managed write transaction",
	"BeginTransaction": "opens an explicit transaction, which may write",
}

// graphWriteAllowedPackages lists package-path substrings permitted to open a
// Neo4j write transaction. See the analyzer doc comment for the justification
// of each; do not add entries to silence a finding.
var graphWriteAllowedPackages = []string{
	// Neo4j schema DDL, run as its own Job outside the data plane.
	"github.com/zeroroot-ai/gibson/cmd/gibson-migrate",

	// APOC export; operational tooling outside the data plane.
	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup",

	// The analyzer itself and its fixtures.
	"/tools/gibsoncheck",
	"/testdata/",
}

// graphWriteAdapterPackage is the driver-adapter package. Holding the driver is
// its purpose, but only its specific driver-holding files may open a write
// transaction — a NEW write-capable method added in any other file of the
// package is flagged (gibson#1300). This replaces the former whole-package
// exemption, whose justification ("the GraphClient interface no longer
// re-exports a write transaction") had gone stale.
const graphWriteAdapterPackage = "github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"

// graphWriteAdapterFiles are the base names within the adapter package that
// legitimately hold the Neo4j driver/session. Query in each selects its
// transaction mode from the statement text (schema DDL + the being-retired
// loader still need write mode); everything else in the package is read-only
// and must stay that way.
var graphWriteAdapterFiles = map[string]bool{
	"neo4j.go":          true,
	"session_client.go": true,
}

// graphWriteProjectorPackage is the package the graph projector lives in. Only
// the projector's own files within it are allowed to write.
const graphWriteProjectorPackage = "github.com/zeroroot-ai/gibson/internal/server/daemon"

// graphWriteProjectorFilePrefix matches the projector's files by base name, so
// the projector can be split across files without weakening the rule and so a
// new file in the daemon package does not silently inherit write rights.
const graphWriteProjectorFilePrefix = "graph_projector"

func runGraphWrite(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	for _, allowed := range graphWriteAllowedPackages {
		if strings.Contains(pkgPath, allowed) {
			return nil, nil
		}
	}
	isProjectorPackage := strings.HasSuffix(pkgPath, graphWriteProjectorPackage) ||
		pkgPath == graphWriteProjectorPackage
	isAdapterPackage := pkgPath == graphWriteAdapterPackage

	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		if isProjectorPackage && isGraphProjectorFile(fname) {
			continue
		}
		if isAdapterPackage && graphWriteAdapterFiles[filepath.Base(filepath.ToSlash(fname))] {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			why, isWrite := neo4jWriteMethods[sel.Sel.Name]
			if !isWrite {
				return true
			}
			if !isNeo4jDriverReceiver(pass, sel) {
				return true
			}
			pass.Reportf(sel.Sel.Pos(),
				"%s.%s %s: the Neo4j knowledge graph has one writer, the graph projector "+
					"(internal/server/daemon/graph_projector*.go), and %q is not it. Emit an "+
					"observation and let the projector materialize it, or extend the projector — "+
					"do not open a write transaction here (ADR-0012).",
				exprString(sel.X), sel.Sel.Name, why, pkgPath)
			return true
		})
	}

	return nil, nil
}

// isGraphProjectorFile reports whether the file is one of the projector's own.
func isGraphProjectorFile(fname string) bool {
	return strings.HasPrefix(filepath.Base(filepath.ToSlash(fname)), graphWriteProjectorFilePrefix)
}

// isNeo4jDriverReceiver reports whether the selector's receiver has a type
// defined in the Neo4j driver module. Type-based rather than name-based so an
// unrelated ExecuteWrite is not flagged and a renamed import cannot evade it.
func isNeo4jDriverReceiver(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	if pass.TypesInfo == nil {
		return false
	}
	if selection := pass.TypesInfo.Selections[sel]; selection != nil {
		if isNeo4jDriverType(selection.Recv()) {
			return true
		}
	}
	// Selections misses calls through an interface value in some shapes; fall
	// back to the receiver expression's own type.
	tv, ok := pass.TypesInfo.Types[sel.X]
	if !ok {
		return false
	}
	return isNeo4jDriverType(tv.Type)
}

// isNeo4jDriverType reports whether t (or what it points to) is declared in the
// Neo4j driver module.
func isNeo4jDriverType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return strings.HasPrefix(obj.Pkg().Path(), neo4jDriverModulePath)
}

// exprString renders a receiver expression for the diagnostic message, falling
// back to a placeholder for shapes that are not a plain identifier or selector.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(…)"
	case *ast.IndexExpr:
		return exprString(v.X) + "[…]"
	default:
		return "session"
	}
}
