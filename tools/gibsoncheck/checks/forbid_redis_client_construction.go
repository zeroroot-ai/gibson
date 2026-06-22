package checks

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// ForbidRedisClientConstructionAnalyzer flags any call to
// github.com/redis/go-redis/v9.NewClient in a package whose import path is
// outside the allowlisted prefixes.
//
// This catches the construction-site escape hatch where a package is on the
// raw-store-import allowlist but still mints a process-wide *redis.Client
// directly rather than going through internal/infra/datapool/Conn.
//
// Test files (*_test.go) are exempt: unit-test fixtures may construct their
// own Redis clients against miniredis.
//
// Spec: daemon-mission-finding-per-tenant-cutover Requirement 5.3, 5.4.
var ForbidRedisClientConstructionAnalyzer = &analysis.Analyzer{
	Name:     "forbidredisclientconstruction",
	Doc:      "fail on redis.NewClient() calls outside internal/infra/datapool/ and internal/server/admin/ (daemon-mission-finding-per-tenant-cutover Req 5.3)",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runForbidRedisClientConstruction,
}

// redisClientConstructionAllowlist contains package import-path prefixes
// that are permitted to call redis.NewClient directly. All other packages
// must access Redis through internal/infra/datapool/Conn.Redis.
//
// The allowlist is deliberately narrow:
//   - internal/infra/datapool/ — constructs per-tenant Conn.Redis and the index client.
//   - internal/infra/datapool/admin/ — constructs the cross-tenant admin Redis client.
//   - internal/server/admin/ — admin-plane-only operations.
//   - internal/engine/state/ — foundational StateClient wrapper (global shared Redis).
//     Higher-level packages must go through StateClient, not bypass it.
//   - tools/gibsoncheck/ — the analyzer itself (imports go-redis for type info).
var redisClientConstructionAllowlist = []string{
	"github.com/zeroroot-ai/gibson/internal/infra/datapool",
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/admin",
	"github.com/zeroroot-ai/gibson/internal/server/admin",
	"github.com/zeroroot-ai/gibson/internal/engine/state",
	"github.com/zeroroot-ai/gibson/tools/gibsoncheck",
}

func runForbidRedisClientConstruction(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// If the package is on the allowlist, skip all checks.
	for _, allowed := range redisClientConstructionAllowlist {
		if strings.HasPrefix(pkgPath, allowed) {
			return nil, nil
		}
	}

	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}

		// Check whether this is a call to redis.NewClient.
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}

		if fn.Sel.Name != "NewClient" {
			return
		}

		// Resolve the type of the receiver to confirm it is go-redis.
		obj, ok := pass.TypesInfo.Uses[fn.Sel]
		if !ok {
			return
		}

		pkgName, ok := qualifiedName(obj)
		if !ok {
			return
		}

		if pkgName != "github.com/redis/go-redis/v9" {
			return
		}

		// Exempt test files.
		pos := pass.Fset.Position(call.Pos())
		if strings.HasSuffix(pos.Filename, "_test.go") {
			return
		}

		pass.Reportf(call.Pos(),
			"forbidden call to redis.NewClient in %q — all per-tenant Redis access must go through internal/infra/datapool/Conn.Redis; see docs/data-plane.md for the correct pattern (daemon-mission-finding-per-tenant-cutover Req 5.3)",
			pkgPath)
	})

	return nil, nil
}

// qualifiedName returns the import path of the package that declares obj,
// and reports whether the call is to a named function (not a method or field).
func qualifiedName(obj types.Object) (string, bool) {
	if obj == nil {
		return "", false
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return "", false
	}
	pkg := fn.Pkg()
	if pkg == nil {
		return "", false
	}
	return pkg.Path(), true
}
