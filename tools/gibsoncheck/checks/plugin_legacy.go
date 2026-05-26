package checks

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// PluginLegacyAnalyzer flags any file under core/sdk/ or core/gibson/internal/
// that imports a pre-release plugin path in its deleted shape.
//
// Three rules are enforced:
//
//  1. Importing "github.com/zeroroot-ai/sdk/pluginkit" → diagnostic.
//     pluginkit provided ConfigSource credential injection via context; it was
//     deleted by the plugin-runtime spec (Spec 2, Phase 1) because it
//     contradicts the broker model.
//
//  2. Importing "github.com/zeroroot-ai/gibson/internal/plugin" → diagnostic.
//     The pre-release daemon registry (DefaultPluginRegistry) was deleted.
//     The path now holds a stub; importing it signals a regression toward
//     the old pattern.
//
//  3. Importing "github.com/zeroroot-ai/sdk/plugin" AND calling or selecting
//     any of the deleted Plugin interface symbol names (Initialize, Query,
//     Shutdown, Health, Methods, MethodDescriptor, Schema) → diagnostic.
//     Note: sdk/plugin is being reborn as the new production package in
//     Phases 2-8 of this spec, so the import path alone is NOT flagged —
//     only the presence of the deleted symbol names matters.
//
// Scope: files whose analyzed-package path contains one of:
//   - "github.com/zeroroot-ai/sdk/"
//   - "github.com/zeroroot-ai/gibson/internal/"
//
// This keeps noise low: the rule is irrelevant for unrelated packages.
//
// Spec: plugin-runtime Requirement 11.6.
var PluginLegacyAnalyzer = &analysis.Analyzer{
	Name: "pluginlegacy",
	Doc:  "flag imports of the pre-release plugin paths deleted by the plugin-runtime spec (Spec 2, Phase 1): sdk/pluginkit, gibson/internal/plugin, and sdk/plugin with old symbol names (plugin-runtime Req 11.6)",
	Run:  runPluginLegacy,
}

// pluginLegacyScopePrefixes lists the package-path substrings that bring a
// package into scope for the pluginlegacy check. Packages whose import path
// does not contain one of these prefixes are skipped.
var pluginLegacyScopePrefixes = []string{
	"github.com/zeroroot-ai/sdk/",
	"github.com/zeroroot-ai/gibson/internal/",
}

// pluginKitImportPath is the deleted pluginkit package import path.
const pluginKitImportPath = "github.com/zeroroot-ai/sdk/pluginkit"

// pluginInternalImportPath is the daemon's internal plugin registry path.
const pluginInternalImportPath = "github.com/zeroroot-ai/gibson/internal/plugin"

// pluginSDKImportPath is the SDK plugin package that will be reborn; the
// import alone is NOT a violation — only the old symbol names are.
const pluginSDKImportPath = "github.com/zeroroot-ai/sdk/plugin"

// deletedPluginSymbols are the method/type names from the deleted pre-release
// Plugin interface shape. Any selector expression on the sdk/plugin import
// that references one of these names is a regression.
var deletedPluginSymbols = map[string]struct{}{
	"Initialize":       {},
	"Query":            {},
	"Shutdown":         {},
	"Health":           {},
	"Methods":          {},
	"MethodDescriptor": {}, // old type name (had InputSchema/OutputSchema schema.JSON fields)
	"Schema":           {}, // referenced by the old MethodDescriptor
	"PluginStatus":     {}, // deleted from sdk/plugin (lives only in internal/plugin stub)
	"ToDescriptor":     {}, // deleted helper function
	"NewConfig":        {}, // deleted builder constructor
	"New":              {}, // deleted plugin.New()
	"MethodHandler":    {}, // deleted handler type
}

func runPluginLegacy(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// Only analyze packages in the defined scope.
	inScope := false
	for _, prefix := range pluginLegacyScopePrefixes {
		if strings.Contains(pkgPath, prefix) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil, nil
	}

	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename

		// Collect which forbidden/watched import paths this file uses,
		// keyed by the local alias (or last path element when no alias).
		var (
			importsPluginKit      bool
			importsInternalPlugin bool
			sdkPluginLocalName    string // non-empty if the file imports sdk/plugin
		)

		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}

			switch path {
			case pluginKitImportPath:
				importsPluginKit = true

				// Only flag non-test files for pluginkit (test fixtures may
				// legitimately reference the stub path).
				if !strings.HasSuffix(fname, "_test.go") {
					pass.Reportf(imp.Pos(),
						"forbidden import %q in %q: sdk/pluginkit was deleted by the plugin-runtime spec (Spec 2, Phase 1) — credential injection via context contradicts the broker model; use secrets.Resolve instead (plugin-runtime Req 11.6)",
						path, pkgPath)
				}

			case pluginInternalImportPath:
				importsInternalPlugin = true

				if !strings.HasSuffix(fname, "_test.go") {
					pass.Reportf(imp.Pos(),
						"forbidden import %q in %q: the pre-release daemon plugin registry was deleted by the plugin-runtime spec (Spec 2, Phase 3); the new registry lives in internal/component/ (Phase 7) — do not re-expand the stub (plugin-runtime Req 11.6)",
						path, pkgPath)
				}

			case pluginSDKImportPath:
				// Determine the local name used for this import.
				if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
					sdkPluginLocalName = imp.Name.Name
				} else {
					// Default local name is the last path component.
					sdkPluginLocalName = "plugin"
				}
			}
		}

		// Suppress unused-variable warnings for rule checks that only record
		// the boolean flag.
		_ = importsPluginKit
		_ = importsInternalPlugin

		// Rule 3: if this file imports sdk/plugin, walk the AST and flag any
		// selector expression whose receiver resolves to the plugin local name
		// AND whose selected name is in deletedPluginSymbols.
		if sdkPluginLocalName == "" {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if _, deleted := deletedPluginSymbols[sel.Sel.Name]; !deleted {
				return true
			}
			// Check whether the X (receiver) is the plugin local import name.
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if ident.Name != sdkPluginLocalName {
				return true
			}
			pass.Reportf(sel.Pos(),
				"reference to deleted symbol %q from sdk/plugin in %q: the pre-release Plugin interface (Initialize/Query/Shutdown/Health/Methods/MethodDescriptor/etc.) was deleted by plugin-runtime spec Phase 1; use the new plugin.Serve API in Phase 8 (plugin-runtime Req 11.6)",
				sdkPluginLocalName+"."+sel.Sel.Name, pkgPath)
			return true
		})
	}

	return nil, nil
}
