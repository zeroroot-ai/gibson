// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// gibsoncheck analyzer: constantverdictdouble.
//
// INVARIANT: a test double that stands in for an authorization decision
// must actually READ the arguments that carry the decision. A double
// that discards them and answers affirmatively cannot distinguish a
// working guard from an inert one — so the test passes whether or not
// the production guard does anything, and a real defect ships green.
//
// The design idea that makes the false-positive rate acceptable is an
// ASYMMETRY: a double that always DENIES cannot hide a vulnerability;
// one that always ALLOWS can. Every condition below fires only on the
// permissive side. Measured on this tree that cuts the candidate
// population by roughly three quarters — the fail-closed doubles in
// internal/platform/authz/fga, operators/, and cmd/ are exempt by
// construction rather than by allowlist.
//
// A method is reported when ALL of:
//
//  1. its receiver type implements one of the decision interfaces in
//     securityDecisionIfaces (resolved through TypesInfo, never by
//     name), and the method is one of decisionMethods;
//  2. at least one decision-carrying parameter is unread — `_`, or
//     UNNAMED (the real shape in this tree), or named but never
//     referenced in the body;
//  3. the method can return the PERMISSIVE verdict.
//
// Scope is _test.go files only: this is a guard on test doubles, and
// every other analyzer in this binary deliberately skips test files.

package checks

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const constantVerdictRule = "constant-verdict-double"

// ConstantVerdictDoubleAnalyzer reports permissive authorization test
// doubles that discard the arguments carrying the decision.
var ConstantVerdictDoubleAnalyzer = &analysis.Analyzer{
	Name: "constantverdictdouble",
	Doc:  "flag permissive authorization test doubles that ignore the arguments carrying the decision",
	Run:  runConstantVerdictDouble,
}

func runConstantVerdictDouble(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if !strings.HasSuffix(fname, "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil {
				continue
			}
			checkConstantVerdictMethod(pass, file, fn)
		}
	}
	return nil, nil
}

func checkConstantVerdictMethod(pass *analysis.Pass, file *ast.File, fn *ast.FuncDecl) {
	if _, isDecision := decisionMethods[fn.Name.Name]; !isDecision {
		return
	}
	if !receiverIsDecisionDouble(pass, fn) {
		return
	}

	// (2) at least one decision parameter unread.
	unread, ok := unreadDecisionParams(pass, fn)
	if !ok {
		return
	}

	// (3) the double can answer permissively. This is the asymmetry:
	// a method whose every return denies is not reported.
	why, permissive := doubleIsPermissive(pass, fn)
	if !permissive {
		return
	}

	dir, hasDir := parseConstantVerdictDirective(pass, file, fn)
	if hasDir && !dir.valid {
		pass.Reportf(dir.pos, "%s", dir.problem)
		return
	}
	if hasDir && dir.valid {
		return
	}
	if baselined(constantVerdictRule, pass.Pkg.Path(), recvTypeName(pass, fn)+"."+fn.Name.Name) {
		return
	}
	pass.Reportf(fn.Pos(),
		"constant-verdict double [%s]: this %s double discards the argument(s) that carry the decision (%s) and %s. It answers the same way whether or not the production guard works, so a test using it cannot fail when the guard goes inert. Key the double on the decision arguments.",
		guardBaselineKey(constantVerdictRule, pass.Pkg.Path(), recvTypeName(pass, fn)+"."+fn.Name.Name),
		fn.Name.Name, strings.Join(unread, ", "), why)
}

// receiverIsDecisionDouble reports whether the method's receiver type
// implements one of the committed decision interfaces. Resolving
// through the type system is what stops an unrelated `Check` method
// from matching.
func receiverIsDecisionDouble(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	obj := pass.TypesInfo.Defs[fn.Name]
	if obj == nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	rt := sig.Recv().Type()
	for _, want := range securityDecisionIfaces {
		if typeSatisfiesNamed(pass, rt, want) {
			return true
		}
	}
	return false
}

// decisionParamPositions names, per decision method, the parameter
// positions that carry the decision. Position 0 is the context.
var decisionParamPositions = map[string][]int{
	"Check":           {1, 2, 3},
	"ListObjects":     {1, 2, 3},
	"ListUsers":       {1, 2, 3},
	"ListUsersOfType": {1, 2, 3, 4},
	"BatchCheck":      {1},
	"Authorize":       {1, 2, 3},
	"Verify":          {1},
	"CanInvokeTool":   {1, 2},
	"CanExecute":      {1, 2},
}

// unreadDecisionParams returns the names (or positions) of decision
// parameters the body never reads. An UNNAMED parameter counts as
// unread by definition — that is the real shape of several doubles in
// this tree, and a rule that only looked for `_` would miss them.
func unreadDecisionParams(pass *analysis.Pass, fn *ast.FuncDecl) ([]string, bool) {
	positions, ok := decisionParamPositions[fn.Name.Name]
	if !ok {
		return nil, false
	}
	flat := flattenParams(fn)
	var unread []string
	for _, idx := range positions {
		if idx >= len(flat) {
			continue
		}
		p := flat[idx]
		switch {
		case p.name == "":
			unread = append(unread, "unnamed parameter "+strconv.Itoa(idx))
		case p.name == "_":
			unread = append(unread, "discarded parameter "+strconv.Itoa(idx))
		case !paramIsRead(pass, fn, p.ident):
			unread = append(unread, p.name)
		}
	}
	return unread, len(unread) > 0
}

type flatParam struct {
	name  string
	ident *ast.Ident
}

// flattenParams expands grouped parameter declarations
// (`a, b, c string`) into one entry per parameter, so positional
// indexing matches the call signature.
func flattenParams(fn *ast.FuncDecl) []flatParam {
	var out []flatParam
	if fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			out = append(out, flatParam{})
			continue
		}
		for _, n := range field.Names {
			out = append(out, flatParam{name: n.Name, ident: n})
		}
	}
	return out
}

// paramIsRead reports whether the parameter's object is referenced in
// the body. For a slice-typed parameter (BatchCheck) any reference
// counts, including a field selection on its elements.
func paramIsRead(pass *analysis.Pass, fn *ast.FuncDecl, ident *ast.Ident) bool {
	if ident == nil {
		return false
	}
	target := pass.TypesInfo.Defs[ident]
	if target == nil {
		return false
	}
	read := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if read {
			return false
		}
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if pass.TypesInfo.Uses[id] == target {
			read = true
			return false
		}
		return true
	})
	return read
}

// doubleIsPermissive reports whether some return path yields the
// permissive verdict. For (bool, error): a constant `true`, or a
// non-constant expression (a struct field, a map read) that the test
// can set to true. For ([]string, error): a non-nil slice.
//
// A method whose EVERY return is `false, ...` or `nil, ...` is not
// reported — it cannot hide a vulnerability.
func doubleIsPermissive(pass *analysis.Pass, fn *ast.FuncDecl) (string, bool) {
	obj := pass.TypesInfo.Defs[fn.Name]
	if obj == nil {
		return "", false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil || sig.Results().Len() == 0 {
		return "", false
	}
	first := sig.Results().At(0).Type()

	permissive := false
	why := ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if permissive {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		r := ret.Results[0]
		switch {
		case isBoolType(first):
			if isTrueIdent(r) {
				permissive, why = true, "answers true unconditionally"
				return false
			}
			if isFalseIdent(r) {
				return true // fail-closed return; keep looking
			}
			// A non-constant verdict (a struct field, a map read) is
			// settable to true by the test, so it is permissive.
			if tv, ok := pass.TypesInfo.Types[r]; ok && tv.Value == nil {
				permissive, why = true, "answers from a caller-settable value rather than from the decision arguments"
				return false
			}
		default:
			if _, isSlice := first.Underlying().(*types.Slice); isSlice {
				if isNilIdent(r) {
					return true
				}
				permissive, why = true, "returns a non-empty result set"
				return false
			}
		}
		return true
	})
	return why, permissive
}

func isFalseIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

func recvTypeName(pass *analysis.Pass, fn *ast.FuncDecl) string {
	obj := pass.TypesInfo.Defs[fn.Name]
	if obj == nil {
		return "?"
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "?"
	}
	t := deref(sig.Recv().Type())
	if named, ok := t.(*types.Named); ok && named.Obj() != nil {
		return named.Obj().Name()
	}
	return t.String()
}

// ---------------------------------------------------------------------------
// suppression — the named compensating test is RESOLVED and CHECKED
// ---------------------------------------------------------------------------

const constantVerdictDirective = "gibsoncheck:allow constant-verdict-double"

var constantVerdictGrammar = regexp.MustCompile(
	`gibsoncheck:allow constant-verdict-double\s+(?:covered by ([A-Za-z_][A-Za-z0-9_]*)|tracked: (gibson|deploy|sdk)#(\d+))`)

type constantVerdictDir struct {
	pos     token.Pos
	valid   bool
	problem string
}

// parseConstantVerdictDirective validates the suppression payload
// rather than merely detecting its presence. For the `covered by`
// form the named test must EXIST in the package and must assert the
// DENY side. That closes the loop that bites in practice: someone
// weakens or deletes the compensating test months later and the
// suppression silently becomes a hole.
func parseConstantVerdictDirective(pass *analysis.Pass, file *ast.File, fn *ast.FuncDecl) (constantVerdictDir, bool) {
	var candidates []*ast.Comment
	if fn.Doc != nil {
		candidates = append(candidates, fn.Doc.List...)
	}
	fnLine := pass.Fset.Position(fn.Pos()).Line
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if l := pass.Fset.Position(c.Pos()).Line; l >= fnLine-4 && l <= fnLine {
				candidates = append(candidates, c)
			}
		}
	}
	for _, c := range candidates {
		if !strings.Contains(c.Text, constantVerdictDirective) {
			continue
		}
		d := constantVerdictDir{pos: token.Pos(c.Pos())}
		m := constantVerdictGrammar.FindStringSubmatch(c.Text)
		if m == nil {
			d.problem = "constant-verdict-double suppression must name what compensates for it: `gibsoncheck:allow constant-verdict-double covered by <TestName>` or `tracked: <repo>#<n>`"
			return d, true
		}
		if testName := m[1]; testName != "" {
			target := findTestFunc(pass, testName)
			if target == nil {
				d.problem = "constant-verdict-double suppression names a test that does not exist: " + testName
				return d, true
			}
			if !testAssertsDeny(target) {
				d.problem = "the compensating test you named (" + testName + ") does not assert the deny side, so it does not compensate for a permissive double"
				return d, true
			}
		}
		d.valid = true
		return d, true
	}
	return constantVerdictDir{}, false
}

// findTestFunc locates a Test* function declaration in the package
// under analysis.
func findTestFunc(pass *analysis.Pass, name string) *ast.FuncDecl {
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == name && fn.Body != nil {
				return fn
			}
		}
	}
	return nil
}

var denyAssertionRe = regexp.MustCompile(`PermissionDenied|Unauthenticated|Unavailable|NotFound|\.Error\(|\brequire\.Error\b|\bassert\.Error\b`)

// testAssertsDeny reports whether the named test contains a deny
// assertion — a gRPC deny code or an Error assertion.
func testAssertsDeny(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if denyAssertionRe.MatchString(v.Sel.Name) {
				found = true
				return false
			}
		case *ast.Ident:
			if denyAssertionRe.MatchString(v.Name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
