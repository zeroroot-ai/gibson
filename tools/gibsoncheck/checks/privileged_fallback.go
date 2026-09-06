// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// gibsoncheck analyzer: privilegedfallback.
//
// CLASS: privileged-fallback — silent substitution of a privileged
// default for an absent security-relevant value.
//
// The class is NOT detectable by inferring "privileged". It IS
// detectable once a human declares the privileged set once. So this
// analyzer pairs a committed sentinel declaration
// (privileged_sentinels.yaml) with a fixed, shape-based AST match:
//
//	G1  privileged sentinel produced on the FAILURE branch of a
//	    fallible security accessor.
//	G2  any function matching G1 is stamped with an analysis.Fact, so
//	    every CALLER of a tainted helper is reported too. A
//	    reintroduction under a new name is caught by shape, not name.
//	G3  the failure result of a fallible security accessor discarded
//	    into `_`.
//
// The FAIL-CLOSED EXEMPTION is what keeps the false-positive rate near
// zero: a failure branch whose terminal statement returns a non-nil
// error (or panics) is never reported, even when it MENTIONS a
// sentinel — for example in a status.Errorf message. Comparisons in
// the CONDITION are never matched; only value production in the branch
// BODY is.

package checks

import (
	_ "embed"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"gopkg.in/yaml.v3"
)

//go:embed privileged_sentinels.yaml
var privilegedSentinelsRaw []byte

const privilegedFallbackRule = "privileged-fallback"

// PrivilegedFallbackAnalyzer reports privileged-default substitution on
// the failure path of a security accessor.
var PrivilegedFallbackAnalyzer = &analysis.Analyzer{
	Name:      "privilegedfallback",
	Doc:       "flag privileged sentinels substituted for an absent tenant/identity on a failure branch",
	Run:       runPrivilegedFallback,
	FactTypes: []analysis.Fact{new(privilegedFallbackFact)},
}

// privilegedFallbackFact marks a *types.Func whose body matches G1.
// multichecker propagates facts across the package graph, which is what
// lets G2 report at CALL SITES in other packages.
type privilegedFallbackFact struct{}

func (*privilegedFallbackFact) AFact() {}

func (*privilegedFallbackFact) String() string { return "privilegedFallback" }

// ---------------------------------------------------------------------------
// declared sentinels
// ---------------------------------------------------------------------------

type sentinelDecl struct {
	Objects []struct {
		Symbol string `yaml:"symbol"`
		Reason string `yaml:"reason"`
	} `yaml:"objects"`
	Values []struct {
		Value  string `yaml:"value"`
		Reason string `yaml:"reason"`
	} `yaml:"values"`
}

var (
	sentinelObjects = map[string]string{} // "pkgpath.Name" -> reason
	sentinelValues  = map[string]string{} // folded constant  -> reason
)

func init() {
	var d sentinelDecl
	if err := yaml.Unmarshal(privilegedSentinelsRaw, &d); err != nil {
		panic(fmt.Sprintf("privilegedfallback: cannot parse privileged_sentinels.yaml: %v", err))
	}
	for _, o := range d.Objects {
		sentinelObjects[o.Symbol] = o.Reason
	}
	for _, v := range d.Values {
		sentinelValues[v.Value] = v.Reason
	}
}

// securityAccessorPkg is the package whose fallible accessors carry the
// tenant/identity that must never be defaulted away.
const securityAccessorPkg = "github.com/zeroroot-ai/sdk/auth"

// stringResultAccessors encode absence as "" rather than as a second
// result, so they need naming explicitly.
var stringResultAccessors = map[string]struct{}{
	"TenantStringFromContext": {},
}

// runPrivilegedFallback makes TWO passes over the package.
//
// The split is load-bearing for G2. Facts are exported by G1, and a
// caller can appear in a file that sorts BEFORE the file declaring the
// helper it calls. A single interleaved pass would therefore miss every
// same-package call site above the definition — the guard would look
// like it worked (it reports the definition) while silently failing to
// report most of its callers.
func runPrivilegedFallback(pass *analysis.Pass) (any, error) {
	type target struct {
		fn         *ast.FuncDecl
		suppressed bool
	}
	var targets []target

	// Pass 1 — validate suppressions, run G1, export facts.
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			dir, hasDir := parsePrivFallbackDirective(pass, fn)
			if hasDir && !dir.valid {
				pass.Reportf(fn.Pos(), "%s", dir.problem)
			}
			suppressed := hasDir && dir.valid

			if checkG1(pass, fn, suppressed) {
				if obj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok && obj != nil {
					pass.ExportObjectFact(obj, new(privilegedFallbackFact))
				}
			}
			targets = append(targets, target{fn: fn, suppressed: suppressed})
		}
	}

	// Pass 2 — call sites, now that every fact in this package is known.
	for _, t := range targets {
		checkG2(pass, t.fn, t.suppressed)
		checkG3(pass, t.fn, t.suppressed)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// G1 — privileged sentinel on the failure branch
// ---------------------------------------------------------------------------

// checkG1 walks every if-statement whose condition is a failure test on
// the result of a fallible security accessor and reports a declared
// sentinel produced in the failure branch. Returns true if the function
// is tainted (so G2 can stamp the fact).
func checkG1(pass *analysis.Pass, fn *ast.FuncDecl, suppressed bool) bool {
	tainted := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		branch := failureBranch(pass, fn, ifs)
		if branch == nil {
			return true
		}
		// FAIL-CLOSED EXEMPTION. A branch that terminates by returning
		// a non-nil error (or panicking) has already denied; a sentinel
		// mentioned inside it is diagnostic text, not a fallback.
		if branchIsFailClosed(pass, branch) {
			return true
		}
		pos, reason, ok := sentinelProducedIn(pass, branch)
		if !ok {
			return true
		}
		tainted = true
		if suppressed || baselined(privilegedFallbackRule, pass.Pkg.Path(), fn.Name.Name) {
			return true
		}
		pass.Reportf(pos,
			"privileged fallback [%s]: %s substitutes a declared privileged sentinel on the failure branch of a security accessor (%s). An absent tenant or identity must deny, not be replaced by a privileged default.",
			guardBaselineKey(privilegedFallbackRule, pass.Pkg.Path(), fn.Name.Name), fn.Name.Name, reason)
		return true
	})
	return tainted
}

// failureBranch returns the block that runs when the security accessor
// reports absence, for the four recognised shapes:
//
//	v, ok := f(...) ; if !ok { B }          -> B
//	v, ok := f(...) ; if ok { A } else { B } -> B
//	v, err := f(...); if err != nil { B }    -> B
//	s := TenantStringFromContext(ctx); if s == "" { B } -> B
func failureBranch(pass *analysis.Pass, fn *ast.FuncDecl, ifs *ast.IfStmt) *ast.BlockStmt {
	switch c := ifs.Cond.(type) {
	case *ast.UnaryExpr: // negated ok: failure is the then-branch
		if c.Op != token.NOT {
			return nil
		}
		if id, ok := c.X.(*ast.Ident); ok && boundByAccessor(pass, fn, id, accessorOKSlot) {
			return ifs.Body
		}
	case *ast.Ident: // bare `ok` with an else branch: failure is the else
		if ifs.Else == nil {
			return nil
		}
		if boundByAccessor(pass, fn, c, accessorOKSlot) {
			if b, ok := ifs.Else.(*ast.BlockStmt); ok {
				return b
			}
		}
	case *ast.BinaryExpr:
		// if err != nil
		if c.Op == token.NEQ && isNilIdent(c.Y) {
			if id, ok := c.X.(*ast.Ident); ok && boundByAccessor(pass, fn, id, accessorErrSlot) {
				return ifs.Body
			}
		}
		// if s == ""
		if c.Op == token.EQL && isEmptyStringLit(c.Y) {
			if id, ok := c.X.(*ast.Ident); ok && boundByAccessor(pass, fn, id, accessorValueSlot) {
				return ifs.Body
			}
		}
	}
	return nil
}

type accessorSlot int

const (
	accessorOKSlot accessorSlot = iota
	accessorErrSlot
	accessorValueSlot
)

// boundByAccessor reports whether ident was bound by an assignment
// whose RHS is a call to a fallible security accessor, in the given
// result slot.
func boundByAccessor(pass *analysis.Pass, fn *ast.FuncDecl, id *ast.Ident, slot accessorSlot) bool {
	target := pass.TypesInfo.Uses[id]
	if target == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		kind, ok := fallibleAccessorKind(pass, call)
		if !ok {
			return true
		}
		wantIdx := -1
		switch slot {
		case accessorValueSlot:
			if kind != accessorStringShaped {
				return true
			}
			wantIdx = 0
		case accessorOKSlot, accessorErrSlot:
			if kind == accessorStringShaped || len(assign.Lhs) < 2 {
				return true
			}
			wantIdx = 1
		}
		if wantIdx < 0 || wantIdx >= len(assign.Lhs) {
			return true
		}
		lhsID, ok := assign.Lhs[wantIdx].(*ast.Ident)
		if !ok {
			return true
		}
		if def := pass.TypesInfo.Defs[lhsID]; def != nil && def == target {
			found = true
			return false
		}
		return true
	})
	return found
}

type accessorKind int

const (
	accessorTwoResult accessorKind = iota
	accessorStringShaped
)

// fallibleAccessorKind reports whether the call resolves to an exported
// function in the security accessor package whose signature is (T,bool)
// or (T,error) — or to one of the string-shaped accessors that encode
// absence as "". Deriving the set from the SIGNATURE means new SDK
// accessors are covered automatically.
func fallibleAccessorKind(pass *analysis.Pass, call *ast.CallExpr) (accessorKind, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	obj, _ := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != securityAccessorPkg {
		return 0, false
	}
	if _, isStringShaped := stringResultAccessors[obj.Name()]; isStringShaped {
		return accessorStringShaped, true
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil || sig.Results().Len() != 2 {
		return 0, false
	}
	second := sig.Results().At(1).Type()
	if isBoolType(second) || isErrorType(second) {
		return accessorTwoResult, true
	}
	return 0, false
}

// branchIsFailClosed reports whether the branch terminates by denying —
// a return whose last result is a non-nil error value, or a
// panic/os.Exit. This is the exemption that keeps the ~15 correct
// `if tenant == "" || tenant == auth.SystemTenantString { return
// nil, status.Error(codes.Unauthenticated, ...) }` sites silent.
func branchIsFailClosed(pass *analysis.Pass, b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt:
		if len(last.Results) == 0 {
			return false
		}
		final := last.Results[len(last.Results)-1]
		if isNilIdent(final) {
			return false
		}
		if isDenyShapedExpr(final) {
			return true
		}
		tv, ok := pass.TypesInfo.Types[final]
		if !ok || tv.Type == nil {
			return false
		}
		return implementsError(tv.Type)
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			return f.Name == "panic"
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok {
				return x.Name == "os" && f.Sel.Name == "Exit"
			}
		}
	}
	return false
}

func implementsError(t types.Type) bool {
	if isErrorType(t) {
		return true
	}
	errIface, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return types.Implements(t, errIface)
}

// sentinelProducedIn reports a declared sentinel appearing in a
// value-producing position inside the branch: a return operand
// (directly or as a composite-literal element), an assignment RHS, or a
// call argument.
func sentinelProducedIn(pass *analysis.Pass, b *ast.BlockStmt) (token.Pos, string, bool) {
	var pos token.Pos
	var reason string
	found := false
	visit := func(e ast.Expr) {
		if found || e == nil {
			return
		}
		ast.Inspect(e, func(n ast.Node) bool {
			if found {
				return false
			}
			ex, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if r, ok := isDeclaredSentinel(pass, ex); ok {
				pos, reason, found = ex.Pos(), r, true
				return false
			}
			return true
		})
	}
	ast.Inspect(b, func(n ast.Node) bool {
		if found {
			return false
		}
		switch s := n.(type) {
		case *ast.ReturnStmt:
			for _, r := range s.Results {
				visit(r)
			}
		case *ast.AssignStmt:
			for _, r := range s.Rhs {
				visit(r)
			}
		case *ast.CallExpr:
			// A sentinel handed to a callee is still a fallback. Deny
			// constructors are already excluded by branchIsFailClosed.
			for _, a := range s.Args {
				visit(a)
			}
		}
		return true
	})
	return pos, reason, found
}

// isDeclaredSentinel matches an expression against the declared set,
// first by TYPE-OBJECT IDENTITY, then by FOLDED CONSTANT VALUE.
func isDeclaredSentinel(pass *analysis.Pass, e ast.Expr) (string, bool) {
	// Object identity — never a name substring.
	if id := identOf(e); id != nil {
		if obj := pass.TypesInfo.Uses[id]; obj != nil && obj.Pkg() != nil {
			key := obj.Pkg().Path() + "." + obj.Name()
			if reason, ok := sentinelObjects[key]; ok {
				return reason, true
			}
		}
	}
	// Folded constant value — closes the literal-evasion hole.
	if tv, ok := pass.TypesInfo.Types[e]; ok && tv.Value != nil {
		if s, err := strconv.Unquote(tv.Value.String()); err == nil {
			if reason, ok := sentinelValues[s]; ok {
				return reason, true
			}
		}
	}
	return "", false
}

// identOf returns the identifier a selector or bare ident refers to.
func identOf(e ast.Expr) *ast.Ident {
	switch v := e.(type) {
	case *ast.Ident:
		return v
	case *ast.SelectorExpr:
		return v.Sel
	}
	return nil
}

func isEmptyStringLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}

// ---------------------------------------------------------------------------
// G2 — the tainted-helper deny-list
// ---------------------------------------------------------------------------

// checkG2 reports every call to a function carrying the
// privilegedFallbackFact. This is what makes the guard bite on the
// CLASS rather than on one function: a reintroduction under any new
// name is caught by shape at its definition and then at every caller.
func checkG2(pass *analysis.Pass, fn *ast.FuncDecl, suppressed bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id := identOf(call.Fun)
		if id == nil {
			return true
		}
		callee, _ := pass.TypesInfo.Uses[id].(*types.Func)
		if callee == nil {
			return true
		}
		var fact privilegedFallbackFact
		if !pass.ImportObjectFact(callee, &fact) {
			return true
		}
		if suppressed || baselined(privilegedFallbackRule, pass.Pkg.Path(), fn.Name.Name+"->"+callee.Name()) {
			return true
		}
		pass.Reportf(call.Pos(),
			"privileged fallback [%s]: %s calls %s, which substitutes a privileged sentinel when the caller has no tenant. Use a fail-closed accessor that returns an error instead.",
			guardBaselineKey(privilegedFallbackRule, pass.Pkg.Path(), fn.Name.Name+"->"+callee.Name()),
			fn.Name.Name, callee.Name())
		return true
	})
}

// ---------------------------------------------------------------------------
// G3 — discarded failure result
// ---------------------------------------------------------------------------

// checkG3 reports `_` in the ok/error position of a fallible security
// accessor. Cheap, and the partial guard for the runtime-sourced
// defaults G1 cannot see.
func checkG3(pass *analysis.Pass, fn *ast.FuncDecl, suppressed bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		kind, ok := fallibleAccessorKind(pass, call)
		if !ok || kind == accessorStringShaped {
			return true
		}
		blank, isIdent := assign.Lhs[1].(*ast.Ident)
		if !isIdent || blank.Name != "_" {
			return true
		}
		sym := fn.Name.Name + "@" + accessorName(call)
		if suppressed || baselined(privilegedFallbackRule, pass.Pkg.Path(), sym) {
			return true
		}
		pass.Reportf(assign.Pos(),
			"privileged fallback [%s]: %s discards the failure result of %s. Absence is then indistinguishable from success, and the zero value flows on as if it were a real tenant or identity.",
			guardBaselineKey(privilegedFallbackRule, pass.Pkg.Path(), sym), fn.Name.Name, accessorName(call))
		return true
	})
}

func accessorName(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return "the security accessor"
}

// ---------------------------------------------------------------------------
// Suppression — parsed and VALIDATED, never bare
// ---------------------------------------------------------------------------

const privFallbackDirective = "gibsoncheck:allow privileged-fallback"

var privFallbackGrammar = regexp.MustCompile(
	`gibsoncheck:allow privileged-fallback\s+(?:guard:([A-Za-z_][A-Za-z0-9_.]*)|issue:(gibson|deploy|sdk)#(\d+))\s+--\s+(\S.{9,})`)

type privFallbackDir struct {
	pos     token.Pos
	valid   bool
	problem string
}

// parsePrivFallbackDirective validates the suppression grammar and, for
// the guard: form, RESOLVES the named symbol. A misspelled or deleted
// guard reds the build — which is the difference between naming a guard
// and typing words in a comment.
func parsePrivFallbackDirective(pass *analysis.Pass, fn *ast.FuncDecl) (privFallbackDir, bool) {
	for _, c := range commentsFor(pass, fn) {
		if !strings.Contains(c.Text, privFallbackDirective) {
			continue
		}
		d := privFallbackDir{pos: c.Pos()}
		m := privFallbackGrammar.FindStringSubmatch(c.Text)
		if m == nil {
			d.problem = "privileged-fallback suppression must name a compensating guard or a tracking issue: `gibsoncheck:allow privileged-fallback (guard:<Symbol>|issue:<repo>#<n>) -- <rationale of at least 10 characters>`"
			return d, true
		}
		if sym := m[1]; sym != "" {
			bare := sym
			if i := strings.LastIndex(bare, "."); i >= 0 {
				bare = bare[i+1:]
			}
			if !symbolResolves(pass, bare) {
				d.problem = fmt.Sprintf("privileged-fallback suppression names guard symbol %s, which does not resolve to a function or method in scope", sym)
				return d, true
			}
		}
		d.valid = true
		return d, true
	}
	return privFallbackDir{}, false
}

// commentsFor returns the doc comment plus any comment on the same
// lines as fn's body. Call-line placement matters: one function can
// hold several accessor reads and a function-level directive would
// blanket-exempt siblings the author never considered.
func commentsFor(pass *analysis.Pass, fn *ast.FuncDecl) []*ast.Comment {
	var out []*ast.Comment
	if fn.Doc != nil {
		out = append(out, fn.Doc.List...)
	}
	for _, f := range pass.Files {
		if f.Pos() > fn.Pos() || f.End() < fn.End() {
			continue
		}
		for _, cg := range f.Comments {
			if cg.Pos() >= fn.Pos() && cg.End() <= fn.End() {
				out = append(out, cg.List...)
			}
		}
	}
	return out
}
