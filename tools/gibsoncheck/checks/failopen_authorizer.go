// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// gibsoncheck analyzer: failopenauthorizer.
//
// INVARIANT: a function whose job is to make an authorization decision
// must not treat an absent authorization dependency as "permission
// granted". When the dependency is missing the function must deny
// (return a gRPC status error, return false, or return a response that
// asserts no authority) — never fall through to the allow path.
//
// The analyzer matches two AST shapes, both gated on the TYPE of the
// dependency (not on its identifier name) and on the RETURN POLARITY of
// the guard branch. Those two gates are what keep the check shippable:
// a name-only or body-only version of the same idea reports fail-CLOSED
// helpers (`return false, nil` predicates), readiness probes, and plain
// value nil-guards as defects.
//
//	FO-1 nil-degradation
//	    if <recv>.<field> == nil { ...; return <permissive> }
//	FO-2 check-under-conditional
//	    if <recv>.<field> != nil { ...decision call...; ...deny return... }
//	    with no else, and with control reaching a non-deny terminal when
//	    the field is nil.
//
// Gate 0 (both shapes): the condition operand must be `<recv>.<field>`
// where <recv> is a single identifier, and <field>'s declared type must
// implement one of securityDecisionIfaces.
//
// Gate 1 (both shapes): the enclosing function must actually decide —
// its body must contain a call to a decision method on that same field.
//
// Suppression: see parseFailOpenDirective. There is no bare opt-out;
// a malformed directive is itself a diagnostic.

package checks

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"
	"time"

	"golang.org/x/tools/go/analysis"
)

// FailOpenAuthorizerAnalyzer reports security-decision functions that
// treat an absent authorization dependency as an allow.
var FailOpenAuthorizerAnalyzer = &analysis.Analyzer{
	Name: "failopenauthorizer",
	Doc:  "flag security-decision helpers that allow through when their authorization dependency is nil",
	Run:  runFailOpenAuthorizer,
}

// securityDecisionIfaces is the committed set of interfaces whose
// absence must never be read as permission granted. Adding a new
// authorizer interface is a deliberate, reviewed one-line change.
//
// Entries are matched as "<package path>.<type name>" against the
// declared type of the guarded struct field, structurally and in BOTH
// directions:
//
//   - the field's type IS, or implements, a listed type — a concrete
//     authorizer, or a wider interface built on top of one;
//   - a listed type implements the field's type — the common shape in
//     this tree, where a package declares a NARROWED local view of the
//     authorizer contract (for example the `authzIface` subset in
//     internal/server/daemon/api) and stores that instead.
//
// The second direction is only accepted when the field's own method set
// contains at least one decisionMethod, so `any` and marker interfaces
// (which every authorizer trivially implements) do not qualify.
var securityDecisionIfaces = []string{
	"github.com/zeroroot-ai/gibson/internal/platform/authz.Authorizer",
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga.Checker",
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant.JWTVerifier",
}

// decisionMethods anchors "this function's job is authorization".
// Gate 1 requires a call to one of these on the guarded field.
var decisionMethods = map[string]struct{}{
	"Check":           {},
	"BatchCheck":      {},
	"Authorize":       {},
	"ListObjects":     {},
	"ListUsers":       {},
	"ListUsersOfType": {},
	"Verify":          {},
	"CanInvokeTool":   {},
	"CanExecute":      {},
}

// authorityFieldRe matches response fields that assert authority. A
// composite-literal return that sets one of these to a non-zero value
// is fabricating a membership/permission claim for an unchecked caller.
var authorityFieldRe = regexp.MustCompile(`(?i)(role|is_?admin|is_?owner|permission|relation|allowed|can_[a-z]+|scopes|grants|entitle)`)

// denyCallRe matches the deny-shaped constructors used across the
// daemon. FO-2 requires one of these inside the guarded block.
var denyCallRe = regexp.MustCompile(`^(status(_grpc)?\.Error(f)?|errors\.New|fmt\.Errorf)$`)

const failOpenDirective = "gibsoncheck:allow fail-open-authorizer"

// failOpenRule is this guard's key prefix in guard_baseline.txt.
const failOpenRule = "fail-open-authorizer"

// failOpenDirectiveRe parses the mandatory qualifier. Exactly one of
// compensating= or issue= must be present; issue= additionally requires
// a well-formed expires= date.
var (
	failOpenCompensatingRe = regexp.MustCompile(`compensating=([A-Za-z_][A-Za-z0-9_.]*)`)
	failOpenIssueRe        = regexp.MustCompile(`issue=([A-Za-z][A-Za-z0-9_-]*)#(\d+)`)
	failOpenExpiresRe      = regexp.MustCompile(`expires=(\d{4}-\d{2}-\d{2})`)
)

// maxSuppressionDays caps how far ahead an issue= suppression may
// expire. Renewing is then a visible, dated, reviewed commit.
const maxSuppressionDays = 90

func runFailOpenAuthorizer(pass *analysis.Pass) (any, error) {
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
			checkFailOpenFunc(pass, fn)
		}
	}
	return nil, nil
}

// checkFailOpenFunc applies both shapes to one function declaration.
func checkFailOpenFunc(pass *analysis.Pass, fn *ast.FuncDecl) {
	// Parse the suppression directive first. A malformed directive is
	// reported regardless of whether the body has a finding — a bare
	// opt-out must never be cheaper than fixing the code.
	dir, hasDir := parseFailOpenDirective(fn)
	if hasDir && !dir.valid {
		pass.Reportf(fn.Pos(), "%s", dir.problem)
		return
	}

	recv := receiverIdent(fn)
	if recv == "" {
		return
	}

	// Gate 0 + Gate 1 are evaluated per candidate field, since a
	// function may guard more than one dependency.
	for _, ifs := range collectIfStmts(fn.Body) {
		field, isNilCmp, ok := securityFieldNilCompare(pass, ifs.Cond, recv)
		if !ok {
			continue
		}
		if !funcDecidesOn(fn, field) {
			continue // Gate 1: holds a reference but does not decide.
		}
		if isNilCmp {
			reportIfPermissiveNilBranch(pass, fn, ifs, field, dir, hasDir)
		} else {
			reportIfCheckUnderConditional(pass, fn, ifs, field, dir, hasDir)
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 0 — the subject must be a security-decision dependency BY TYPE
// ---------------------------------------------------------------------------

// securityFieldNilCompare reports whether cond compares `<recv>.<field>`
// against nil, where <field>'s type implements a securityDecisionIface.
// isNil is true for `== nil`, false for `!= nil`. Conditions joined by
// || or && are searched recursively, matching the nil-guard convention
// used elsewhere in the tree.
func securityFieldNilCompare(pass *analysis.Pass, cond ast.Expr, recv string) (field string, isNil, ok bool) {
	switch c := cond.(type) {
	case *ast.ParenExpr:
		return securityFieldNilCompare(pass, c.X, recv)
	case *ast.BinaryExpr:
		if c.Op == token.LAND || c.Op == token.LOR {
			if f, n, o := securityFieldNilCompare(pass, c.X, recv); o {
				return f, n, true
			}
			return securityFieldNilCompare(pass, c.Y, recv)
		}
		if c.Op != token.EQL && c.Op != token.NEQ {
			return "", false, false
		}
		sel, nilSide := nilComparisonOperands(c)
		if sel == nil || !nilSide {
			return "", false, false
		}
		// ReceiverFieldOnly: X must be the bare receiver identifier.
		x, isIdent := sel.X.(*ast.Ident)
		if !isIdent || x.Name != recv {
			return "", false, false
		}
		if !isSecurityDecisionField(pass, sel) {
			return "", false, false
		}
		return sel.Sel.Name, c.Op == token.EQL, true
	}
	return "", false, false
}

// nilComparisonOperands splits a binary comparison into its selector
// side and reports whether the other side is the nil identifier.
func nilComparisonOperands(c *ast.BinaryExpr) (*ast.SelectorExpr, bool) {
	if isNilIdent(c.Y) {
		if sel, ok := c.X.(*ast.SelectorExpr); ok {
			return sel, true
		}
	}
	if isNilIdent(c.X) {
		if sel, ok := c.Y.(*ast.SelectorExpr); ok {
			return sel, true
		}
	}
	return nil, false
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// isSecurityDecisionField resolves the selector through TypesInfo and
// reports whether the field's declared type satisfies one of the
// committed security-decision interfaces. This is the gate that keeps
// keyword false positives (`if n.RetryPolicy != nil`) out.
func isSecurityDecisionField(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	selection, ok := pass.TypesInfo.Selections[sel]
	if !ok {
		return false
	}
	ft := selection.Type()
	if ft == nil {
		return false
	}
	for _, want := range securityDecisionIfaces {
		if typeSatisfiesNamed(pass, ft, want) {
			return true
		}
	}
	return false
}

// typeSatisfiesNamed reports whether t is a security-decision
// dependency with respect to the named type "<pkgpath>.<Name>", in
// either direction (see securityDecisionIfaces).
func typeSatisfiesNamed(pass *analysis.Pass, t types.Type, qualified string) bool {
	idx := strings.LastIndex(qualified, ".")
	if idx < 0 {
		return false
	}
	pkgPath, name := qualified[:idx], qualified[idx+1:]

	// Exact identity: the field is declared as the listed type.
	if named, ok := deref(t).(*types.Named); ok {
		obj := named.Obj()
		if obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath {
			return true
		}
	}

	target := lookupNamedType(pass, pkgPath, name)
	if target == nil {
		return false
	}

	// Direction 1: the field's type implements the listed interface.
	if iface, ok := target.Underlying().(*types.Interface); ok {
		if types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface) {
			return true
		}
	}

	// Direction 2: the listed type implements the field's type — a
	// narrowed local view of the same contract. Guarded by requiring
	// the field's own method set to carry a decision method, so `any`
	// and marker interfaces do not qualify.
	if fieldIface, ok := t.Underlying().(*types.Interface); ok && ifaceHasDecisionMethod(fieldIface) {
		if types.Implements(target, fieldIface) || types.Implements(types.NewPointer(target), fieldIface) {
			return true
		}
	}
	return false
}

// ifaceHasDecisionMethod reports whether the interface declares at
// least one authorization decision method.
func ifaceHasDecisionMethod(iface *types.Interface) bool {
	for i := range iface.NumMethods() {
		if _, ok := decisionMethods[iface.Method(i).Name()]; ok {
			return true
		}
	}
	return false
}

func deref(t types.Type) types.Type {
	if p, ok := t.(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}

// lookupNamedType finds a named type in the analysed package or any of
// its imports, direct or transitive.
func lookupNamedType(pass *analysis.Pass, pkgPath, name string) types.Type {
	var target *types.Package
	if pass.Pkg.Path() == pkgPath {
		target = pass.Pkg
	} else {
		seen := map[string]bool{}
		var find func(p *types.Package)
		find = func(p *types.Package) {
			if target != nil || p == nil || seen[p.Path()] {
				return
			}
			seen[p.Path()] = true
			if p.Path() == pkgPath {
				target = p
				return
			}
			for _, imp := range p.Imports() {
				find(imp)
			}
		}
		for _, imp := range pass.Pkg.Imports() {
			find(imp)
		}
	}
	if target == nil {
		return nil
	}
	obj := target.Scope().Lookup(name)
	if obj == nil {
		return nil
	}
	return obj.Type()
}

// ---------------------------------------------------------------------------
// Gate 1 — the enclosing function must actually decide
// ---------------------------------------------------------------------------

// funcDecidesOn reports whether fn's body calls a decision method on
// the named field. This excludes readiness probes and wiring code that
// merely holds a reference to an authorizer.
func funcDecidesOn(fn *ast.FuncDecl, field string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, isDecision := decisionMethods[sel.Sel.Name]; !isDecision {
			return true
		}
		// Receiver of the decision call must be the guarded field, or
		// a local alias of it.
		inner, ok := sel.X.(*ast.SelectorExpr)
		if ok && inner.Sel.Name == field {
			found = true
			return false
		}
		if id, ok := sel.X.(*ast.Ident); ok && aliasesField(fn, id.Name, field) {
			found = true
			return false
		}
		return true
	})
	return found
}

// aliasesField reports whether local variable name was assigned from
// `<something>.<field>` inside fn.
func aliasesField(fn *ast.FuncDecl, name, field string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != name || i >= len(assign.Rhs) {
				continue
			}
			if sel, ok := assign.Rhs[i].(*ast.SelectorExpr); ok && sel.Sel.Name == field {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// FO-1 — nil-degradation
// ---------------------------------------------------------------------------

func reportIfPermissiveNilBranch(pass *analysis.Pass, fn *ast.FuncDecl, ifs *ast.IfStmt, field string, dir failOpenDirective2, hasDir bool) {
	ret := terminalReturn(ifs.Body)
	if ret == nil {
		return
	}
	why, permissive := returnIsPermissive(pass, fn, ret)
	if !permissive {
		return
	}
	if hasDir && dir.valid {
		if problem := verifyCompensating(pass, fn, dir, ret.Pos()); problem != "" {
			pass.Reportf(fn.Pos(), "%s", problem)
		}
		return
	}
	if baselined(failOpenRule, pass.Pkg.Path(), fn.Name.Name) {
		return
	}
	pass.Reportf(ifs.Pos(),
		"fail-open authorization [%s]: %s guards the security-decision dependency %s.%s and the guarded branch %s. An absent authorization dependency must deny (return a Unavailable/PermissionDenied status), never allow through.",
		guardBaselineKey(failOpenRule, pass.Pkg.Path(), fn.Name.Name), funcLabel(fn), receiverIdent(fn), field, why)
}

// terminalReturn returns the last statement of a block when it is a
// return statement.
func terminalReturn(b *ast.BlockStmt) *ast.ReturnStmt {
	if b == nil || len(b.List) == 0 {
		return nil
	}
	ret, _ := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ret
}

// returnIsPermissive models the return polarity for the function's own
// result signature. This is the gate that exonerates fail-closed
// predicates (`return false, nil`) and empty responses.
func returnIsPermissive(pass *analysis.Pass, fn *ast.FuncDecl, ret *ast.ReturnStmt) (string, bool) {
	results := resultTypes(pass, fn)
	switch {
	// (error) -> `return nil` is permissive.
	case len(results) == 1 && isErrorType(results[0]):
		if len(ret.Results) == 1 && isNilIdent(ret.Results[0]) {
			return "returns a nil error, which its callers read as \"allowed\"", true
		}
	// (bool) or (bool, error) -> `return true, ...` is permissive.
	case len(results) >= 1 && isBoolType(results[0]):
		if len(ret.Results) >= 1 && isTrueIdent(ret.Results[0]) {
			return "returns true, granting the permission it was asked to verify", true
		}
	// (*pbT, error) -> permissive iff the literal asserts authority.
	case len(results) == 2 && isErrorType(results[1]):
		if len(ret.Results) == 2 && isNilIdent(ret.Results[1]) {
			if f, ok := compositeAssertsAuthority(pass, ret.Results[0]); ok {
				return fmt.Sprintf("returns a synthesised response asserting authority (%s) for a caller whose permissions were never checked", f), true
			}
		}
	}
	return "", false
}

// resultTypes resolves the function's declared result types through
// TypesInfo. The return-polarity model is keyed on these, not on the
// syntax of the return statement.
func resultTypes(pass *analysis.Pass, fn *ast.FuncDecl) []types.Type {
	obj, ok := pass.TypesInfo.Defs[fn.Name]
	if !ok || obj == nil {
		return nil
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil {
		return nil
	}
	out := make([]types.Type, 0, sig.Results().Len())
	for i := range sig.Results().Len() {
		out = append(out, sig.Results().At(i).Type())
	}
	return out
}

// isErrorType reports whether t is the builtin error interface.
func isErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() == nil && obj.Name() == "error"
}

// isBoolType reports whether t is the builtin bool.
func isBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

func isTrueIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}

// compositeAssertsAuthority reports whether a returned composite
// literal sets an authority-bearing field to a non-zero literal.
// `&GetMyPermissionsResponse{Role: "member"}` trips it;
// `&ListMembersResponse{}` does not — an empty response leaks nothing.
func compositeAssertsAuthority(pass *analysis.Pass, e ast.Expr) (string, bool) {
	lit := compositeLitOf(e)
	if lit == nil {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || !authorityFieldRe.MatchString(key.Name) {
			continue
		}
		if isZeroValueExpr(pass, kv.Value) {
			continue
		}
		return key.Name, true
	}
	return "", false
}

func compositeLitOf(e ast.Expr) *ast.CompositeLit {
	switch v := e.(type) {
	case *ast.CompositeLit:
		return v
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			return compositeLitOf(v.X)
		}
	}
	return nil
}

// isZeroValueExpr reports whether the expression is a constant zero
// value — false, 0, "", or nil.
func isZeroValueExpr(pass *analysis.Pass, e ast.Expr) bool {
	if isNilIdent(e) {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && id.Name == "false" {
		return true
	}
	tv, ok := pass.TypesInfo.Types[e]
	if !ok || tv.Value == nil {
		return false
	}
	return tv.Value.String() == `""` || tv.Value.String() == "0"
}

// ---------------------------------------------------------------------------
// FO-2 — check-under-conditional (the omission form)
// ---------------------------------------------------------------------------

func reportIfCheckUnderConditional(pass *analysis.Pass, fn *ast.FuncDecl, ifs *ast.IfStmt, field string, dir failOpenDirective2, hasDir bool) {
	if ifs.Else != nil {
		return // (a) an else branch means nil is handled explicitly.
	}
	if !blockCallsDecisionOn(ifs.Body, field) {
		return // (b) the guarded block must contain the decision call.
	}
	if !blockHasDenyReturn(ifs.Body) {
		return // (c) the guarded block must be able to deny.
	}
	if isLastStmt(fn.Body, ifs) {
		return // (d) control must reach a non-deny terminal when nil.
	}
	if hasDir && dir.valid {
		if problem := verifyCompensating(pass, fn, dir, ifs.Pos()); problem != "" {
			pass.Reportf(fn.Pos(), "%s", problem)
		}
		return
	}
	if baselined(failOpenRule, pass.Pkg.Path(), fn.Name.Name) {
		return
	}
	pass.Reportf(ifs.Pos(),
		"fail-open authorization [%s]: %s performs its only authorization check inside `if %s.%s != nil`, so the check is skipped entirely when the dependency is absent and control falls through to the allow path. Invert the guard: deny up front when %s.%s is nil.",
		guardBaselineKey(failOpenRule, pass.Pkg.Path(), fn.Name.Name), funcLabel(fn), receiverIdent(fn), field, receiverIdent(fn), field)
}

// blockCallsDecisionOn reports whether the block calls a decision
// method on the named field.
func blockCallsDecisionOn(b *ast.BlockStmt, field string) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, isDecision := decisionMethods[sel.Sel.Name]; !isDecision {
			return true
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == field {
			found = true
			return false
		}
		return true
	})
	return found
}

// blockHasDenyReturn reports whether the block returns a deny-shaped
// error that is NOT nested inside a function literal. The FuncLit
// exclusion is load-bearing: it is what separates a guarded control
// flow from wiring that appends closures returning errors.
func blockHasDenyReturn(b *ast.BlockStmt) bool {
	found := false
	walk := func(n ast.Node) {
		ast.Inspect(n, func(c ast.Node) bool {
			if found {
				return false
			}
			if _, isLit := c.(*ast.FuncLit); isLit {
				return false // do not descend into closures
			}
			ret, ok := c.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, r := range ret.Results {
				if isDenyShapedExpr(r) {
					found = true
					return false
				}
			}
			return true
		})
	}
	walk(b)
	return found
}

// isDenyShapedExpr matches status.Error*/errors.New/fmt.Errorf calls
// and a bare `err` identifier.
func isDenyShapedExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "err"
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		return denyCallRe.MatchString(x.Name + "." + sel.Sel.Name)
	}
	return false
}

func isLastStmt(b *ast.BlockStmt, target ast.Stmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	return b.List[len(b.List)-1] == target
}

// ---------------------------------------------------------------------------
// Suppression — validated, never bare
// ---------------------------------------------------------------------------

// failOpenDirective2 is a parsed suppression directive.
type failOpenDirective2 struct {
	pos          token.Pos
	valid        bool
	problem      string
	compensating string // package-qualified or bare symbol name
}

// parseFailOpenDirective reads the function's doc comment for the
// fail-open suppression and validates its qualifier. Exactly one of
// compensating= or issue= is required; issue= additionally requires a
// well-formed, unexpired, in-horizon expires= date.
func parseFailOpenDirective(fn *ast.FuncDecl) (failOpenDirective2, bool) {
	if fn.Doc == nil {
		return failOpenDirective2{}, false
	}
	for _, c := range fn.Doc.List {
		if !strings.Contains(c.Text, failOpenDirective) {
			continue
		}
		d := failOpenDirective2{pos: c.Pos()}
		comp := failOpenCompensatingRe.FindStringSubmatch(c.Text)
		issue := failOpenIssueRe.FindStringSubmatch(c.Text)
		switch {
		case comp == nil && issue == nil:
			d.problem = "bare fail-open-authorizer suppression is not permitted: name a compensating guard (compensating=<pkg>.<Sym>) or an open tracking issue (issue=<repo>#<N> with expires=<YYYY-MM-DD>)"
			return d, true
		case comp != nil && issue != nil:
			d.problem = "fail-open-authorizer suppression must name exactly one of compensating= or issue=, not both"
			return d, true
		case comp != nil:
			d.compensating = comp[1]
			d.valid = true
			return d, true
		default:
			exp := failOpenExpiresRe.FindStringSubmatch(c.Text)
			if exp == nil {
				d.problem = "fail-open-authorizer suppression with issue= must also carry expires=<YYYY-MM-DD>"
				return d, true
			}
			when, err := time.Parse("2006-01-02", exp[1])
			if err != nil {
				d.problem = fmt.Sprintf("fail-open-authorizer suppression has a malformed expires= date %q; use YYYY-MM-DD", exp[1])
				return d, true
			}
			now := time.Now().UTC()
			if when.Before(now) {
				d.problem = fmt.Sprintf("fail-open-authorizer suppression expired on %s; fix the handler or renew the suppression with a fresh, reviewed date", exp[1])
				return d, true
			}
			if when.After(now.AddDate(0, 0, maxSuppressionDays)) {
				d.problem = fmt.Sprintf("fail-open-authorizer suppression expires= %s is more than %d days out; suppressions are capped so renewal stays a visible, reviewed commit", exp[1], maxSuppressionDays)
				return d, true
			}
			d.valid = true
			return d, true
		}
	}
	return failOpenDirective2{}, false
}

// verifyCompensating checks that a compensating= suppression names a
// real symbol AND that the symbol is actually called before the
// permissive return. A guard that is named but not on the permissive
// path is reported. Returns "" when the claim holds.
func verifyCompensating(pass *analysis.Pass, fn *ast.FuncDecl, dir failOpenDirective2, permissivePos token.Pos) string {
	if dir.compensating == "" {
		return ""
	}
	sym := dir.compensating
	if i := strings.LastIndex(sym, "."); i >= 0 {
		sym = sym[i+1:]
	}
	if !symbolResolves(pass, sym) {
		return fmt.Sprintf("compensating guard %s named in the fail-open-authorizer suppression does not resolve to a function or method in scope", dir.compensating)
	}
	if !calledBefore(fn, sym, permissivePos) {
		return fmt.Sprintf("compensating guard %s is named but not on the permissive path: it is never called before the branch this suppression excuses", dir.compensating)
	}
	return ""
}

// symbolResolves reports whether sym names a func or method reachable
// from the analysed package — package scope, an imported package, or a
// method on any named type in scope.
func symbolResolves(pass *analysis.Pass, sym string) bool {
	if obj := pass.Pkg.Scope().Lookup(sym); obj != nil {
		if _, ok := obj.(*types.Func); ok {
			return true
		}
	}
	for _, imp := range pass.Pkg.Imports() {
		if obj := imp.Scope().Lookup(sym); obj != nil {
			if _, ok := obj.(*types.Func); ok {
				return true
			}
		}
	}
	// Methods: scan named types declared in this package.
	scope := pass.Pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		for i := range named.NumMethods() {
			if named.Method(i).Name() == sym {
				return true
			}
		}
	}
	return false
}

// calledBefore reports whether sym is called anywhere in fn strictly
// before pos. This is the intraprocedural reachability claim the
// compensating= form is allowed to make, and it is checked.
func calledBefore(fn *ast.FuncDecl, sym string, pos token.Pos) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() >= pos {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == sym {
				found = true
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == sym {
				found = true
			}
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// receiverIdent returns the method receiver's identifier name, or ""
// for a plain function. Gate 0's ReceiverFieldOnly narrowing depends on
// this: it is what kills selector-chain and parameter-shape noise.
func receiverIdent(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	names := fn.Recv.List[0].Names
	if len(names) == 0 {
		return ""
	}
	return names[0].Name
}

func funcLabel(fn *ast.FuncDecl) string {
	return fn.Name.Name
}

// collectIfStmts returns every if-statement in the block, including
// nested ones.
func collectIfStmts(b *ast.BlockStmt) []*ast.IfStmt {
	var out []*ast.IfStmt
	ast.Inspect(b, func(n ast.Node) bool {
		if ifs, ok := n.(*ast.IfStmt); ok {
			out = append(out, ifs)
		}
		return true
	})
	return out
}
