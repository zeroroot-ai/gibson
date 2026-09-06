// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// gibsoncheck analyzer: fgalistusers.
//
// INVARIANT: Authorizer.ListUsers hardcodes an OpenFGA
// UserTypeFilter{Type:"user"}. Calling it for a relation that cannot
// yield a `user`-typed subject is not an error at runtime — OpenFGA
// answers with a SUCCESSFUL EMPTY RESULT. The caller therefore reads
// "nobody holds this relation" and proceeds, silently. That is the
// defect class: an authorization query that is structurally incapable
// of returning an answer, failing open and quietly.
//
// Ground truth is internal/platform/authz/model.fga, parsed at analysis
// time with the official OpenFGA transformer — no hand-rolled DSL
// parsing, and the guard re-derives from the model on every run rather
// than encoding a snapshot. A future model narrowing that invalidates a
// previously-correct call is therefore caught.
//
//	R1  static mismatch — objectType and relation both constant-foldable
//	    and admitsUser(objectType, relation) is false. Decidable, exact.
//	R2  result-shape contradiction — the results are filtered on an FGA
//	    type prefix other than "user:", so the branch is provably dead.
//	    Needs no argument resolution, which is why it bites on the
//	    request-driven dynamic case R1 cannot see.
//	R3  unresolved arguments — reported so the author hoists a constant
//	    or switches to ListUsersOfType, rather than the guard guessing.
//
// FAIL-CLOSED ON MODEL LOAD: if the model is missing, unreadable, or
// fails to transform, the analyzer returns an ERROR. A guard that
// silently no-ops when it cannot find its model reproduces the exact
// failure mode it exists to catch.

package checks

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"golang.org/x/tools/go/analysis"
)

const fgaListUsersRule = "fga-list-users"

// FGAListUsersAnalyzer reports ListUsers calls whose relation cannot
// admit a user-typed subject.
var FGAListUsersAnalyzer = &analysis.Analyzer{
	Name: "fgalistusers",
	Doc:  "flag Authorizer.ListUsers calls against relations that cannot yield a user-typed subject",
	Run:  runFGAListUsers,
}

// modelPathFlag lets CI point at the model explicitly; by default the
// analyzer walks up from the package's own files to the module root.
var modelPathFlag string

func init() {
	FGAListUsersAnalyzer.Flags.StringVar(&modelPathFlag, "model", "",
		"path to model.fga (default: <module root>/internal/platform/authz/model.fga)")
}

// ---------------------------------------------------------------------------
// model loading + the admitsUser fixpoint
// ---------------------------------------------------------------------------

type fgaModel struct {
	types map[string]*openfgav1.TypeDefinition

	// memo caches admitsUser results. The model is parsed once and
	// shared by every analyzer pass, and multichecker runs passes
	// concurrently, so the cache needs its own lock — `types` is
	// read-only after construction and does not.
	memoMu sync.Mutex
	memo   map[string]bool
}

var (
	modelMu  sync.Mutex
	modelVal *fgaModel
)

// loadModel resolves and parses model.fga once per process. Only
// SUCCESS is memoized: the model path is module-global, but an
// individual pass may see files that do not sit under the module root
// (generated or cached sources), so a failure for one package must not
// poison every later package. A pass that genuinely cannot reach the
// model errors — never silently skips.
func loadModel(pass *analysis.Pass) (*fgaModel, error) {
	modelMu.Lock()
	defer modelMu.Unlock()
	if modelVal != nil {
		return modelVal, nil
	}

	path := modelPathFlag
	if path == "" {
		path = findModelPath(pass)
	}
	if path == "" {
		return nil, errors.New("fgalistusers: cannot locate internal/platform/authz/model.fga; pass -fgalistusers.model=<path>. Refusing to run: a guard that silently finds nothing when it cannot load its model reproduces the defect it exists to catch")
	}
	// #nosec G304 -- path is the analyzer's own -model flag or a path
	// derived from the module root; this is a build-time linter reading a
	// committed model file, with no untrusted input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fgalistusers: cannot read %s: %w", path, err)
	}
	am, err := transformer.TransformDSLToProto(string(data))
	if err != nil {
		return nil, fmt.Errorf("fgalistusers: cannot parse %s: %w", path, err)
	}
	m := &fgaModel{types: map[string]*openfgav1.TypeDefinition{}, memo: map[string]bool{}}
	for _, td := range am.GetTypeDefinitions() {
		m.types[td.GetType()] = td
	}
	modelVal = m
	return modelVal, nil
}

// findModelPath looks for the model relative to the module root,
// starting from the package's own files and falling back to the
// working directory (which is the module root under `go build`-driven
// CI invocations).
func findModelPath(pass *analysis.Pass) string {
	var starts []string
	if len(pass.Files) > 0 {
		starts = append(starts, filepath.Dir(pass.Fset.Position(pass.Files[0].Pos()).Filename))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, dir := range starts {
		if p := ascendToModel(dir); p != "" {
			return p
		}
	}
	return ""
}

// ascendToModel walks up to the directory containing go.mod and returns
// the model path when it exists there.
func ascendToModel(dir string) string {
	for i := 0; i < 40 && dir != "" && dir != string(filepath.Separator); i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			p := filepath.Join(dir, "internal", "platform", "authz", "model.fga")
			if _, err := os.Stat(p); err == nil {
				return p
			}
			return ""
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// admitsUser is a memoized least-fixpoint over the transformed model:
// can relation `rel` on type `typ` ever resolve to a `user`-typed
// subject? An in-progress (typ, rel) resolves to false on the recursive
// edge, which makes the fixpoint least (reachability).
func (m *fgaModel) admitsUser(typ, rel string) bool {
	m.memoMu.Lock()
	defer m.memoMu.Unlock()
	return m.admitsUserLocked(typ, rel)
}

// admitsUserLocked is the recursive body. The lock is taken once at the
// top-level entry point and held for the whole traversal: the recursion
// is pure and cheap, so a single non-reentrant lock is simpler and
// safer than per-key locking.
func (m *fgaModel) admitsUserLocked(typ, rel string) bool {
	key := typ + "#" + rel
	if v, ok := m.memo[key]; ok {
		return v
	}
	m.memo[key] = false // cycle guard

	td, ok := m.types[typ]
	if !ok {
		return false
	}
	userset, ok := td.GetRelations()[rel]
	if !ok {
		return false
	}
	res := m.evalUserset(td, rel, userset)
	m.memo[key] = res
	return res
}

func (m *fgaModel) evalUserset(td *openfgav1.TypeDefinition, rel string, us *openfgav1.Userset) bool {
	if us == nil {
		return false
	}
	switch v := us.GetUserset().(type) {
	case *openfgav1.Userset_This:
		return m.directAdmitsUser(td, rel)
	case *openfgav1.Userset_ComputedUserset:
		return m.admitsUserLocked(td.GetType(), v.ComputedUserset.GetRelation())
	case *openfgav1.Userset_TupleToUserset:
		tuplesetRel := v.TupleToUserset.GetTupleset().GetRelation()
		target := v.TupleToUserset.GetComputedUserset().GetRelation()
		for _, rr := range m.directTypes(td, tuplesetRel) {
			if m.admitsUserLocked(rr.GetType(), target) {
				return true
			}
		}
		return false
	case *openfgav1.Userset_Union:
		for _, child := range v.Union.GetChild() {
			if m.evalUserset(td, rel, child) {
				return true
			}
		}
		return false
	case *openfgav1.Userset_Intersection:
		// A branch that cannot yield a user makes the whole
		// intersection unable to.
		for _, child := range v.Intersection.GetChild() {
			if !m.evalUserset(td, rel, child) {
				return false
			}
		}
		return len(v.Intersection.GetChild()) > 0
	case *openfgav1.Userset_Difference:
		// Subtraction cannot ADD types.
		return m.evalUserset(td, rel, v.Difference.GetBase())
	}
	return false
}

// directAdmitsUser inspects the declared directly-related user types.
// A `user`, `user:*`, or `user with <condition>` entry all satisfy a
// UserTypeFilter{Type:"user"}. A userset entry T#r recurses, because
// ListUsers expands usersets.
func (m *fgaModel) directAdmitsUser(td *openfgav1.TypeDefinition, rel string) bool {
	for _, rr := range m.directTypes(td, rel) {
		if rr.GetType() == "user" {
			return true
		}
		if sub := rr.GetRelation(); sub != "" {
			if m.admitsUserLocked(rr.GetType(), sub) {
				return true
			}
		}
	}
	return false
}

func (m *fgaModel) directTypes(td *openfgav1.TypeDefinition, rel string) []*openfgav1.RelationReference {
	md := td.GetMetadata()
	if md == nil {
		return nil
	}
	rm, ok := md.GetRelations()[rel]
	if !ok {
		return nil
	}
	return rm.GetDirectlyRelatedUserTypes()
}

// declaredSubjectTypes lists the subject types a relation can yield,
// for the diagnostic message.
func (m *fgaModel) declaredSubjectTypes(typ, rel string) []string {
	td, ok := m.types[typ]
	if !ok {
		return nil
	}
	direct := m.directTypes(td, rel)
	out := make([]string, 0, len(direct))
	for _, rr := range direct {
		s := rr.GetType()
		if sub := rr.GetRelation(); sub != "" {
			s += "#" + sub
		}
		out = append(out, s)
	}
	return out
}

// typesDefiningRelation returns every object type declaring `rel`.
func (m *fgaModel) typesDefiningRelation(rel string) []string {
	var out []string
	for name, td := range m.types {
		if _, ok := td.GetRelations()[rel]; ok {
			out = append(out, name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// call-site matching
// ---------------------------------------------------------------------------

// listUsersPrimitiveRecv exempts the primitive itself and its
// passthrough observer — they are not consumers of the contract.
var listUsersPrimitiveRecv = map[string]struct{}{
	"github.com/zeroroot-ai/gibson/internal/platform/authz":    {},
	"github.com/zeroroot-ai/gibson/internal/platform/manifest": {},
}

func runFGAListUsers(pass *analysis.Pass) (any, error) {
	model, err := loadModel(pass)
	if err != nil {
		return nil, err
	}
	if _, exempt := listUsersPrimitiveRecv[pass.Pkg.Path()]; exempt {
		return nil, nil
	}
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
			inspectListUsersCalls(pass, model, file, fn)
		}
	}
	return nil, nil
}

// isListUsersCall matches by SIGNATURE SHAPE, not by concrete type:
// ListUsers is declared on several distinct types (the Authorizer
// interface, narrow local interfaces, the observer passthrough, the
// concrete client), and matching one would leak the others.
func isListUsersCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ListUsers" {
		return false
	}
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok {
		return false
	}
	sig, ok := tv.Type.(*types.Signature)
	if !ok || sig.Params().Len() != 4 || sig.Results().Len() != 2 {
		return false
	}
	// (context.Context, string, string, string) ([]string, error)
	for i := 1; i < 4; i++ {
		if b, ok := sig.Params().At(i).Type().Underlying().(*types.Basic); !ok || b.Kind() != types.String {
			return false
		}
	}
	if s, ok := sig.Results().At(0).Type().Underlying().(*types.Slice); !ok {
		return false
	} else if b, ok := s.Elem().Underlying().(*types.Basic); !ok || b.Kind() != types.String {
		return false
	}
	return isErrorType(sig.Results().At(1).Type()) || implementsError(sig.Results().At(1).Type())
}

func inspectListUsersCalls(pass *analysis.Pass, model *fgaModel, file *ast.File, fn *ast.FuncDecl) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isListUsersCall(pass, call) {
			return true
		}
		objectType, otConst := foldString(pass, call.Args[1])
		relation, relConst := foldString(pass, call.Args[3])

		dir, hasDir := parseFGAListUsersDirective(pass, file, fn, call)
		if hasDir && !dir.valid {
			pass.Reportf(dir.pos, "%s", dir.problem)
			return true
		}

		// R2 first: it is independent of argument resolution AND it is
		// not suppressible. A result-shape contradiction is a provably
		// dead branch — there is no compensating guard that makes it
		// meaningful.
		if prefix, pos, ok := deadTypePrefixFilter(pass, fn, call); ok {
			if !baselined(fgaListUsersRule, pass.Pkg.Path(), fn.Name.Name+"#R2") {
				pass.Reportf(pos,
					"fga ListUsers result-shape contradiction [%s]: this result is filtered on the FGA type prefix %q, but ListUsers hardcodes a user-type filter and can only ever return \"user:\"-prefixed references. The branch is unreachable, so the reconcile or revoke path it guards never runs. Use ListUsersOfType with the subject type you actually want.",
					guardBaselineKey(fgaListUsersRule, pass.Pkg.Path(), fn.Name.Name+"#R2"), prefix)
			}
			return true
		}

		if hasDir && dir.valid {
			return true
		}

		switch {
		case otConst && relConst:
			// R1 — decidable and exact.
			if model.admitsUser(objectType, relation) {
				return true
			}
			if baselined(fgaListUsersRule, pass.Pkg.Path(), fn.Name.Name+"#"+objectType+"/"+relation) {
				return true
			}
			pass.Reportf(call.Pos(),
				"fga ListUsers subject-type mismatch [%s]: relation %q on type %q cannot yield a user-typed subject (declared subject types: %v), but ListUsers filters for user. This call returns an empty result with a nil error on every invocation. Use ListUsersOfType with the declared subject type.",
				guardBaselineKey(fgaListUsersRule, pass.Pkg.Path(), fn.Name.Name+"#"+objectType+"/"+relation),
				relation, objectType, model.declaredSubjectTypes(objectType, relation))
		case relConst && !otConst:
			// R3 with a relation to reason about: if NO type defining
			// this relation admits a user, the call is certainly wrong.
			candidates := model.typesDefiningRelation(relation)
			anyAdmits := false
			for _, t := range candidates {
				if model.admitsUser(t, relation) {
					anyAdmits = true
					break
				}
			}
			if !anyAdmits && len(candidates) > 0 {
				reportUnlessBaselined(pass, fn, "#R3-certain",
					fmt.Sprintf("fga ListUsers subject-type mismatch [%%s]: no object type defining relation %q admits a user-typed subject, so this call can never return a result regardless of which object type the dynamic argument resolves to.", relation),
					call.Pos())
				return true
			}
			reportUnlessBaselined(pass, fn, "#R3",
				fmt.Sprintf("fga ListUsers unresolved arguments [%%s]: the object type is not constant-foldable, so the subject type of relation %q cannot be verified against the model. Hoist the object type to a constant, or switch to ListUsersOfType naming the subject type explicitly.", relation),
				call.Pos())
		default:
			reportUnlessBaselined(pass, fn, "#R3",
				"fga ListUsers unresolved arguments [%s]: neither the object type nor the relation is constant-foldable, so this call cannot be verified against the authorization model. Hoist them to constants, or switch to ListUsersOfType naming the subject type explicitly.",
				call.Pos())
		}
		return true
	})
}

func reportUnlessBaselined(pass *analysis.Pass, fn *ast.FuncDecl, suffix, format string, pos token.Pos) {
	sym := fn.Name.Name + suffix
	if baselined(fgaListUsersRule, pass.Pkg.Path(), sym) {
		return
	}
	pass.Reportf(pos, format, guardBaselineKey(fgaListUsersRule, pass.Pkg.Path(), sym))
}

// foldString resolves an expression to a compile-time string constant,
// covering string literals AND named constants.
func foldString(pass *analysis.Pass, e ast.Expr) (string, bool) {
	tv, ok := pass.TypesInfo.Types[e]
	if !ok || tv.Value == nil {
		return "", false
	}
	s, err := strconv.Unquote(tv.Value.String())
	if err != nil {
		return "", false
	}
	return s, true
}

// ---------------------------------------------------------------------------
// R2 — result-shape contradiction
// ---------------------------------------------------------------------------

// fgaTypePrefixRe matches an FGA type prefix literal such as "team:".
var fgaTypePrefixRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*:$`)

var prefixFuncs = map[string]struct{}{
	"HasPrefix":  {},
	"TrimPrefix": {},
	"CutPrefix":  {},
}

// deadTypePrefixFilter reports whether an element of the call's result
// slice is tested against an FGA type prefix other than "user:".
func deadTypePrefixFilter(pass *analysis.Pass, fn *ast.FuncDecl, call *ast.CallExpr) (string, token.Pos, bool) {
	resultVar := resultBindingOf(pass, fn, call)
	if resultVar == nil {
		return "", 0, false
	}
	var prefix string
	var pos token.Pos
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 2 {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "strings" {
			return true
		}
		if _, ok := prefixFuncs[sel.Sel.Name]; !ok {
			return true
		}
		lit, isConst := foldString(pass, c.Args[1])
		if !isConst || !fgaTypePrefixRe.MatchString(lit) || lit == "user:" {
			return true
		}
		if !derivesFrom(pass, c.Args[0], resultVar) {
			return true
		}
		prefix, pos, found = lit, token.Pos(c.Pos()), true
		return false
	})
	return prefix, pos, found
}

// resultBindingOf returns the types.Object bound to the call's first
// result, when the call appears in a simple assignment.
func resultBindingOf(pass *analysis.Pass, fn *ast.FuncDecl, call *ast.CallExpr) types.Object {
	var out types.Object
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if out != nil {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || assign.Rhs[0] != call || len(assign.Lhs) == 0 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if def := pass.TypesInfo.Defs[id]; def != nil {
			out = def
		} else if use := pass.TypesInfo.Uses[id]; use != nil {
			out = use
		}
		return false
	})
	return out
}

// derivesFrom reports whether expr is an element of the slice bound to
// obj — the range value of `for _, v := range obj`, or `obj[i]`.
func derivesFrom(pass *analysis.Pass, expr ast.Expr, obj types.Object) bool {
	// Direct index expression: obj[i]. Checked first — an IndexExpr is
	// not an Ident, so testing it after the Ident narrowing below would
	// make this branch unreachable.
	if idx, ok := expr.(*ast.IndexExpr); ok {
		xid, ok := idx.X.(*ast.Ident)
		return ok && pass.TypesInfo.Uses[xid] == obj
	}

	id, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	target := pass.TypesInfo.Uses[id]
	if target == nil {
		if target = pass.TypesInfo.Defs[id]; target == nil {
			return false
		}
	}

	// Range value over obj: `for _, v := range obj`.
	found := false
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			if found {
				return false
			}
			rng, ok := n.(*ast.RangeStmt)
			if !ok || rng.Value == nil {
				return true
			}
			xid, ok := rng.X.(*ast.Ident)
			if !ok || pass.TypesInfo.Uses[xid] != obj {
				return true
			}
			vid, ok := rng.Value.(*ast.Ident)
			if !ok {
				return true
			}
			if pass.TypesInfo.Defs[vid] == target {
				found = true
				return false
			}
			return true
		})
	}
	return found
}

// ---------------------------------------------------------------------------
// suppression — mandatory, validated qualifier
// ---------------------------------------------------------------------------

const fgaListUsersDirective = "gibsoncheck:allow fga-list-users"

var fgaListUsersGrammar = regexp.MustCompile(
	`gibsoncheck:allow fga-list-users\s+(?:compensating-guard:([A-Za-z_][A-Za-z0-9_.]*)|(gibson|deploy|sdk)#(\d+))`)

type fgaListUsersDir struct {
	pos     token.Pos
	valid   bool
	problem string
}

// parseFGAListUsersDirective accepts the directive on the enclosing
// function's doc comment OR on the call line. Call-line placement
// matters: several files hold multiple ListUsers calls in one function,
// and a function-level directive would blanket-exempt siblings the
// author never considered.
func parseFGAListUsersDirective(pass *analysis.Pass, file *ast.File, fn *ast.FuncDecl, call *ast.CallExpr) (fgaListUsersDir, bool) {
	callLine := pass.Fset.Position(call.Pos()).Line
	var candidates []*ast.Comment
	if fn.Doc != nil {
		candidates = append(candidates, fn.Doc.List...)
	}
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			l := pass.Fset.Position(c.Pos()).Line
			if l == callLine || l == callLine-1 {
				candidates = append(candidates, c)
			}
		}
	}
	for _, c := range candidates {
		if !strings.Contains(c.Text, fgaListUsersDirective) {
			continue
		}
		d := fgaListUsersDir{pos: token.Pos(c.Pos())}
		m := fgaListUsersGrammar.FindStringSubmatch(c.Text)
		if m == nil {
			d.problem = "bare gibsoncheck:allow fga-list-users is not permitted; qualify with compensating-guard:<Symbol> or <repo>#<issue>"
			return d, true
		}
		if sym := m[1]; sym != "" {
			bare := sym
			if i := strings.LastIndex(bare, "."); i >= 0 {
				bare = bare[i+1:]
			}
			if !symbolResolves(pass, bare) {
				d.problem = fmt.Sprintf("gibsoncheck:allow fga-list-users names compensating-guard:%s, which does not resolve to a function or method in scope", sym)
				return d, true
			}
		}
		d.valid = true
		return d, true
	}
	return fgaListUsersDir{}, false
}

// ResetFGAModelForTest clears the process-wide parsed-model cache. The
// analyzer memoizes the model for the life of the process, which is
// correct in CI but would leak between test cases here.
func ResetFGAModelForTest() {
	modelMu.Lock()
	defer modelMu.Unlock()
	modelVal = nil
}

// LoadFGAModelForTest exposes the model-load path so the fail-closed
// contract can be asserted directly. It must ERROR — never return a
// usable-but-empty model — when the model is missing or unparseable.
func LoadFGAModelForTest(path string) error {
	ResetFGAModelForTest()
	defer ResetFGAModelForTest()
	prev := modelPathFlag
	modelPathFlag = path
	defer func() { modelPathFlag = prev }()
	_, err := loadModel(&analysis.Pass{})
	return err
}
