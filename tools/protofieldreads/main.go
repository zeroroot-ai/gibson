// Command protofieldreads lists every read of a generated proto message
// field in a Go module, resolved by the type checker.
//
// It is the Go half of scripts/check-proto-field-consumers.sh (ADR-0094
// layer 5, gibson#502). A name match cannot tell AckTenantOpResponse.acked
// from AckTenantProvisionedResponse.acked, so the gate asks the type checker
// which struct a selector resolves to.
//
// A read is a selector expression that resolves to a field of a struct, or
// a call of its generated getter. A composite-literal key is not a selector,
// and the left-hand side of an assignment is a write, so neither counts.
// Generated files and test files are skipped: generated code reads every
// field, and a test reading a field proves the field can be read, not that
// anything does.
//
// Output, one per line, sorted and unique:
//
//	<import path>.<Type>.<Field>
//
// Usage:
//
//	protofieldreads -dir <module root> [-prefix <import path prefix>]
//
// -prefix limits the output to types declared under that import path; empty
// means every struct type in the load.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, collects the reads and prints them, returning the exit
// code. It is main without os.Exit so the test can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("protofieldreads", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "module root to load")
	prefix := fs.String("prefix", "", "only report types whose import path starts with this")
	tags := fs.String("tags", "setec_integration", "build tags, the image's by default")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	reads, err := collect(*dir, *prefix, *tags)
	if err != nil {
		fmt.Fprintln(stderr, "protofieldreads:", err)
		return 1
	}
	for _, r := range reads {
		fmt.Fprintln(stdout, r)
	}
	return 0
}

// collect loads every package under dir and returns the sorted, unique set
// of field reads on struct types under prefix.
func collect(dir, prefix, tags string) ([]string, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:        dir,
		Tests:      false,
		BuildFlags: []string{"-tags=" + tags},
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", dir, err)
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	})
	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("%d load errors, first: %s", len(loadErrs), loadErrs[0])
	}

	seen := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			if ast.IsGenerated(f) {
				continue
			}
			writes := assignmentTargets(f)
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || writes[sel] {
					return true
				}
				key, ok := fieldRead(p.TypesInfo, sel, prefix)
				if ok {
					seen[key] = true
				}
				return true
			})
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// assignmentTargets marks every selector that is the left-hand side of an
// assignment or an increment: those are writes.
func assignmentTargets(f *ast.File) map[*ast.SelectorExpr]bool {
	writes := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					writes[sel] = true
				}
			}
		case *ast.IncDecStmt:
			if sel, ok := s.X.(*ast.SelectorExpr); ok {
				writes[sel] = true
			}
		}
		return true
	})
	return writes
}

// fieldRead resolves sel to <import path>.<Type>.<Field> when it is a field
// read or a generated getter call on a struct type under prefix.
func fieldRead(info *types.Info, sel *ast.SelectorExpr, prefix string) (string, bool) {
	s, ok := info.Selections[sel]
	if !ok {
		return "", false
	}
	named, ok := receiverNamed(s.Recv())
	if !ok {
		return "", false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return "", false
	}
	pkg := named.Obj().Pkg()
	if pkg == nil || !strings.HasPrefix(pkg.Path(), prefix) {
		return "", false
	}
	var field string
	switch s.Kind() {
	case types.FieldVal:
		field = s.Obj().Name()
	case types.MethodVal:
		name := s.Obj().Name()
		if !strings.HasPrefix(name, "Get") || !hasField(st, name[3:]) {
			return "", false
		}
		field = name[3:]
	case types.MethodExpr:
		// A method expression (T.GetFoo) names the getter without calling it
		// on a value; nothing in the tree reads a field that way.
		return "", false
	default:
		return "", false
	}
	return pkg.Path() + "." + named.Obj().Name() + "." + field, true
}

func receiverNamed(t types.Type) (*types.Named, bool) {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	return named, ok
}

func hasField(st *types.Struct, name string) bool {
	for i := range st.NumFields() {
		if st.Field(i).Name() == name {
			return true
		}
	}
	return false
}
