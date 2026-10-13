// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	pathpkg "path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// envName is the shape of an env var name.
var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// baseReaders are the standard-library calls that read one env var, keyed
// by package and function. The name is argument 0.
var baseReaders = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true},
	"syscall": {"Getenv": true},
}

// source is the parsed tree of every scanned file, and the facts the reads
// are resolved against. The facts are keyed by bare name, with no package:
// two packages that use one name for two strings both count, which can only
// add a name.
type source struct {
	files []*ast.File
	// consts maps a const or var name to the string literals it holds.
	consts map[string][]string
	// slices maps a var name to the elements of the composite literal it holds.
	slices map[string][]ast.Expr
	// fields maps a struct field name to the values a composite literal or
	// an assignment gives it: a string literal, or a constant.
	fields map[string][]ast.Expr
	// envFields are the struct fields an env read takes its name from:
	// os.Getenv(e.configKnob).
	envFields map[string]bool
	// readers maps a function or method name to the indexes of the
	// parameters it passes to an env read.
	readers map[string]map[int]bool
}

// parseSource parses each file. A file that does not parse adds nothing: the
// compiler refuses it, so it reads nothing.
func parseSource(files map[string][]byte) *source {
	s := &source{
		consts:    map[string][]string{},
		slices:    map[string][]ast.Expr{},
		fields:    map[string][]ast.Expr{},
		envFields: map[string]bool{},
		readers:   map[string]map[int]bool{},
	}
	fset := token.NewFileSet()
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		s.files = append(s.files, f)
	}
	for _, f := range s.files {
		s.collectFacts(f)
	}
	s.findReaders()
	return s
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

func (s *source) collectFacts(f *ast.File) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if i >= len(n.Values) {
					break
				}
				if v, ok := stringLit(n.Values[i]); ok {
					s.consts[id.Name] = append(s.consts[id.Name], v)
				}
				if cl, ok := n.Values[i].(*ast.CompositeLit); ok {
					s.slices[id.Name] = append(s.slices[id.Name], cl.Elts...)
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := n.Key.(*ast.Ident); ok && nameValue(n.Value) {
				s.fields[key.Name] = append(s.fields[key.Name], n.Value)
			}
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				if i >= len(n.Rhs) {
					break
				}
				switch l := lhs.(type) {
				case *ast.SelectorExpr:
					if nameValue(n.Rhs[i]) {
						s.fields[l.Sel.Name] = append(s.fields[l.Sel.Name], n.Rhs[i])
					}
				case *ast.Ident:
					if v, ok := stringLit(n.Rhs[i]); ok && n.Tok == token.DEFINE {
						s.consts[l.Name] = append(s.consts[l.Name], v)
					}
				}
			}
		}
		return true
	})
}

// nameValue reports whether e can hold an env name: a string literal, a
// constant, or a constant of another package.
func nameValue(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.Ident, *ast.SelectorExpr:
		return true
	}
	return false
}

// scope is what one function body adds to the facts: the local readers (a
// parameter of type func(string) string, or a closure that reads env with
// its parameter) and the range variables over a list.
type scope struct {
	locals map[string]bool
	ranges map[string][]ast.Expr
	params map[string]int
	// pkg is the package of the file, and imports maps each import name of
	// the file to the package it names. A reader function is keyed by
	// package, so two packages with one function name stay apart.
	pkg     string
	imports map[string]string
}

// fileScope is the scope of a file with no function: its package and its
// imports.
func fileScope(f *ast.File) *scope {
	sc := &scope{locals: map[string]bool{}, ranges: map[string][]ast.Expr{}, params: map[string]int{},
		pkg: f.Name.Name, imports: map[string]string{}}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := pathpkg.Base(path)
		if len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
			name = pathpkg.Base(pathpkg.Dir(path))
		}
		local := name
		if imp.Name != nil {
			local = imp.Name.Name
		}
		sc.imports[local] = name
	}
	return sc
}

// isGetenvFunc reports whether t is func(string) string or
// func(string) (string, bool), the type of os.Getenv and os.LookupEnv.
func isGetenvFunc(t ast.Expr) bool {
	ft, ok := t.(*ast.FuncType)
	if !ok || ft.Params == nil || len(ft.Params.List) != 1 || len(ft.Params.List[0].Names) > 1 {
		return false
	}
	if id, ok := ft.Params.List[0].Type.(*ast.Ident); !ok || id.Name != "string" {
		return false
	}
	if ft.Results == nil || len(ft.Results.List) == 0 {
		return false
	}
	id, ok := ft.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "string"
}

// paramNames maps each string parameter of ft to its index. Only a string
// parameter can carry an env name, so a context or a request never makes a
// function a reader.
func paramNames(ft *ast.FuncType) map[string]int {
	out := map[string]int{}
	if ft.Params == nil {
		return out
	}
	i := 0
	for _, field := range ft.Params.List {
		id, isString := field.Type.(*ast.Ident)
		isString = isString && id.Name == "string"
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, name := range field.Names {
			if isString {
				out[name.Name] = i
			}
			i++
		}
	}
	return out
}

func (s *source) newScope(file *scope, ft *ast.FuncType, body *ast.BlockStmt) *scope {
	sc := &scope{locals: map[string]bool{}, ranges: map[string][]ast.Expr{}, params: paramNames(ft),
		pkg: file.pkg, imports: file.imports}
	if ft.Params != nil {
		for _, field := range ft.Params.List {
			if isGetenvFunc(field.Type) {
				for _, id := range field.Names {
					sc.locals[id.Name] = true
				}
			}
		}
	}
	if body == nil {
		return sc
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.RangeStmt:
			v, ok := n.Value.(*ast.Ident)
			if !ok {
				return true
			}
			switch x := n.X.(type) {
			case *ast.CompositeLit:
				sc.ranges[v.Name] = append(sc.ranges[v.Name], x.Elts...)
			case *ast.Ident:
				sc.ranges[v.Name] = append(sc.ranges[v.Name], s.slices[x.Name]...)
			}
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(n.Rhs) {
					continue
				}
				switch r := n.Rhs[i].(type) {
				case *ast.FuncLit:
					if s.readsParam(file, r.Type, r.Body) {
						sc.locals[id.Name] = true
					}
				case *ast.SelectorExpr:
					if x, ok := r.X.(*ast.Ident); ok && baseReaders[x.Name][r.Sel.Name] {
						sc.locals[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return sc
}

// readsParam reports whether a closure passes its parameter 0 to an env read.
func (s *source) readsParam(file *scope, ft *ast.FuncType, body *ast.BlockStmt) bool {
	sc := s.newScope(file, ft, nil)
	found := false
	s.eachRead(body, sc, func(arg ast.Expr) {
		if id, ok := arg.(*ast.Ident); ok {
			if i, isParam := sc.params[id.Name]; isParam && i == 0 {
				found = true
			}
		}
	})
	return found
}

// eachRead calls fn with the name argument of each env read in body: a base
// reader, a local reader of sc, or a reader function at its reader index.
func (s *source) eachRead(body ast.Node, sc *scope, fn func(arg ast.Expr)) {
	if body == nil || reflect.ValueOf(body).IsNil() {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var indexes map[int]bool
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if sc.locals[f.Name] {
				indexes = map[int]bool{0: true}
			} else {
				indexes = s.readers[sc.pkg+"."+f.Name]
			}
		case *ast.SelectorExpr:
			x, ok := f.X.(*ast.Ident)
			if !ok {
				break
			}
			pkg, isImport := sc.imports[x.Name]
			switch {
			case isImport && baseReaders[pkg][f.Sel.Name]:
				indexes = map[int]bool{0: true}
			case isImport:
				indexes = s.readers[pkg+"."+f.Sel.Name]
			}
		}
		for i := range indexes {
			if i < len(call.Args) {
				fn(call.Args[i])
			}
		}
		return true
	})
}

// findReaders finds, to a fixed point, each function that passes one of its
// parameters to an env read: durationOr(key, ...) in cmd/ext-authz. A
// function that stores a parameter in a field that an env read takes its
// name from is a reader too: seam.Register(name, configKnob, ...).
func (s *source) findReaders() {
	s.findEnvFields()
	for changed := true; changed; {
		changed = false
		mark := func(fn string, i int) {
			if s.readers[fn][i] {
				return
			}
			if s.readers[fn] == nil {
				s.readers[fn] = map[int]bool{}
			}
			s.readers[fn][i] = true
			changed = true
		}
		for _, f := range s.files {
			file := fileScope(f)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				// A method is not a reader: a call site does not show the
				// type of its receiver, so a method name cannot be matched.
				if !ok || fd.Body == nil || fd.Recv != nil {
					continue
				}
				key := file.pkg + "." + fd.Name.Name
				sc := s.newScope(file, fd.Type, fd.Body)
				s.eachRead(fd.Body, sc, func(arg ast.Expr) {
					if a, ok := arg.(*ast.Ident); ok {
						if i, isParam := sc.params[a.Name]; isParam {
							mark(key, i)
						}
					}
				})
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					kv, ok := n.(*ast.KeyValueExpr)
					if !ok {
						return true
					}
					field, ok := kv.Key.(*ast.Ident)
					val, ok2 := kv.Value.(*ast.Ident)
					if ok && ok2 && s.envFields[field.Name] {
						if i, isParam := sc.params[val.Name]; isParam {
							mark(key, i)
						}
					}
					return true
				})
			}
		}
	}
}

// findEnvFields finds the selectors that a direct env read takes its name
// from: os.Getenv(e.configKnob). A selector can also name a constant of
// another package (os.Getenv(api.EnvAppURL)); such a name has no field
// value, so it adds nothing here.
func (s *source) findEnvFields() {
	for _, f := range s.files {
		file := fileScope(f)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			fun, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := fun.X.(*ast.Ident)
			if !ok || !baseReaders[file.imports[x.Name]][fun.Sel.Name] {
				return true
			}
			if a, ok := call.Args[0].(*ast.SelectorExpr); ok {
				s.envFields[a.Sel.Name] = true
			}
			return true
		})
	}
}

// resolve gives the env names an argument of an env read can hold.
func (s *source) resolve(arg ast.Expr, sc *scope, add func(string)) {
	addLit := func(v string) {
		if envName.MatchString(v) {
			add(v)
		}
	}
	switch a := arg.(type) {
	case *ast.BasicLit:
		if v, ok := stringLit(a); ok {
			addLit(v)
		}
	case *ast.Ident:
		if elts, ok := sc.ranges[a.Name]; ok {
			for _, e := range elts {
				s.resolve(e, sc, add)
			}
			return
		}
		for _, v := range s.consts[a.Name] {
			addLit(v)
		}
	case *ast.SelectorExpr:
		// The selector names a constant of another package (api.EnvAppURL),
		// or a struct field (s.spec.ConfigKnob). Both count, since the
		// scan does not see types.
		for _, v := range s.consts[a.Sel.Name] {
			addLit(v)
		}
		// A field value counts as a literal or a constant only. One field
		// that copies another (Knob: cfg.Knob) is not followed, so a cycle
		// cannot recurse.
		for _, e := range s.fields[a.Sel.Name] {
			switch v := e.(type) {
			case *ast.BasicLit:
				s.resolve(v, &scope{}, add)
			case *ast.Ident:
				for _, c := range s.consts[v.Name] {
					addLit(c)
				}
			case *ast.SelectorExpr:
				for _, c := range s.consts[v.Sel.Name] {
					addLit(c)
				}
			}
		}
	case *ast.CallExpr:
		// strings.TrimSpace(x) and the like: the name is the argument.
		if len(a.Args) == 1 {
			s.resolve(a.Args[0], sc, add)
		}
	case *ast.ParenExpr:
		s.resolve(a.X, sc, add)
	}
}

// structTagNames gives the names of `env:"NAME"` struct tags, the reads of
// an env-to-struct loader.
func structTagNames(f *ast.File, add func(string)) {
	ast.Inspect(f, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok || field.Tag == nil {
			return true
		}
		raw, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			return true
		}
		if v, ok := reflect.StructTag(raw).Lookup("env"); ok && envName.MatchString(v) {
			add(v)
		}
		return true
	})
}

// envReads returns every env name the files can read.
func envReads(files map[string][]byte) map[string]bool {
	s := parseSource(files)
	out := map[string]bool{}
	add := func(n string) { out[n] = true }
	for _, f := range s.files {
		structTagNames(f, add)
		file := fileScope(f)
		visit := func(ft *ast.FuncType, body *ast.BlockStmt) {
			sc := s.newScope(file, ft, body)
			s.eachRead(body, sc, func(arg ast.Expr) { s.resolve(arg, sc, add) })
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				visit(n.Type, n.Body)
			case *ast.FuncLit:
				visit(n.Type, n.Body)
			}
			return true
		})
		// A read at package level: var x = os.Getenv("NAME").
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok {
				s.eachRead(gd, file, func(arg ast.Expr) { s.resolve(arg, file, add) })
			}
		}
	}
	return out
}
