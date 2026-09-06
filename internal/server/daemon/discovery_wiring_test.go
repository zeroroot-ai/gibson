// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestEveryDiscoveryDispatchPathIsWired asserts, in source, that each of the
// three dispatch paths that can carry a DiscoveryResult hands the daemon's
// processor to its seam.
//
// The behavioural test above proves the processor works. It cannot prove the
// processor is *reached*: delete any one of these three wiring lines and every
// other test in this package still passes, while field-100 payloads arriving on
// that path silently reach nothing. That is precisely the defect gibson#1266
// exists to remove — the previous ingest package was imported by seven files
// and constructed by none — so "is it wired?" needs an assertion of its own.
//
// Source-level because there is no unit-level seam: the two daemon wiring sites
// live inside Start and buildGRPCServer, which need the whole infrastructure
// stack to call.
func TestEveryDiscoveryDispatchPathIsWired(t *testing.T) {
	cases := []struct {
		file    string
		sink    string // the method or constructor the processor must reach
		context string // what breaks when it is missing
	}{
		{"daemon.go", "SetDiscoveryProcessor", "harness callback dispatch"},
		{"grpc.go", "WithDiscoveryProcessor", "ComponentService.SubmitResult (proto field 100)"},
		{"harness_init.go", "NewSetecSandboxedExecutor", "sandboxed (setec) tool dispatch"},
	}

	for _, tc := range cases {
		t.Run(tc.context, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.file, err)
			}

			var wired bool
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !callTargets(call, tc.sink) {
					return true
				}
				for _, arg := range call.Args {
					if subtreeMentions(arg, "newDiscoveryProcessor") {
						wired = true
					}
				}
				return true
			})

			if !wired {
				t.Fatalf("%s no longer passes newDiscoveryProcessor() to %s — "+
					"DiscoveryResult payloads arriving on the %s path reach nothing, silently",
					tc.file, tc.sink, tc.context)
			}
		})
	}
}

// callTargets reports whether the call names fn, as a bare identifier or as the
// selector of any receiver.
func callTargets(call *ast.CallExpr, fn string) bool {
	switch target := call.Fun.(type) {
	case *ast.Ident:
		return target.Name == fn
	case *ast.SelectorExpr:
		return target.Sel.Name == fn
	}
	return false
}

// subtreeMentions reports whether name appears as an identifier anywhere under
// n, so an argument built inline (an adapter wrapping the call) counts as wired
// just as a variable holding it does.
func subtreeMentions(n ast.Node, name string) bool {
	var found bool
	ast.Inspect(n, func(node ast.Node) bool {
		switch id := node.(type) {
		case *ast.Ident:
			if id.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if id.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	if found {
		return true
	}
	// An argument may be a variable assigned from the constructor earlier in the
	// function (harness_init.go does this); the caller passes the identifier, so
	// fall back to the name itself.
	ident, ok := n.(*ast.Ident)
	return ok && strings.Contains(ident.Name, "Discovery") && ident.Obj != nil
}
