// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// slotResolverWired reports whether the source holds a call to
// WithSlotModelResolver whose argument uses newSlotManagerForTenant.
func slotResolverWired(t *testing.T, name string, src any) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var wired bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !callTargets(call, "WithSlotModelResolver") {
			return true
		}
		// The resolver must be the shared per-tenant builder of the daemon,
		// the same one that the mission path uses. A stub is not enough.
		for _, arg := range call.Args {
			if subtreeMentions(arg, "newSlotManagerForTenant") {
				wired = true
			}
		}
		return true
	})
	return wired
}

// TestComponentServiceHasSlotResolverWired asserts, in source, that the
// ComponentService is built with a slot resolver over the per-tenant slot
// manager.
//
// Without it, ResolveModel answers Unavailable ("the model gateway is not
// configured on this server") for each agent in pull mode. The bug is invisible
// to a unit test of the construction site, because it compiles and runs. It
// shows only on a real call. This test pins the wiring.
//
// The check reads the source because the construction is inside
// buildGRPCServer, which needs the whole infrastructure stack to run.
func TestComponentServiceHasSlotResolverWired(t *testing.T) {
	src, err := os.ReadFile("grpc.go")
	if err != nil {
		t.Fatalf("read grpc.go: %v", err)
	}
	if !slotResolverWired(t, "grpc.go", src) {
		t.Fatal("the ComponentService is not built with " +
			".WithSlotModelResolver(&componentSlotModels{forTenant: d.newSlotManagerForTenant()}): " +
			"ResolveModel answers Unavailable for each agent in pull mode")
	}
}

// TestSlotResolverWiringGuard_FailsOnAnUnwiredSource is the failing fixture of
// the guard above. A source with no resolver, or with a resolver that is not
// the per-tenant slot manager, must not pass.
func TestSlotResolverWiringGuard_FailsOnAnUnwiredSource(t *testing.T) {
	cases := map[string]string{
		"no call": `package p
func f(s *S) { s.WithGateways() }`,
		"a stub resolver": `package p
func f(s *S) { s.WithSlotModelResolver(&stub{}) }`,
	}
	for name, src := range cases {
		if slotResolverWired(t, "fixture.go", src) {
			t.Errorf("%s: the guard accepted a source with no per-tenant slot resolver", name)
		}
	}
	good := `package p
func f(s *S) { s.WithSlotModelResolver(&componentSlotModels{forTenant: d.newSlotManagerForTenant()}) }`
	if !slotResolverWired(t, "fixture.go", good) {
		t.Error("the guard rejected the wired source")
	}
}
