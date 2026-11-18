// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestLLMAdapterHasTenantResolverWired asserts, in source, that the
// ComponentService LLM adapter is constructed WITH a per-tenant resolver.
//
// NewLLMRegistryAdapter alone leaves resolveTenant nil, and the adapter then
// fails every completion closed with "per-tenant LLM provider resolution is
// not configured" (llm_adapter.go) — the adapter is wired into
// ComponentService but inert, so an enrolled agent's completion never reaches
// a provider. The bug is invisible to a unit test of the construction site
// (it compiles and runs); it only shows at runtime on a real completion. This
// pins the wiring: delete the WithTenantResolver call and this fails.
//
// Source-level because the construction lives inside buildGRPCServer, which
// needs the whole infrastructure stack to invoke.
func TestLLMAdapterHasTenantResolverWired(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "grpc.go", nil, 0)
	if err != nil {
		t.Fatalf("parse grpc.go: %v", err)
	}

	var wired bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !callTargets(call, "WithTenantResolver") {
			return true
		}
		// The resolver must be the daemon's shared per-tenant builder, the
		// same one the mission path uses — not some inert stub.
		for _, arg := range call.Args {
			if subtreeMentions(arg, "newSlotManagerForTenant") {
				wired = true
			}
		}
		return true
	})

	if !wired {
		t.Fatal("the ComponentService LLM adapter is not constructed with " +
			".WithTenantResolver(d.newSlotManagerForTenant()) — every enrolled-component " +
			"completion will fail closed with \"per-tenant LLM provider resolution is not configured\"")
	}
}
