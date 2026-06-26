// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	dataplaneclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// TestCacheKindParity_WrapperVsManager locks the invariant that the
// per-tenant-kind set known to the dataplane client wrapper
// (internal/dataplane/client.PerTenantKinds) is identical to the
// per-tenant-kind set the manager-cache excludes from cluster-scope
// LIST/WATCH (cmd/cache_disable_for.go perTenantNamespaceCacheDisableTypes).
//
// Drift between these two sets reproduces the bug class behind
// tenant-operator#57: a kind the wrapper guards but the manager doesn't
// exclude from cache hangs in WaitForCacheSync forever (no cluster-wide
// LIST permission); a kind the manager excludes but the wrapper doesn't
// guard regresses the n.ns vs tenantNS divergence. The two lists MUST
// stay byte-identical.
//
// PRD module: zeroroot-ai/tenant-operator#76 Module 3 / issue #86.
func TestCacheKindParity_WrapperVsManager(t *testing.T) {
	managerSet := toTypeNameSet(perTenantNamespaceCacheDisableTypes())
	wrapperSet := toTypeNameSet(dataplaneclient.PerTenantKinds())

	if diff := diffSet(managerSet, wrapperSet); diff != "" {
		t.Errorf("manager-cache list has kinds the wrapper doesn't guard:\n%s\n"+
			"Add the missing kinds to internal/dataplane/client.PerTenantKinds "+
			"AND update the wrapper's perTenantKind type-switch.", diff)
	}
	if diff := diffSet(wrapperSet, managerSet); diff != "" {
		t.Errorf("wrapper guards kinds the manager-cache doesn't exclude:\n%s\n"+
			"Add the missing kinds to cmd/cache_disable_for.go "+
			"perTenantNamespaceCacheDisableTypes() — without it, "+
			"WaitForCacheSync will hang and the reconciler will never dispatch.", diff)
	}
}

func toTypeNameSet[T any](objs []T) map[string]bool {
	out := map[string]bool{}
	for _, o := range objs {
		out[fmt.Sprintf("%T", o)] = true
	}
	return out
}

// diffSet returns elements in a not in b, sorted, one-per-line.
func diffSet(a, b map[string]bool) string {
	var only []string
	for k := range a {
		if !b[k] {
			only = append(only, k)
		}
	}
	sort.Strings(only)
	var b2 strings.Builder
	for _, k := range only {
		b2.WriteString("  ")
		b2.WriteString(k)
		b2.WriteByte('\n')
	}
	return b2.String()
}
