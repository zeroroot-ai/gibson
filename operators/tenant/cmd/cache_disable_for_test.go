// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// apiAliases maps each import alias the operator uses for a Kubernetes API
// package to that package's group and version. The walk below judges only
// composite literals of these aliases.
var apiAliases = map[string]schema.GroupVersion{
	"corev1":       {Group: "", Version: "v1"},
	"appsv1":       {Group: "apps", Version: "v1"},
	"batchv1":      {Group: "batch", Version: "v1"},
	"networkingv1": {Group: "networking.k8s.io", Version: "v1"},
	"rbacv1":       {Group: "rbac.authorization.k8s.io", Version: "v1"},
}

// allowedNotInDisableFor holds the API kinds that the operator code
// instantiates and that need no DisableFor entry. Each entry has a reason.
var allowedNotInDisableFor = map[string]string{
	"corev1.Pod":                       "diagnostic-only via APIReader; cache not registered",
	"corev1.Event":                     "Create-only; cluster-wide grant in operator ClusterRole",
	"corev1.Namespace":                 "cluster-scoped resource; cache is fine",
	"rbacv1.ClusterRole":               "cluster-scoped resource; cache is fine",
	"rbacv1.ClusterRoleBinding":        "cluster-scoped resource; cache is fine",
	"corev1.ObjectReference":           "a kind in the scheme, but used here only as an embedded reference",
	"corev1.LocalObjectReference":      "a kind in the scheme, but used here only as an embedded reference",
	"corev1.SecretReference":           "a kind in the scheme, but used here only as an embedded reference",
	"corev1.TypedLocalObjectReference": "a kind in the scheme, but used here only as an embedded reference",
}

// TestCacheDisableForParity walks every non-test .go file under internal/
// and finds each Kubernetes API kind instantiated as a composite literal
// (`&corev1.Service{}`, `batchv1.CronJob{}`). Each such kind MUST appear in
// perTenantNamespaceCacheDisableTypes(), or in allowedNotInDisableFor with
// a reason. A `<Kind>List` literal counts as its kind.
//
// Why: controller-runtime's typed cache lazily registers a cluster-wide
// LIST/WATCH informer the first time client.Get/List sees a kind. The
// operator holds those verbs at the per-tenant Role level only. A kind used
// through the manager client and missing from DisableFor makes the
// reflector retry the cluster-scope LIST forever, and the step that uses it
// fails on "failed waiting for Informer to sync". Incidents of this class:
// tenant-operator#49 (PVC), tenant-operator#57 (Service and StatefulSet),
// gibson#1089 (the belief trainer CronJob in internal/saga/flows, which the
// earlier walk of internal/dataplane/ only did not see).
//
// Embedded types (PodSpec, CronJobSpec) are not kinds in the scheme, so the
// walk skips them without an allowlist entry.
func TestCacheDisableForParity(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	internalDir := filepath.Join(filepath.Dir(thisFile), "..", "internal")

	used := usedAPIKinds(t, internalDir)
	if len(used) == 0 {
		t.Fatalf("no Kubernetes API kind found under %s: the walk is blind", internalDir)
	}
	for _, name := range missingFromDisableFor(used, perTenantNamespaceCacheDisableTypes()) {
		t.Errorf(
			"%s instantiated in internal/%s but missing from "+
				"cmd/cache_disable_for.go perTenantNamespaceCacheDisableTypes(). "+
				"Either add it to that list (and to the chart's per-tenant "+
				"ClusterRole) OR add it to allowedNotInDisableFor with a reason. "+
				"See tenant-operator#49 / #57 / #76, gibson#1089.",
			name, used[name])
	}
}

// TestCacheDisableForParity_FailsOnAMissingKind proves the check fails on the
// shape of gibson#1089: a CronJob instantiated outside internal/dataplane/
// with no DisableFor entry.
func TestCacheDisableForParity_FailsOnAMissingKind(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "saga", "flows")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package flows\n\nimport batchv1 \"k8s.io/api/batch/v1\"\n\n" +
		"func cj() *batchv1.CronJob { return &batchv1.CronJob{Spec: batchv1.CronJobSpec{}} }\n"
	if err := os.WriteFile(filepath.Join(sub, "trainer.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	used := usedAPIKinds(t, dir)
	if _, ok := used["batchv1.CronJobSpec"]; ok {
		t.Fatal("an embedded type must not count as a kind")
	}
	without := missingFromDisableFor(used, nil)
	if len(without) != 1 || without[0] != "batchv1.CronJob" {
		t.Fatalf("want one finding batchv1.CronJob with an empty list, got %v", without)
	}
	if got := missingFromDisableFor(used, perTenantNamespaceCacheDisableTypes()); len(got) != 0 {
		t.Fatalf("the real list must cover the CronJob, got %v", got)
	}
}

// usedAPIKinds returns each API kind instantiated under root, keyed by
// "<alias>.<Kind>", with the first file (relative to root) where it occurs.
func usedAPIKinds(t *testing.T, root string) map[string]string {
	t.Helper()
	known := clientgoscheme.Scheme.AllKnownTypes()
	used := map[string]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}
			sel, ok := cl.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			gv, ok := apiAliases[pkgIdent.Name]
			if !ok {
				return true
			}
			kind := strings.TrimSuffix(sel.Sel.Name, "List")
			if _, isKind := known[gv.WithKind(kind)]; !isKind {
				return true
			}
			key := pkgIdent.Name + "." + kind
			if _, already := used[key]; !already {
				used[key] = rel
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return used
}

// missingFromDisableFor returns, sorted, each used kind that is neither in
// list nor in allowedNotInDisableFor.
func missingFromDisableFor(used map[string]string, list []client.Object) []string {
	got := map[string]bool{}
	for _, obj := range list {
		got[shortName(obj)] = true
	}
	var out []string
	for name := range used {
		if got[name] {
			continue
		}
		if _, ok := allowedNotInDisableFor[name]; ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// shortName returns the "<alias>.<Kind>" form of obj that the walk emits.
func shortName(obj any) string {
	rt := reflect.TypeOf(obj)
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	for alias, gv := range apiAliases {
		if apiPackage(gv) == rt.PkgPath() {
			return alias + "." + rt.Name()
		}
	}
	return rt.PkgPath() + "." + rt.Name()
}

// apiPackage is the Go import path of the k8s.io/api package of gv.
func apiPackage(gv schema.GroupVersion) string {
	group := gv.Group
	switch group {
	case "":
		group = "core"
	case "networking.k8s.io":
		group = "networking"
	case "rbac.authorization.k8s.io":
		group = "rbac"
	}
	return "k8s.io/api/" + group + "/" + gv.Version
}
