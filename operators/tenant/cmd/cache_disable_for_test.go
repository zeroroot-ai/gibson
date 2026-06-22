/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCacheDisableForParity walks every .go file under internal/dataplane/
// looking for K8s types instantiated as struct literals (`&corev1.Service{}`,
// `appsv1.StatefulSet{}`, etc.). Every type found that lives in a per-tenant
// namespace MUST appear in perTenantNamespaceCacheDisableTypes().
//
// Why: controller-runtime's typed cache lazily registers a cluster-wide
// LIST/WATCH informer the first time client.Get/List sees a kind. The
// operator only holds those verbs at the per-tenant Role level. A type
// touched through the manager client but missing from DisableFor causes
// WaitForCacheSync to hang forever, the reconciler to never dispatch,
// and every signup to time out at PROVISIONING_TIMEOUT. Three real
// incidents traced to exactly this class — tenant-operator#49 (PVC),
// tenant-operator#57 (Service + StatefulSet). This test locks the
// invariant so a fourth incident isn't possible from the same root cause.
//
// The walk is approximate — false positives (Pod, embedded types) are
// filtered against the allowlist below with a recorded justification.
func TestCacheDisableForParity(t *testing.T) {
	// Types referenced in internal/dataplane/ that are NOT used through
	// the manager client (embedded sub-types, diagnostic-only reads via
	// APIReader, cluster-scoped resources whose cache is fine). Each
	// entry needs a written justification.
	allowedNotInDisableFor := map[string]string{
		"corev1.Pod":                            "diagnostic-only via APIReader; cache not registered",
		"corev1.Event":                          "Create-only; cluster-wide grant in operator ClusterRole",
		"corev1.PodSpec":                        "embedded type, not a top-level resource",
		"corev1.Container":                      "embedded type, not a top-level resource",
		"corev1.VolumeSource":                   "embedded type, not a top-level resource",
		"corev1.Volume":                         "embedded type, not a top-level resource",
		"corev1.VolumeMount":                    "embedded type, not a top-level resource",
		"corev1.ResourceList":                   "embedded type, not a top-level resource",
		"corev1.ResourceRequirements":           "embedded type, not a top-level resource",
		"corev1.VolumeResourceRequirements":     "embedded type, not a top-level resource",
		"corev1.ConfigMapKeySelector":           "embedded type, not a top-level resource",
		"corev1.SecretKeySelector":              "embedded type, not a top-level resource",
		"corev1.EnvVar":                         "embedded type, not a top-level resource",
		"corev1.EnvVarSource":                   "embedded type, not a top-level resource",
		"corev1.EnvFromSource":                  "embedded type, not a top-level resource",
		"corev1.SecretEnvSource":                "embedded type, not a top-level resource",
		"corev1.ConfigMapEnvSource":             "embedded type, not a top-level resource",
		"corev1.Probe":                          "embedded type, not a top-level resource",
		"corev1.ProbeHandler":                   "embedded type, not a top-level resource",
		"corev1.TCPSocketAction":                "embedded type, not a top-level resource",
		"corev1.ExecAction":                     "embedded type, not a top-level resource",
		"corev1.HTTPGetAction":                  "embedded type, not a top-level resource",
		"corev1.SecurityContext":                "embedded type, not a top-level resource",
		"corev1.PodSecurityContext":             "embedded type, not a top-level resource",
		"corev1.Capabilities":                   "embedded type, not a top-level resource",
		"corev1.SeccompProfile":                 "embedded type, not a top-level resource",
		"corev1.PodTemplateSpec":                "embedded type, not a top-level resource",
		"corev1.LocalObjectReference":           "embedded type, not a top-level resource",
		"corev1.ObjectReference":                "embedded type, not a top-level resource",
		"corev1.ServicePort":                    "embedded type, not a top-level resource",
		"corev1.ServiceSpec":                    "embedded type, not a top-level resource",
		"corev1.PersistentVolumeClaimSpec":      "embedded type, not a top-level resource",
		"corev1.PersistentVolumeAccessMode":     "embedded type, not a top-level resource",
		"corev1.SecretReference":                "embedded type, not a top-level resource",
		"corev1.Namespace":                      "cluster-scoped resource; cache is fine",
		"appsv1.StatefulSetSpec":                "embedded type, not a top-level resource",
		"appsv1.StatefulSetUpdateStrategy":      "embedded type, not a top-level resource",
		"networkingv1.NetworkPolicySpec":        "embedded type, not a top-level resource",
		"networkingv1.NetworkPolicyIngressRule": "embedded type, not a top-level resource",
		"networkingv1.NetworkPolicyPeer":        "embedded type, not a top-level resource",
		"networkingv1.NetworkPolicyPort":        "embedded type, not a top-level resource",
		"rbacv1.RoleRef":                        "embedded type, not a top-level resource",
		"rbacv1.Subject":                        "embedded type, not a top-level resource",
		"rbacv1.PolicyRule":                     "embedded type, not a top-level resource",
	}

	// Build the "got" set from the source-of-truth function.
	got := make(map[string]bool)
	for _, obj := range perTenantNamespaceCacheDisableTypes() {
		got[shortName(obj)] = true
	}

	// Locate internal/dataplane/ relative to this test file.
	_, thisFile, _, _ := runtime.Caller(0)
	dataplaneDir := filepath.Join(filepath.Dir(thisFile), "..", "internal", "dataplane")

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dataplaneDir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", dataplaneDir, err)
	}

	// Walk AST for `pkgalias.TypeName{...}` composite literals.
	used := map[string]string{} // type → first file where seen
	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
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
				switch pkgIdent.Name {
				case "corev1", "appsv1", "networkingv1", "rbacv1", "batchv1":
					// continue
				default:
					return true
				}
				key := pkgIdent.Name + "." + sel.Sel.Name
				if _, already := used[key]; !already {
					used[key] = filepath.Base(filename)
				}
				return true
			})
		}
	}

	for name, where := range used {
		if got[name] {
			continue
		}
		if reason, ok := allowedNotInDisableFor[name]; ok {
			t.Logf("OK: %s used in %s but allowlisted (%s)", name, where, reason)
			continue
		}
		t.Errorf(
			"%s instantiated in internal/dataplane/%s but missing from "+
				"cmd/cache_disable_for.go perTenantNamespaceCacheDisableTypes(). "+
				"Either add it to that list (and to the chart's per-tenant "+
				"ClusterRole) OR add to the test's allowedNotInDisableFor map "+
				"with a justification. See tenant-operator#49 / #57 / #76.",
			name, where)
	}
}

// shortName returns the same "corev1.Service" form the AST walker emits,
// so the two key sets line up.
func shortName(obj any) string {
	t := fmt.Sprintf("%T", obj)
	t = strings.TrimPrefix(t, "*")
	// fmt.Sprintf renders the import path like "v1.Service" for corev1;
	// remap by best-effort suffix.
	switch {
	case strings.HasPrefix(t, "v1.") && (isCoreV1(t)):
		return "corev1." + strings.TrimPrefix(t, "v1.")
	case strings.HasPrefix(t, "v1.") && isAppsV1(t):
		return "appsv1." + strings.TrimPrefix(t, "v1.")
	case strings.HasPrefix(t, "v1.") && isNetworkingV1(t):
		return "networkingv1." + strings.TrimPrefix(t, "v1.")
	case strings.HasPrefix(t, "v1.") && isRbacV1(t):
		return "rbacv1." + strings.TrimPrefix(t, "v1.")
	}
	return t
}

func isCoreV1(t string) bool {
	for _, k := range []string{"ConfigMap", "Secret", "Service", "PersistentVolumeClaim", "Pod", "Namespace", "Event"} {
		if strings.HasPrefix(t, "v1."+k) {
			// Disambiguate against rbacv1.RoleBinding etc. — but those don't
			// start with these core kinds.
			return true
		}
	}
	return false
}
func isAppsV1(t string) bool {
	for _, k := range []string{"StatefulSet", "Deployment", "DaemonSet", "ReplicaSet"} {
		if strings.HasPrefix(t, "v1."+k) {
			return true
		}
	}
	return false
}
func isNetworkingV1(t string) bool {
	return strings.HasPrefix(t, "v1.NetworkPolicy") || strings.HasPrefix(t, "v1.Ingress")
}
func isRbacV1(t string) bool {
	for _, k := range []string{"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} {
		if t == "v1."+k {
			return true
		}
	}
	return false
}
