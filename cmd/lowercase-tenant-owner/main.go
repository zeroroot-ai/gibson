// lowercase-tenant-owner is a one-shot reconciler that lowercases the
// `spec.owner` field on every Tenant CR cluster-wide. Pre-existing CRs
// were written with mixed-case email values; spec
// auth-resolution-hardening (R4) normalizes those values so any
// remaining email-keyed lookups are case-insensitive at write time.
//
// Idempotent — re-running on a fully-lowercased cluster is a no-op.
// Logs structured progress: scanned, patched.
//
// Run via the chart's post-install/post-upgrade Hook Job
// (templates/migration/lowercase-tenant-owner-job.yaml). Manual
// invocation:
//
//	go run ./cmd/lowercase-tenant-owner
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var tenantsGVR = schema.GroupVersionResource{
	Group:    "gibson.gibson.io",
	Version:  "v1alpha1",
	Resource: "tenants",
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx := context.Background()

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err.Error())
		os.Exit(1)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error("dynamic client", "err", err.Error())
		os.Exit(1)
	}

	scanned, patched, errs := reconcile(ctx, dyn, logger)
	logger.Info("done",
		"scanned", scanned,
		"patched", patched,
		"errors", errs,
	)
	if errs > 0 {
		os.Exit(1)
	}
}

func loadConfig() (*rest.Config, error) {
	// In-cluster first; fall back to KUBECONFIG for local invocation.
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
}

func reconcile(ctx context.Context, dyn dynamic.Interface, logger *slog.Logger) (scanned, patched, errs int) {
	list, err := dyn.Resource(tenantsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Error("list tenants", "err", err.Error())
		return 0, 0, 1
	}
	for _, item := range list.Items {
		scanned++
		if changed, err := lowercaseOwner(ctx, dyn, &item, logger); err != nil {
			errs++
		} else if changed {
			patched++
		}
	}
	return scanned, patched, errs
}

func lowercaseOwner(ctx context.Context, dyn dynamic.Interface, t *corev1.Unstructured, logger *slog.Logger) (bool, error) {
	owner, found, err := getNestedString(t, "spec", "owner")
	if err != nil {
		logger.Error("read owner", "tenant", t.GetName(), "err", err.Error())
		return false, err
	}
	if !found || owner == "" {
		return false, nil
	}
	lower := strings.ToLower(owner)
	if lower == owner {
		return false, nil
	}
	patch := map[string]any{
		"spec": map[string]any{"owner": lower},
	}
	body, _ := json.Marshal(patch)
	if _, err := dyn.Resource(tenantsGVR).Patch(ctx, t.GetName(), types.MergePatchType, body, metav1.PatchOptions{}); err != nil {
		logger.Error("patch tenant", "tenant", t.GetName(), "err", err.Error())
		return false, err
	}
	logger.Info("lowercased",
		"tenant", t.GetName(),
		"before", owner,
		"after", lower,
	)
	return true, nil
}

func getNestedString(u *corev1.Unstructured, fields ...string) (string, bool, error) {
	v, found, err := unstructuredNestedString(u.Object, fields...)
	if err != nil || !found {
		return "", found, err
	}
	return v, true, nil
}

// unstructuredNestedString is a tiny re-implementation of
// `apimachinery/pkg/apis/meta/v1/unstructured.NestedString` to avoid
// pulling in another import path; same semantics.
func unstructuredNestedString(obj map[string]any, fields ...string) (string, bool, error) {
	cur := any(obj)
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		v, exists := m[f]
		if !exists {
			return "", false, nil
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		return "", true, fmt.Errorf("expected string at %v, got %T", fields, cur)
	}
	return s, true, nil
}
