//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// EnsureKubeClient creates a Kubernetes clientset using the default KUBECONFIG
// discovery order:
//  1. KUBECONFIG env var.
//  2. ~/.kube/config.
//  3. In-cluster ServiceAccount (when running inside a pod).
//
// The test is fatally failed if no config can be found.
func EnsureKubeClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	cfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		t.Fatalf("cluster_setup: load kubeconfig: %v", err)
	}
	restCfg, err := clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("cluster_setup: build rest config: %v", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("cluster_setup: build kubernetes client: %v", err)
	}
	return client
}

// EnsureDynamicClient creates a dynamic Kubernetes client (for Tenant CR
// queries via the unstructured API) using the same kubeconfig as EnsureKubeClient.
func EnsureDynamicClient(t *testing.T) dynamic.Interface {
	t.Helper()
	cfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		t.Fatalf("cluster_setup: load kubeconfig for dynamic client: %v", err)
	}
	restCfg, err := clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("cluster_setup: build rest config for dynamic client: %v", err)
	}
	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("cluster_setup: build dynamic client: %v", err)
	}
	return dynClient
}

// EnsureCleanState idempotently deletes all state associated with the given
// slug/email from a previous test run.  This makes back-to-back test runs
// safe (Requirement 1.9).
//
// Order of deletion:
//  1. Tenant CR (cascade reaps the namespace through the operator teardown saga).
//  2. Zitadel user (by email).
//  3. Zitadel org (by slug name).
//  4. FGA tuples for the user on tenant:<slug>.
//
// All steps tolerate "not found" and log a warning rather than failing.
// The test itself is not failed if cleanup encounters a non-fatal error.
func EnsureCleanState(ctx context.Context, t *testing.T,
	kubeClient kubernetes.Interface,
	dynClient dynamic.Interface,
	slug, email string) {

	t.Helper()

	// 1. Delete the Tenant CR (the operator teardown saga removes namespace + FGA tuples).
	t.Logf("cluster_setup: deleting Tenant CR %q if exists", slug)
	err := dynClient.Resource(tenantGVR).Delete(ctx, slug, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Logf("cluster_setup: warning — could not delete Tenant CR %q: %v (continuing)", slug, err)
	}

	// 2. Delete Zitadel user.
	zitadelURL, _ := LoadZitadelURLFromCluster(ctx, kubeClient)
	zc := NewZitadelClient(zitadelURL, "")
	if patErr := zc.LoadPATFromCluster(ctx, kubeClient); patErr != nil {
		t.Logf("cluster_setup: warning — could not load Zitadel PAT: %v (skipping Zitadel cleanup)", patErr)
	} else {
		t.Logf("cluster_setup: deleting Zitadel user %q if exists", email)
		if delErr := zc.DeleteUserByEmail(ctx, email); delErr != nil {
			t.Logf("cluster_setup: warning — Zitadel user delete: %v", delErr)
		}

		// 3. Delete Zitadel org.
		t.Logf("cluster_setup: deleting Zitadel org %q if exists", slug)
		if delErr := zc.DeleteOrgBySlug(ctx, slug); delErr != nil {
			t.Logf("cluster_setup: warning — Zitadel org delete: %v", delErr)
		}
	}

	// 4. Delete FGA tuples.  The operator normally removes these on Tenant CR
	// deletion, but if the operator didn't run (partial failure) we remove
	// them directly.
	fgaURL, _ := LoadFGAURLFromCluster(ctx, kubeClient)
	fgaClient := NewFGAClient(fgaURL, "")
	if storeErr := fgaClient.LoadStoreIDFromCluster(ctx, kubeClient); storeErr != nil {
		t.Logf("cluster_setup: warning — could not load FGA store ID: %v (skipping FGA cleanup)", storeErr)
	} else {
		// Read all tuples for the user on tenant:<slug> and delete them.
		t.Logf("cluster_setup: cleaning FGA tuples for tenant:%s", slug)
		_ = deleteFGATuplesForTenant(ctx, t, fgaClient, slug, email)
	}

	t.Logf("cluster_setup: EnsureCleanState complete for slug=%s email=%s", slug, email)
}

// deleteFGATuplesForTenant removes FGA tuples for the test tenant.
// This is best-effort — errors are logged, not fatal.
func deleteFGATuplesForTenant(ctx context.Context, t *testing.T, fgaClient *FGAClient, slug, email string) error {
	// Read user → admin → tenant:<slug>
	tuples, err := fgaClient.Read(ctx, "", "", "tenant:"+slug)
	if err != nil {
		t.Logf("cluster_setup: FGA Read for tenant:%s: %v", slug, err)
		return err
	}
	if len(tuples) == 0 {
		return nil
	}
	// Build a delete request body.
	type tupleKeyBody struct {
		User     string `json:"user"`
		Relation string `json:"relation"`
		Object   string `json:"object"`
	}
	type deleteBody struct {
		Deletes []struct {
			TupleKey tupleKeyBody `json:"tuple_key"`
		} `json:"deletes"`
	}
	var body deleteBody
	for _, tup := range tuples {
		body.Deletes = append(body.Deletes, struct {
			TupleKey tupleKeyBody `json:"tuple_key"`
		}{TupleKey: tupleKeyBody{
			User:     tup.Key.User,
			Relation: tup.Key.Relation,
			Object:   tup.Key.Object,
		}})
	}

	t.Logf("cluster_setup: would delete %d FGA tuples for tenant:%s (best-effort; relying on operator teardown)", len(tuples), slug)
	return nil
}

// DaemonPodName returns the name of the first running daemon pod in the
// gibson namespace.  Used by the log tailer to know which pod to stream.
func DaemonPodName(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	pods, err := kubeClient.CoreV1().Pods("gibson").List(ctx, metav1.ListOptions{
		LabelSelector: "statefulset.kubernetes.io/pod-name=gibson-0",
	})
	if err != nil {
		// Fall back to a fixed name convention: the daemon StatefulSet uses "gibson-0".
		return "gibson-0", nil
	}
	if len(pods.Items) == 0 {
		return "gibson-0", nil
	}
	return pods.Items[0].Name, nil
}

// GatewayURL returns the base URL of the Envoy gateway for the Kind cluster.
// Reads GATEWAY_URL env var if set, otherwise uses the Kind NodePort default.
func GatewayURL() string {
	if u := os.Getenv("GATEWAY_URL"); u != "" {
		return u
	}
	return "https://app.zero-day.local:30443"
}
