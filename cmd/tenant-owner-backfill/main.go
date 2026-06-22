// tenant-owner-backfill is a one-shot migration binary that seeds FGA owner
// tuples for existing tenants whose founding user currently holds only the
// admin relation.
//
// For each Tenant CR:
//  1. List TenantMember CRs in the tenant's namespace (status.namespace).
//  2. Sort by metadata.creationTimestamp ascending.
//  3. Pick the earliest member whose status.userId is non-empty — that user
//     is considered the tenant founder.
//  4. Call FGA Check(user:<sub>, owner, tenant:<slug>). If allowed=false,
//     write the tuple. If already allowed, skip.
//  5. Log one structured line per tenant:
//     outcome=backfilled|already_owner|no_founder_found  tenant=<slug>  user=<sub>
//
// Idempotent — safe to re-run. Exits zero unconditionally; per-tenant skips
// do not fail the Job.
//
// Environment variables (read from the gibson-fga-config ConfigMap injected
// into the Job's env):
//
//	EXT_AUTHZ_FGA_ADDR      — HTTP endpoint of the OpenFGA server
//	EXT_AUTHZ_FGA_STORE_ID  — FGA store ID
//	EXT_AUTHZ_FGA_MODEL_ID  — FGA authorization model ID
//
// Spec: tenant-role-taxonomy Req 5.1–5.4.
package main

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// GVR definitions for Tenant and TenantMember CRs.
var (
	tenantsGVR = schema.GroupVersionResource{
		Group:    "gibson.zeroroot.ai",
		Version:  "v1alpha1",
		Resource: "tenants",
	}
	tenantMembersGVR = schema.GroupVersionResource{
		Group:    "gibson.zeroroot.ai",
		Version:  "v1alpha1",
		Resource: "tenantmembers",
	}
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	// Load kubernetes config: in-cluster first, then KUBECONFIG fallback.
	k8sCfg, err := loadKubeConfig()
	if err != nil {
		logger.Error("failed to load kubernetes config", "err", err)
		os.Exit(1)
	}
	dyn, err := dynamic.NewForConfig(k8sCfg)
	if err != nil {
		logger.Error("failed to create dynamic k8s client", "err", err)
		os.Exit(1)
	}

	// Build FGA authorizer from env vars matching the daemon's config shape.
	fgaAddr := requireEnv(logger, "EXT_AUTHZ_FGA_ADDR")
	fgaStoreID := requireEnv(logger, "EXT_AUTHZ_FGA_STORE_ID")
	fgaModelID := requireEnv(logger, "EXT_AUTHZ_FGA_MODEL_ID")
	if fgaAddr == "" || fgaStoreID == "" || fgaModelID == "" {
		// requireEnv already logged; exit to satisfy Job retry contract.
		os.Exit(1)
	}

	authzClient, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  fgaAddr,
		StoreID:   fgaStoreID,
		ModelID:   fgaModelID,
		TimeoutMs: 5000,
		Logger:    logger,
	})
	if err != nil {
		logger.Error("failed to create FGA authorizer", "err", err)
		os.Exit(1)
	}
	defer authzClient.Close()

	// List all Tenant CRs (cluster-scoped).
	tenantList, err := dyn.Resource(tenantsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Error("failed to list Tenant CRs", "err", err)
		os.Exit(1)
	}

	logger.Info("starting tenant owner backfill",
		"tenant_count", len(tenantList.Items),
	)

	for _, tenantObj := range tenantList.Items {
		slug := tenantObj.GetName()

		// Extract the namespace from status.namespace.
		ns, _, _ := nestedString(tenantObj.Object, "status", "namespace")
		if ns == "" {
			logger.Warn("skipping tenant: status.namespace empty",
				"outcome", "no_founder_found",
				"tenant", slug,
				"user", "",
			)
			continue
		}

		// List TenantMember CRs in the tenant's namespace.
		memberList, err := dyn.Resource(tenantMembersGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Warn("skipping tenant: failed to list TenantMember CRs",
				"tenant", slug,
				"namespace", ns,
				"err", err,
			)
			continue
		}

		// Sort members by creationTimestamp ascending to find the earliest.
		members := memberList.Items
		sort.Slice(members, func(i, j int) bool {
			ti := members[i].GetCreationTimestamp().Time
			tj := members[j].GetCreationTimestamp().Time
			return ti.Before(tj)
		})

		// Find the earliest member with a non-empty status.userId.
		var founderSub string
		for _, m := range members {
			uid, _, _ := nestedString(m.Object, "status", "userId")
			if uid != "" {
				founderSub = uid
				break
			}
		}

		if founderSub == "" {
			logger.Info("no founder found for tenant",
				"outcome", "no_founder_found",
				"tenant", slug,
				"user", "",
			)
			continue
		}

		// Check if the owner tuple already exists.
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		allowed, err := authzClient.Check(checkCtx, "user:"+founderSub, "owner", "tenant:"+slug)
		cancel()
		if err != nil {
			logger.Warn("FGA check failed; skipping tenant",
				"tenant", slug,
				"user", founderSub,
				"err", err,
			)
			continue
		}

		if allowed {
			logger.Info("owner tuple already present",
				"outcome", "already_owner",
				"tenant", slug,
				"user", founderSub,
			)
			continue
		}

		// Write the owner tuple. Do NOT modify existing admin tuples (Req 5.4).
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = authzClient.Write(writeCtx, []authz.Tuple{
			{User: "user:" + founderSub, Relation: "owner", Object: "tenant:" + slug},
		})
		cancel()
		if err != nil {
			logger.Warn("FGA write failed; skipping tenant",
				"tenant", slug,
				"user", founderSub,
				"err", err,
			)
			continue
		}

		logger.Info("backfilled owner tuple",
			"outcome", "backfilled",
			"tenant", slug,
			"user", founderSub,
		)
	}

	logger.Info("tenant owner backfill complete",
		"tenant_count", len(tenantList.Items),
	)
	// Exit zero unconditionally — per-tenant skips do NOT fail the Job.
}

// loadKubeConfig returns an in-cluster config if available, falling back to
// the KUBECONFIG env / default kubeconfig file for local invocation.
func loadKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
}

// requireEnv returns the value of the given env var. If the var is unset or
// empty it logs an error and returns "".
func requireEnv(logger *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error("required environment variable not set or empty", "key", key)
	}
	return v
}

// nestedString retrieves a string value from an unstructured map by following
// the given field path. Returns ("", false, nil) if any intermediate field is
// missing. Mirrors the helper in cmd/lowercase-tenant-owner.
func nestedString(obj map[string]any, fields ...string) (string, bool, error) {
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
		return "", false, nil
	}
	return s, true, nil
}
