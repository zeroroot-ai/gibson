// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// active-session-backfill is a one-shot migration Job that seeds the FGA
// active_session conditional tuple for every existing human tenant member
// (gibson#627 Slice 2).
//
// The tuple written is:
//
//	(user:<userID>, active_session, tenant:<slug>)
//	  condition: token_not_revoked{revoked_at: "1970-01-01T00:00:00Z"}
//
// A revoked_at at the epoch means "never revoked" — token_issued_at > epoch is
// always true for any real JWT. RevokeUserSessions will advance revoked_at to
// the current time when a session is explicitly revoked.
//
// Only human users (user: principal) receive an active_session tuple.
// Machine principals (agent_principal / tool_principal / plugin_principal) are
// excluded: they authenticate via mTLS + CG-JWTs and are NOT gated by
// active_session.
//
// Idempotent and safe to re-run. Exits zero unconditionally — per-member
// failures are logged and skipped.
//
// Environment variables (matching the pattern in cmd/tenant-owner-backfill):
//
//	EXT_AUTHZ_FGA_ADDR      — HTTP endpoint of the OpenFGA server
//	EXT_AUTHZ_FGA_STORE_ID  — FGA store ID
//	EXT_AUTHZ_FGA_MODEL_ID  — FGA authorization model ID
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

// backfillOutcome is logged as the structured "outcome" field per member.
type backfillOutcome string

const (
	outcomeBackfilled    backfillOutcome = "backfilled"
	outcomeAlreadySeeded backfillOutcome = "already_seeded"
	outcomeWriteFailed   backfillOutcome = "write_failed"
	outcomeCheckFailed   backfillOutcome = "check_failed"
)

// BackfillStats holds the counters returned by runBackfill.
type BackfillStats struct {
	Backfilled    int
	AlreadySeeded int
	Failed        int
}

// TenantLister enumerates Tenant CRs from the cluster.
type TenantLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

// MemberLister enumerates TenantMember CRs for a given namespace.
type MemberLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

// MemberListerFactory returns a MemberLister scoped to a namespace.
type MemberListerFactory func(namespace string) MemberLister

// fgaEnvConfig holds the FGA coordinates resolved from env vars.
type fgaEnvConfig struct {
	Addr    string
	StoreID string
	ModelID string
}

// kubeConfigLoader loads a *rest.Config. Injectable for testing.
type kubeConfigLoader func() (*rest.Config, error)

// listerProvider creates a TenantLister and MemberListerFactory from a *rest.Config.
// Injectable so tests do not need to implement the full dynamic.Interface.
type listerProvider func(*rest.Config) (TenantLister, MemberListerFactory, error)

// fgaAuthorizerBuilder builds an authz.Authorizer from a FgaConfig. Injectable for testing.
type fgaAuthorizerBuilder func(ctx context.Context, cfg authz.FgaConfig) (authz.Authorizer, error)

func main() {
	os.Exit(run())
}

// run wires real constructors and delegates to runWithDeps.
// Only the three constructor calls and the run() entry point are uncovered here.
func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return runWithDeps(
		logger,
		loadKubeConfig,
		func(cfg *rest.Config) (TenantLister, MemberListerFactory, error) {
			dyn, err := dynamic.NewForConfig(cfg)
			if err != nil {
				return nil, nil, fmt.Errorf("dynamic client: %w", err)
			}
			tenantLister := dyn.Resource(tenantsGVR)
			memberFactory := func(ns string) MemberLister {
				return dyn.Resource(tenantMembersGVR).Namespace(ns)
			}
			return tenantLister, memberFactory, nil
		},
		authz.NewFgaAuthorizer,
	)
}

// runWithDeps resolves config, constructs clients via the supplied factory
// functions, and delegates to runWithWriter. All logic branches are exercisable
// by injecting fake constructors — only the real constructor calls in run() are
// irreducibly un-testable.
func runWithDeps(
	logger *slog.Logger,
	kubeLoader kubeConfigLoader,
	listProvider listerProvider,
	authzBuilder fgaAuthorizerBuilder,
) int {
	ctx := context.Background()

	fgaCfg, err := resolveFgaEnvConfig(logger)
	if err != nil {
		logger.Error("missing required environment variables", "err", err)
		return 1
	}

	k8sCfg, err := kubeLoader()
	if err != nil {
		logger.Error("failed to load kubernetes config", "err", err)
		return 1
	}

	tenantLister, memberFactory, err := listProvider(k8sCfg)
	if err != nil {
		logger.Error("failed to create dynamic k8s client", "err", err)
		return 1
	}

	authzBase, err := authzBuilder(ctx, authz.FgaConfig{
		Endpoint:  fgaCfg.Addr,
		StoreID:   fgaCfg.StoreID,
		ModelID:   fgaCfg.ModelID,
		TimeoutMs: 5000,
		Logger:    logger,
	})
	if err != nil {
		logger.Error("failed to create FGA authorizer", "err", err)
		return 1
	}
	defer func() {
		if closeErr := authzBase.Close(); closeErr != nil {
			logger.Warn("failed to close FGA authorizer", "err", closeErr)
		}
	}()

	cw, ok := authzBase.(authz.ConditionalWriter)
	if !ok {
		logger.Error("FGA authorizer does not implement ConditionalWriter; cannot write conditional tuples")
		return 1
	}

	return runWithWriter(ctx, tenantLister, memberFactory, cw, logger)
}

// resolveFgaEnvConfig reads the three required FGA env vars.
func resolveFgaEnvConfig(logger *slog.Logger) (fgaEnvConfig, error) {
	addr := requireEnv(logger, "EXT_AUTHZ_FGA_ADDR")
	storeID := requireEnv(logger, "EXT_AUTHZ_FGA_STORE_ID")
	modelID := requireEnv(logger, "EXT_AUTHZ_FGA_MODEL_ID")

	var missing []string
	if addr == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_ADDR")
	}
	if storeID == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_STORE_ID")
	}
	if modelID == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_MODEL_ID")
	}
	if len(missing) > 0 {
		return fgaEnvConfig{}, fmt.Errorf("required env vars not set: %v", missing)
	}
	return fgaEnvConfig{Addr: addr, StoreID: storeID, ModelID: modelID}, nil
}

// runWithWriter runs the full backfill and maps the result to an exit code.
func runWithWriter(
	ctx context.Context,
	tenants TenantLister,
	members MemberListerFactory,
	cw authz.ConditionalWriter,
	logger *slog.Logger,
) int {
	stats, err := runBackfill(ctx, tenants, members, cw, logger)
	if err != nil {
		logger.Error("backfill failed fatally", "err", err)
		return 1
	}
	logger.Info("active-session backfill complete",
		"backfilled", stats.Backfilled,
		"already_seeded", stats.AlreadySeeded,
		"failed", stats.Failed,
	)
	return 0
}

// runBackfill enumerates all Tenants and their Active TenantMembers, writing
// an active_session FGA tuple for each.
func runBackfill(
	ctx context.Context,
	tenants TenantLister,
	members MemberListerFactory,
	cw authz.ConditionalWriter,
	logger *slog.Logger,
) (BackfillStats, error) {
	tenantList, err := tenants.List(ctx, metav1.ListOptions{})
	if err != nil {
		return BackfillStats{}, fmt.Errorf("list Tenant CRs: %w", err)
	}

	logger.Info("starting active-session backfill",
		"tenant_count", len(tenantList.Items),
	)

	var stats BackfillStats

	for _, tenantObj := range tenantList.Items {
		slug := tenantObj.GetName()

		ns, _, _ := nestedString(tenantObj.Object, "status", "namespace")
		if ns == "" {
			logger.Warn("skipping tenant: status.namespace empty", "tenant", slug)
			continue
		}

		memberList, err := members(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Warn("skipping tenant: failed to list TenantMember CRs",
				"tenant", slug, "namespace", ns, "err", err)
			continue
		}

		items := memberList.Items
		sort.Slice(items, func(i, j int) bool {
			return items[i].GetCreationTimestamp().Time.Before(items[j].GetCreationTimestamp().Time)
		})

		for _, m := range items {
			phase, _, _ := nestedString(m.Object, "status", "phase")
			userID, _, _ := nestedString(m.Object, "status", "userId")

			if phase != "Active" || userID == "" {
				continue
			}

			outcome, memberErr := backfillMember(ctx, cw, slug, userID)
			log := logger.With(
				"outcome", string(outcome),
				"tenant", slug,
				"user_id", userID,
				"member", m.GetName(),
			)
			if memberErr != nil {
				log.Warn("backfill member failed", "err", memberErr)
				stats.Failed++
			} else {
				switch outcome {
				case outcomeAlreadySeeded:
					log.Info("backfill member: already seeded")
					stats.AlreadySeeded++
				case outcomeBackfilled:
					log.Info("backfill member: written")
					stats.Backfilled++
				case outcomeWriteFailed, outcomeCheckFailed:
					log.Warn("backfill member: unexpected nil-error with failure outcome")
					stats.Failed++
				}
			}
		}
	}
	return stats, nil
}

// backfillMember seeds the active_session conditional tuples for one
// user+tenant: the per-tenant tuple (user:<id>, active_session, tenant:<slug>)
// AND the user-scoped tuple (user:<id>, active_session, user:<id>) that gates
// tenant-less requests (gibson#1244). Both are written by every writer that
// seeds a session so a tenant-less request is gated by the same revocation
// event as a tenant-scoped one. The user-scoped write is idempotent: a
// multi-tenant user resolves to one user-scoped tuple regardless of how many
// per-tenant tuples exist (WriteConditional treats the duplicate as a no-op).
func backfillMember(ctx context.Context, cw authz.ConditionalWriter, tenantSlug, userID string) (outcome backfillOutcome, err error) {
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tuple := authz.ActiveSessionTuple(userID, tenantSlug)
	if writeErr := cw.WriteConditional(writeCtx, tuple); writeErr != nil {
		return outcomeWriteFailed, fmt.Errorf("WriteConditional(%s, %s): %w", userID, tenantSlug, writeErr)
	}
	userTuple := authz.ActiveSessionUserTuple(userID)
	if writeErr := cw.WriteConditional(writeCtx, userTuple); writeErr != nil {
		return outcomeWriteFailed, fmt.Errorf("WriteConditional(%s, user-scoped): %w", userID, writeErr)
	}
	return outcomeBackfilled, nil
}

// loadKubeConfig returns an in-cluster config if available, falling back to
// the KUBECONFIG env / default kubeconfig file.
func loadKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return cfg, nil
}

// requireEnv returns the value of the given env var, logging an error if unset.
func requireEnv(logger *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error("required environment variable not set or empty", "key", key)
	}
	return v
}

// nestedString retrieves a string value from an unstructured map by following
// the given field path.
func nestedString(obj map[string]any, fields ...string) (value string, found bool, err error) {
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
