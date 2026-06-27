// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Command backfill-credentials re-runs each provisioner's Provision step
// against every Ready Tenant CR so the per-tenant credentials envelope
// lives in Vault.
//
// Phase 6.2 of spec tenant-provisioning-unification-phase2 deleted the
// daemon's legacy KEK-derivation fallback in pgxpool_per_tenant.go; the
// daemon now resolves the per-tenant Postgres DSN through the secrets
// broker. Clusters that provisioned tenants prior to Phase 1.x (the
// operator's Vault credential writes) need this backfill before the
// daemon can dial the data plane.
//
// The chart wires this binary as a pre-upgrade Helm hook so it runs
// before the daemon StatefulSet rolls.
//
// Idempotent: each Provision step is a no-op-on-existing — Postgres uses
// CREATE IF NOT EXISTS + ALTER ROLE for password rotation, Neo4j upserts
// the StatefulSet, Redis upserts the index hash entry, vector creates the
// RediSearch HNSW index if absent. Vault writes are KV upserts.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 8.5.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

func main() {
	var (
		dryRun  bool
		timeout time.Duration
	)
	flag.BoolVar(&dryRun, "dry-run", false, "List tenants that would be backfilled without invoking provisioners")
	flag.DurationVar(&timeout, "timeout", 10*time.Minute, "Overall deadline for the backfill run")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	if err := run(ctx, dryRun); err != nil {
		logger.Error("backfill failed", "err", err)
		os.Exit(1)
	}
	logger.Info("backfill complete")
}

func run(ctx context.Context, dryRun bool) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(gibsonv1alpha1.AddToScheme(scheme))

	cfg, err := loadKubeConfig()
	if err != nil {
		return fmt.Errorf("kube config: %w", err)
	}

	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	var tenants gibsonv1alpha1.TenantList
	if err := cl.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	slog.Info("found tenants", "count", len(tenants.Items))

	if dryRun {
		for _, t := range tenants.Items {
			slog.Info("would backfill", "tenant", t.Name, "phase", t.Status.Phase)
		}
		return nil
	}

	pl, err := buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("pipeline build: %w", err)
	}

	var backfilled, skipped, failed int
	for _, t := range tenants.Items {
		if t.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
			slog.Info("skipping non-ready tenant", "tenant", t.Name, "phase", t.Status.Phase)
			skipped++
			continue
		}
		if err := pl.Provision(ctx, t.Name); err != nil {
			slog.Error("backfill tenant failed", "tenant", t.Name, "err", err)
			failed++
			continue
		}
		slog.Info("backfilled", "tenant", t.Name)
		backfilled++
	}
	slog.Info("summary", "backfilled", backfilled, "skipped", skipped, "failed", failed)
	if failed > 0 {
		return fmt.Errorf("%d tenant(s) failed backfill", failed)
	}
	return nil
}

// loadKubeConfig prefers KUBECONFIG, falling back to in-cluster.
func loadKubeConfig() (*rest.Config, error) {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	return ctrl.GetConfig()
}

// buildPipeline mirrors cmd/main.go's data-plane wiring (env-var
// driven). Importing the controller's exact wiring would pull the
// manager runtime in; this thin replica keeps the binary lean.
// pipelineRunner is the surface buildPipeline returns — the concrete type
// is package-private in dataplane, so we use the exported Provisioner
// interface to avoid leaking it across packages.
type pipelineRunner = dataplane.Provisioner

func buildPipeline(ctx context.Context) (pipelineRunner, error) {
	pgDSN := os.Getenv("DATAPLANE_PG_ADMIN_DSN")
	// DATAPLANE_MIGRATIONS_DIR removed per spec
	// gibson-postgres-migrations Component 5.

	kekDeriver, err := buildKEKDeriver()
	if err != nil {
		return nil, fmt.Errorf("kek deriver: %w", err)
	}

	vaultClient, err := buildVaultClient()
	if err != nil {
		return nil, fmt.Errorf("vault admin client: %w", err)
	}

	cfg := dataplane.PipelineConfig{}

	if pgDSN != "" {
		pg, err := dataplane.NewPostgresProvisioner(dataplane.PostgresConfig{
			AdminDSN:               pgDSN,
			KEKDeriver:             kekDeriver,
			DefaultConnectionLimit: 50,
			VaultClient:            vaultClient,
		})
		if err != nil {
			return nil, fmt.Errorf("postgres provisioner: %w", err)
		}
		cfg.Postgres = pg
	}

	// Neo4j requires a controller-runtime client; the standalone backfill
	// binary intentionally does NOT re-provision Neo4j StatefulSets — that
	// would risk evicting tenant pods. The Neo4j credential write happens
	// inside the controller's reconcile loop on next tenant touch.
	// If you need to backfill Neo4j Vault entries explicitly, restart the
	// operator pod after running this Job; the controller's idempotent
	// reconcile will re-write them.

	if redisAddr := os.Getenv("DATAPLANE_REDIS_ADDR"); redisAddr != "" {
		rp, err := dataplane.NewRedisProvisioner(dataplane.RedisProvisionerConfig{
			Addr:     redisAddr,
			Password: os.Getenv("DATAPLANE_REDIS_PASSWORD"),
		})
		if err != nil {
			return nil, fmt.Errorf("redis provisioner: %w", err)
		}
		cfg.Redis = rp
	}

	// Vector provisioning uses the same Redis address as the Redis step.
	// NewRedisVSSProvisioner creates its own connection (DB 0).
	if redisAddr := os.Getenv("DATAPLANE_REDIS_ADDR"); redisAddr != "" {
		vp, err := dataplane.NewRedisVSSProvisioner(dataplane.RedisVSSConfig{
			Addr:        redisAddr,
			Password:    os.Getenv("DATAPLANE_REDIS_PASSWORD"),
			VaultClient: vaultClient,
		})
		if err != nil {
			return nil, fmt.Errorf("vector provisioner: %w", err)
		}
		cfg.Vector = vp
	}

	cfg.KEK = &dataplane.KEKInitProvisioner{KEKDeriver: kekDeriver}

	_ = ctx // reserved for future per-step contexts
	return dataplane.New(cfg), nil
}

// buildKEKDeriver mirrors cmd/main.go's selection logic:
//
//	GIBSON_KMS_KEY_ARN set → AWS KMS HMAC deriver (production EKS)
//	GIBSON_VAULT_ADDR + AUTH_TOKEN set → Vault transit deriver (kind/Vault)
//	else → error (DATAPLANE_MASTER_KEK / local HKDF removed per tenant-operator#245)
//
// Spec helm-eks-readiness-and-pg-split Phase 5 (T5.2).
func buildKEKDeriver() (dataplane.KEKDeriver, error) {
	if kmsKeyID := os.Getenv("GIBSON_KMS_KEY_ARN"); kmsKeyID != "" {
		cfg, err := awsconfig.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("kek: load AWS config: %w", err)
		}
		return dataplane.NewKMSHMACDeriver(awskms.NewFromConfig(cfg), kmsKeyID)
	}
	vaultAddr := os.Getenv("GIBSON_VAULT_ADDR")
	vaultToken := os.Getenv("GIBSON_VAULT_AUTH_TOKEN")
	transitKey := os.Getenv("GIBSON_VAULT_TRANSIT_KEY")
	if transitKey == "" {
		transitKey = "master-kek"
	}
	if vaultAddr != "" && vaultToken != "" {
		tc, err := vaultadmin.NewTransitClient(vaultadmin.TransitConfig{
			Address:   vaultAddr,
			AuthToken: vaultToken,
			KeyName:   transitKey,
			Namespace: os.Getenv("GIBSON_VAULT_ROOT_NAMESPACE"),
		})
		if err != nil {
			return nil, err
		}
		return dataplane.NewVaultTransitDeriver(tc, transitKey)
	}
	return nil, fmt.Errorf("kek: no KEK source configured — " +
		"set GIBSON_KMS_KEY_ARN (EKS) or GIBSON_VAULT_ADDR + GIBSON_VAULT_AUTH_TOKEN (kind/Vault)")
}

func buildVaultClient() (vaultadmin.AdminClient, error) {
	addr := os.Getenv("GIBSON_VAULT_ADDR")
	token := os.Getenv("GIBSON_VAULT_AUTH_TOKEN")
	if addr == "" || token == "" {
		return nil, nil //nolint:nilnil // optional
	}
	return vaultadmin.New(vaultadmin.Config{
		Address:       addr,
		AdminToken:    token,
		RootNamespace: os.Getenv("GIBSON_VAULT_ROOT_NAMESPACE"),
	})
}
