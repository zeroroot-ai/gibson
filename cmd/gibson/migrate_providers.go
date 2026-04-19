package main

// migrate_providers.go implements the `gibson migrate-providers` subcommand.
//
// The command performs a one-shot migration of LLM provider credentials stored
// as base64-encoded JSON arrays in per-tenant Kubernetes Secrets
// (name: llm-providers, namespace: tenant-<id>) into the daemon's encrypted
// provider config store via the DaemonAdminService.CreateProvider gRPC RPC.
//
// Design §9 of spec 25-daemon-driven-provider-config specifies the full flow.
//
// Key properties:
//   - Idempotent: re-running on already-migrated tenants is safe (annotation check).
//   - Non-destructive: Secrets are annotated but never deleted.
//   - Fault-isolated: per-tenant errors are logged and skipped; migration continues.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	adminapi "github.com/zero-day-ai/gibson/internal/daemon/api"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants & annotations
// ─────────────────────────────────────────────────────────────────────────────

const (
	// migrationAnnotationKey is applied to successfully-migrated Secrets so
	// subsequent runs skip them (idempotency).
	migrationAnnotationKey = "gibson.zero-day.ai/migrated-to-daemon"
	migrationAnnotationVal = "true"

	// llmProvidersSecretName is the name of the per-tenant K8s Secret holding
	// the old dashboard-managed provider credentials.
	llmProvidersSecretName = "llm-providers"

	// saTokenPath is the default ServiceAccount token mount inside pods.
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// migrationLockTTL is the Redis TTL for the distributed migration lock.
	// Must be long enough for the migration to complete across all tenants.
	migrationLockTTL = 10 * time.Minute
)

// ─────────────────────────────────────────────────────────────────────────────
// Legacy schema types — dashboard's old K8s Secret payload
// ─────────────────────────────────────────────────────────────────────────────

// legacyProviderRecord mirrors the shape stored in the dashboard's
// llm-providers Secret (see enterprise/platform/dashboard/src/lib/k8s/provider-storage.ts).
// The schema evolved over time so we handle both flat and nested Bedrock fields.
type legacyProviderRecord struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	APIKey    string `json:"apiKey"`
	Model     string `json:"model"`
	BaseURL   string `json:"baseUrl,omitempty"`
	IsDefault bool   `json:"isDefault,omitempty"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`

	// Bedrock-specific fields — may be at the top level or nested under AWS.
	AWSRegion          string `json:"awsRegion,omitempty"`
	AWSAccessKeyID     string `json:"awsAccessKeyId,omitempty"`
	AWSSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`

	// AWS sub-object (alternative Bedrock encoding).
	AWS *legacyAWSFields `json:"aws,omitempty"`
}

type legacyAWSFields struct {
	Region          string `json:"region,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Unsupported provider types
// ─────────────────────────────────────────────────────────────────────────────

// unsupportedTypes lists provider types that have no corresponding daemon
// type and should be logged + skipped during migration.
// azure_openai was never in the daemon; ernie/maritaca/watsonx/local were
// removed by spec-25 task 6.
var unsupportedTypes = map[string]bool{
	"azure_openai": true,
	"ernie":        true,
	"maritaca":     true,
	"watsonx":      true,
	"local":        true,
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag defaults
// ─────────────────────────────────────────────────────────────────────────────

var (
	migrateDaemonAddr   string
	migrateLockKey      string
	migrateDryRun       bool
	migrateRedisAddr    string
	migrateKubeconfig   string
)

// ─────────────────────────────────────────────────────────────────────────────
// Command definition
// ─────────────────────────────────────────────────────────────────────────────

var migrateProvidersCmd = &cobra.Command{
	Use:   "migrate-providers",
	Short: "Migrate LLM provider credentials from K8s Secrets to the daemon store",
	Long: `migrate-providers reads per-tenant Kubernetes Secrets named "llm-providers"
and imports each provider record into the daemon's encrypted provider config
store via the DaemonAdminService.CreateProvider gRPC RPC.

The command is idempotent: Secrets already annotated with
  gibson.zero-day.ai/migrated-to-daemon: "true"
are skipped. Successfully migrated Secrets are annotated after all records in
that tenant succeed.

Provider type mapping:
  aws_bedrock → bedrock  (AWS credentials extracted from legacy fields)
  azure_openai / ernie / maritaca / watsonx / local → skipped with a WARN
  All others → passed through unchanged

The command is safe to re-run: Secrets are annotated but never deleted.
One-release rollback window: the Secret remains readable if the daemon must be
rolled back before permanent deletion.

EXAMPLES

  # Run in a Kind dev cluster (uses KUBECONFIG env / ~/.kube/config)
  gibson migrate-providers

  # Run inside a pod (in-cluster config, no KUBECONFIG needed)
  gibson migrate-providers --daemon-addr gibson-daemon:50002

  # Dry-run — log what would happen without making any RPC calls
  gibson migrate-providers --dry-run`,
	SilenceUsage: true,
	RunE:         runMigrateProviders,
}

func init() {
	migrateProvidersCmd.Flags().StringVar(&migrateDaemonAddr, "daemon-addr",
		getEnvOrDefault("GIBSON_DAEMON_ADDR", "gibson-daemon:50002"),
		"Address of the Gibson daemon gRPC server (host:port)")

	migrateProvidersCmd.Flags().StringVar(&migrateLockKey, "migration-lock-key",
		getEnvOrDefault("GIBSON_MIGRATION_LOCK_KEY", "migration:providers:default"),
		"Redis key used as a distributed lock to prevent concurrent migration runs")

	migrateProvidersCmd.Flags().BoolVar(&migrateDryRun, "dry-run",
		false,
		"Log what would be migrated without calling the daemon or annotating Secrets")

	migrateProvidersCmd.Flags().StringVar(&migrateRedisAddr, "redis-addr",
		getEnvOrDefault("GIBSON_REDIS_ADDR", ""),
		"Redis address for the migration lock (optional; falls back to GIBSON_REDIS_ADDR or skips lock)")

	migrateProvidersCmd.Flags().StringVar(&migrateKubeconfig, "kubeconfig",
		os.Getenv("KUBECONFIG"),
		"Path to kubeconfig (optional; uses in-cluster config when empty)")
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─────────────────────────────────────────────────────────────────────────────
// Command runner
// ─────────────────────────────────────────────────────────────────────────────

func runMigrateProviders(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	logger := slog.Default()

	logger.InfoContext(ctx, "migrate-providers: starting",
		"daemon_addr", migrateDaemonAddr,
		"lock_key", migrateLockKey,
		"dry_run", migrateDryRun,
	)

	// ── 1. Acquire distributed lock via Redis (best-effort; skip if no Redis addr) ─
	var lockRelease func()
	if migrateRedisAddr != "" {
		var err error
		lockRelease, err = acquireMigrationLock(ctx, migrateRedisAddr, migrateLockKey)
		if err != nil {
			return fmt.Errorf("failed to acquire migration lock %q: %w", migrateLockKey, err)
		}
		defer lockRelease()
		logger.InfoContext(ctx, "migrate-providers: migration lock acquired", "key", migrateLockKey)
	} else {
		logger.WarnContext(ctx, "migrate-providers: no redis-addr configured, skipping distributed lock")
	}

	// ── 2. Build Kubernetes client ──────────────────────────────────────────────
	k8sClient, err := buildK8sClient(migrateKubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes client: %w", err)
	}

	// ── 3. Build daemon gRPC client ─────────────────────────────────────────────
	saToken, err := readSAToken()
	if err != nil {
		logger.WarnContext(ctx, "migrate-providers: could not read SA token; RPC calls will be unauthenticated",
			"error", err)
		saToken = ""
	}

	adminClient, grpcConn, err := buildAdminClient(ctx, migrateDaemonAddr, saToken)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon at %s: %w", migrateDaemonAddr, err)
	}
	defer grpcConn.Close() //nolint:errcheck

	// ── 4. Discover tenant namespaces ───────────────────────────────────────────
	namespaces, err := listTenantNamespaces(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to list tenant namespaces: %w", err)
	}
	logger.InfoContext(ctx, "migrate-providers: discovered namespaces", "count", len(namespaces))

	// ── 5. Migrate each tenant ─────────────────────────────────────────────────
	var totalMigrated, totalSkipped, totalErrors int
	for _, ns := range namespaces {
		m, s, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, migrateDryRun)
		totalMigrated += m
		totalSkipped += s
		totalErrors += e
	}

	logger.InfoContext(ctx, "migrate-providers: complete",
		"total_migrated", totalMigrated,
		"total_skipped", totalSkipped,
		"total_errors", totalErrors,
	)

	if totalErrors > 0 {
		return fmt.Errorf("migration completed with %d tenant error(s); review logs above", totalErrors)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis distributed lock
// ─────────────────────────────────────────────────────────────────────────────

// acquireMigrationLock acquires a Redis SET NX lock. Returns the release func.
// Returns an error if the lock is already held by another runner.
func acquireMigrationLock(ctx context.Context, redisAddr, lockKey string) (func(), error) {
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

	acquired, err := rdb.SetNX(ctx, lockKey, "1", migrationLockTTL).Result()
	if err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis SetNX failed: %w", err)
	}
	if !acquired {
		_ = rdb.Close()
		return nil, fmt.Errorf("lock %q is held by another migration runner (concurrent execution prevented)", lockKey)
	}

	release := func() {
		delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rdb.Del(delCtx, lockKey).Err()
		_ = rdb.Close()
	}
	return release, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Kubernetes client helpers
// ─────────────────────────────────────────────────────────────────────────────

// buildK8sClient constructs a Kubernetes clientset.
// Prefers in-cluster config; falls back to kubeconfig file if provided.
func buildK8sClient(kubeconfigPath string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error

	if kubeconfigPath != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			// Fall back to default kubeconfig for local dev runs.
			cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// listTenantNamespaces returns all namespaces that appear to be Gibson tenant
// namespaces. Primary selection: label app.kubernetes.io/managed-by=gibson.
// Fallback: all namespaces with the "tenant-" prefix.
func listTenantNamespaces(ctx context.Context, k8s kubernetes.Interface) ([]string, error) {
	nsList, err := k8s.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=gibson",
	})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	names := make([]string, 0, len(nsList.Items))
	for i := range nsList.Items {
		names = append(names, nsList.Items[i].Name)
	}

	// Fallback: collect namespaces with the "tenant-" prefix that weren't
	// captured by the label selector.
	if len(names) == 0 {
		all, err := k8s.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list all namespaces (fallback): %w", err)
		}
		for i := range all.Items {
			if strings.HasPrefix(all.Items[i].Name, "tenant-") {
				names = append(names, all.Items[i].Name)
			}
		}
	}

	return names, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC client helpers
// ─────────────────────────────────────────────────────────────────────────────

// readSAToken reads the Kubernetes ServiceAccount bearer token from the default
// mount path inside a pod. Returns an error if the file is not present (not in pod).
func readSAToken() (string, error) {
	data, err := os.ReadFile(saTokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// buildAdminClient connects to the daemon's DaemonAdminService.
func buildAdminClient(ctx context.Context, addr, saToken string) (adminapi.DaemonAdminServiceClient, *grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if saToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&bearerToken{token: saToken}))
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, addr, opts...) //nolint:staticcheck
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return adminapi.NewDaemonAdminServiceClient(conn), conn, nil
}

// bearerToken implements credentials.PerRPCCredentials for the SA token.
type bearerToken struct{ token string }

func (b *bearerToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	if b.token == "" {
		return nil, nil
	}
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}
func (b *bearerToken) RequireTransportSecurity() bool { return false }

// ─────────────────────────────────────────────────────────────────────────────
// Per-tenant migration
// ─────────────────────────────────────────────────────────────────────────────

// migrateTenant migrates a single tenant namespace. Returns (migrated, skipped, errors).
func migrateTenant(
	ctx context.Context,
	logger *slog.Logger,
	k8s kubernetes.Interface,
	adminClient adminapi.DaemonAdminServiceClient,
	namespace string,
	dryRun bool,
) (migrated, skipped, errorCount int) {
	// Derive the tenantID from the namespace name. Convention: namespace = "tenant-<id>".
	tenantID := strings.TrimPrefix(namespace, "tenant-")
	if tenantID == "" {
		tenantID = namespace
	}

	// ── Read Secret ────────────────────────────────────────────────────────────
	secret, err := k8s.CoreV1().Secrets(namespace).Get(ctx, llmProvidersSecretName, metav1.GetOptions{})
	if err != nil {
		// Not found is fine — namespace may never have had any providers.
		if isNotFound(err) {
			return 0, 0, 0
		}
		logger.ErrorContext(ctx, "migrate-providers: failed to read Secret",
			"namespace", namespace,
			"tenant", tenantID,
			"error", err,
		)
		return 0, 0, 1
	}

	// ── Idempotency check ─────────────────────────────────────────────────────
	if secret.Annotations != nil && secret.Annotations[migrationAnnotationKey] == migrationAnnotationVal {
		logger.InfoContext(ctx, "migrate-providers: tenant already migrated, skipping",
			"namespace", namespace,
			"tenant", tenantID,
		)
		return 0, 0, 0
	}

	// ── Decode payload ────────────────────────────────────────────────────────
	records, err := decodeProviderSecret(secret)
	if err != nil {
		logger.ErrorContext(ctx, "migrate-providers: failed to decode Secret payload",
			"namespace", namespace,
			"tenant", tenantID,
			"error", err,
		)
		return 0, 0, 1
	}

	if len(records) == 0 {
		logger.InfoContext(ctx, "migrate-providers: empty provider list, annotating and skipping",
			"namespace", namespace,
			"tenant", tenantID,
		)
		if !dryRun {
			if annotateErr := annotateMigrated(ctx, k8s, namespace, secret); annotateErr != nil {
				logger.WarnContext(ctx, "migrate-providers: failed to annotate empty Secret",
					"namespace", namespace, "error", annotateErr)
			}
		}
		return 0, 0, 0
	}

	// ── Process each record ────────────────────────────────────────────────────
	var tenantMigrated, tenantSkipped, tenantErrors int
	for i := range records {
		rec := &records[i]
		ok, skip := migrateRecord(ctx, logger, adminClient, tenantID, rec, dryRun)
		if skip {
			tenantSkipped++
		} else if ok {
			tenantMigrated++
		} else {
			tenantErrors++
		}
	}

	// ── Annotate on full success ───────────────────────────────────────────────
	if tenantErrors == 0 && !dryRun {
		if annotateErr := annotateMigrated(ctx, k8s, namespace, secret); annotateErr != nil {
			logger.ErrorContext(ctx, "migrate-providers: failed to annotate Secret",
				"namespace", namespace,
				"tenant", tenantID,
				"error", annotateErr,
			)
			tenantErrors++
		}
	}

	// ── Structured audit log line ──────────────────────────────────────────────
	logger.InfoContext(ctx, "migrate-providers: tenant summary",
		"event", "migrate-providers",
		"tenant_namespace", namespace,
		"tenant_id", tenantID,
		"migrated_count", tenantMigrated,
		"skipped_count", tenantSkipped,
		"errors_count", tenantErrors,
		"dry_run", dryRun,
		"spec", "25",
	)

	return tenantMigrated, tenantSkipped, tenantErrors
}

// ─────────────────────────────────────────────────────────────────────────────
// Record-level migration
// ─────────────────────────────────────────────────────────────────────────────

// migrateRecord migrates a single provider record.
// Returns (success bool, shouldSkip bool).
func migrateRecord(
	ctx context.Context,
	logger *slog.Logger,
	adminClient adminapi.DaemonAdminServiceClient,
	tenantID string,
	rec *legacyProviderRecord,
	dryRun bool,
) (bool, bool) {
	// ── Unsupported type → skip with WARN ─────────────────────────────────────
	if unsupportedTypes[rec.Type] {
		logger.WarnContext(ctx, "migrate-providers: skipping unsupported provider type",
			"tenant_id", tenantID,
			"provider_name", rec.Name,
			"provider_type", rec.Type,
			"created_at", rec.CreatedAt,
			"reason", "not supported by daemon post-spec-25",
		)
		return false, true // skip
	}

	// ── Build credentials map ─────────────────────────────────────────────────
	credentials := make(map[string]string)
	daemonType := rec.Type

	switch rec.Type {
	case "aws_bedrock":
		// Rename type and map AWS credential fields.
		daemonType = "bedrock"
		region, keyID, secret := extractBedrockCredentials(rec)
		credentials["aws_region"] = region
		credentials["aws_access_key_id"] = keyID
		credentials["aws_secret_access_key"] = secret
		// api_key is not used for Bedrock; omit it.

	default:
		// Pass-through: anthropic, openai, google, ollama, cohere, mistral,
		// cloudflare, huggingface, llamafile, and any future types.
		if rec.APIKey != "" {
			credentials["api_key"] = rec.APIKey
		}
		if rec.BaseURL != "" {
			credentials["base_url"] = rec.BaseURL
		}
	}

	// ── Build CreateProviderRequest ───────────────────────────────────────────
	req := &adminapi.CreateProviderRequest{
		Input: &adminapi.ProviderConfigInput{
			Name:         rec.Name,
			Type:         daemonType,
			DefaultModel: rec.Model,
			Credentials:  credentials,
			SetAsDefault: rec.IsDefault,
		},
	}

	if dryRun {
		logger.InfoContext(ctx, "migrate-providers: [dry-run] would migrate provider",
			"tenant_id", tenantID,
			"provider_name", rec.Name,
			"provider_type", daemonType,
		)
		return true, false
	}

	// ── Call daemon RPC with tenant metadata ──────────────────────────────────
	rpcCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-gibson-tenant", tenantID,
	))

	_, err := adminClient.CreateProvider(rpcCtx, req)
	if err != nil {
		logger.ErrorContext(ctx, "migrate-providers: CreateProvider RPC failed",
			"tenant_id", tenantID,
			"provider_name", rec.Name,
			"provider_type", daemonType,
			"error", err,
		)
		return false, false
	}

	logger.InfoContext(ctx, "migrate-providers: migrated provider",
		"tenant_id", tenantID,
		"provider_name", rec.Name,
		"provider_type", daemonType,
	)
	return true, false
}

// extractBedrockCredentials returns (region, accessKeyID, secretAccessKey)
// from a legacy record, handling both flat and nested AWS field layouts.
func extractBedrockCredentials(rec *legacyProviderRecord) (string, string, string) {
	// Prefer top-level fields (older schema).
	region := rec.AWSRegion
	keyID := rec.AWSAccessKeyID
	secret := rec.AWSSecretAccessKey

	// Override with nested aws object if present (newer schema).
	if rec.AWS != nil {
		if rec.AWS.Region != "" {
			region = rec.AWS.Region
		}
		if rec.AWS.AccessKeyID != "" {
			keyID = rec.AWS.AccessKeyID
		}
		if rec.AWS.SecretAccessKey != "" {
			secret = rec.AWS.SecretAccessKey
		}
	}
	return region, keyID, secret
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret helpers
// ─────────────────────────────────────────────────────────────────────────────

// decodeProviderSecret reads and JSON-decodes the provider list from a Secret.
// The Secret stores a base64-encoded JSON array under the "providers" key.
// Kubernetes automatically base64-decodes Secret.Data, so the value returned
// in Data["providers"] is the raw JSON bytes already.
func decodeProviderSecret(secret *corev1.Secret) ([]legacyProviderRecord, error) {
	raw, ok := secret.Data["providers"]
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	var records []legacyProviderRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("json unmarshal providers: %w", err)
	}
	return records, nil
}

// annotateMigrated patches the Secret annotation to mark it as migrated.
// We read the current resource version from the live object to avoid 409s.
func annotateMigrated(ctx context.Context, k8s kubernetes.Interface, namespace string, secret *corev1.Secret) error {
	// Work on a shallow copy to avoid mutating the cached object.
	patch := secret.DeepCopy()
	if patch.Annotations == nil {
		patch.Annotations = make(map[string]string)
	}
	patch.Annotations[migrationAnnotationKey] = migrationAnnotationVal

	_, err := k8s.CoreV1().Secrets(namespace).Update(ctx, patch, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update Secret %s/%s: %w", namespace, llmProvidersSecretName, err)
	}
	return nil
}

// isNotFound reports whether err is a Kubernetes API Not Found error.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found") ||
		strings.Contains(err.Error(), "404")
}
